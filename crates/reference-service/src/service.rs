//! The listener, the worker threads and the stop.
//!
//! A fixed pool of worker threads serves the connections. One open connection
//! uses one worker. This is the simplest model with a bound on the number of
//! threads. The accept loop polls a listener that does not block, so that the
//! stop flag ends it with no `unsafe` code.

use std::io::{self, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use procurauth_pep::Pep;
use procurauth_pep::config::PepConfig;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};

use crate::app::App;
use crate::data::Store;
use crate::document::reference_document_with;
use crate::http::{Connection, Limits, ReadResult};

/// The most connections that wait for a free worker.
const QUEUE: usize = 64;

/// Build the service from the configuration of the PEP. The transport is
/// `HttpTransport`: it has no TLS, so the link to the PDP is `http`. A deployment
/// that needs TLS builds the [`App`] with its own transport.
///
/// # Errors
/// Returns every error of the configuration of the PEP, of the action document and of the map of the tools.
pub fn build_app(
    pep: PepConfig,
    mcp_path: Option<String>,
    log: Box<dyn Write + Send>,
) -> Result<App, Vec<String>> {
    build_app_with(pep, mcp_path, false, log)
}

/// Build the service as [`build_app`] does, with the option `mcp_session_budget`:
/// when it is true, the action `mcp.session` lists a budget (binding 3.6a).
///
/// # Errors
/// Returns every error of the configuration of the PEP, of the action document and of the map of the tools.
pub fn build_app_with(
    pep: PepConfig,
    mcp_path: Option<String>,
    session_budget: bool,
    log: Box<dyn Write + Send>,
) -> Result<App, Vec<String>> {
    let document = reference_document_with(&pep.service_id, session_budget)
        .map_err(|text| vec![format!("The action document is not valid: {text}.")])?;
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&pep.pdp)));
    let pep = Pep::new(pep, document, transport)
        .map_err(|errors| errors.iter().map(ToString::to_string).collect::<Vec<_>>())?;
    App::new(pep, Store::demo(), mcp_path, log).map_err(|text| vec![text])
}

/// A service that listens. Drop it, or call [`RunningService::shutdown`], to stop it.
pub struct RunningService {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    workers: Vec<JoinHandle<()>>,
}

/// Open the port and start the threads. Port 0 chooses a free port.
///
/// # Errors
/// Returns the error of the system when the port cannot open.
pub fn start(
    app: Arc<App>,
    listen: SocketAddr,
    workers: usize,
    limits: Limits,
) -> io::Result<RunningService> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (app, receiver, stop) = (Arc::clone(&app), Arc::clone(&receiver), Arc::clone(&stop));
        handles.push(thread::spawn(move || {
            worker(&app, &receiver, &stop, limits)
        }));
    }
    let accept = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || accept_loop(&listener, &sender, &stop))
    };
    Ok(RunningService {
        addr,
        stop,
        accept: Some(accept),
        workers: handles,
    })
}

impl RunningService {
    /// The address that the listener bound. With port 0, this holds the port that the system chose.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base URL of the service, for example `http://127.0.0.1:8080`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The flag that stops the service. Set it from a signal handler.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Stop the service. A request in progress ends first, and each thread ends.
    pub fn shutdown(mut self) {
        self.stop_threads();
    }

    /// Wait until the stop flag is set, then stop the threads.
    pub fn run_until_stopped(mut self) {
        while !self.stop.load(Ordering::SeqCst) {
            thread::sleep(Duration::from_millis(50));
        }
        self.stop_threads();
    }

    fn stop_threads(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        self.stop_threads();
    }
}

fn accept_loop(listener: &TcpListener, sender: &SyncSender<TcpStream>, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut waiting = Some(stream);
                while let Some(stream) = waiting.take() {
                    match sender.try_send(stream) {
                        Ok(()) => {}
                        Err(TrySendError::Full(back)) => {
                            if stop.load(Ordering::SeqCst) {
                                return;
                            }
                            waiting = Some(back);
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(TrySendError::Disconnected(_)) => return,
                    }
                }
            }
            Err(_) => thread::sleep(Duration::from_millis(10)),
        }
    }
}

fn worker(
    app: &App,
    receiver: &Mutex<Receiver<TcpStream>>,
    stop: &Arc<AtomicBool>,
    limits: Limits,
) {
    loop {
        let next = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(Duration::from_millis(50));
        match next {
            Ok(stream) => serve(app, stream, stop, limits),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn serve(app: &App, stream: TcpStream, stop: &Arc<AtomicBool>, limits: Limits) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_nodelay(true);
    let mut connection = Connection::new(stream, Arc::clone(stop));
    while !stop.load(Ordering::SeqCst) {
        match connection.read_request(&limits) {
            ReadResult::Closed => return,
            ReadResult::Reject(reply) => {
                let _ = connection.write_reply(&reply, false);
                return;
            }
            ReadResult::Request(request) => {
                let reply = app.handle(&request);
                let keep = request.keep_alive && !stop.load(Ordering::SeqCst);
                if connection.write_reply(&reply, keep).is_err() || !keep {
                    return;
                }
            }
        }
    }
}
