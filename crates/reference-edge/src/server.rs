//! The listener, the worker threads and the stop.
//!
//! A fixed pool of worker threads serves the connections. One open connection
//! uses one worker. This is the simplest model with a bound on the number of
//! threads. The accept loop polls a listener that does not block, so that the
//! stop flag ends it with no `unsafe` code.

use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use procurauth_pep::reply::HttpReply;

use crate::edge::{Edge, Verdict};
use crate::http::{Connection, Limits, ReadHead};
use crate::proxy::{Relayed, failure_reply};

/// The most connections that wait for a free worker.
const QUEUE: usize = 64;

/// An edge that listens. Drop it, or call [`RunningEdge::shutdown`], to stop it.
pub struct RunningEdge {
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
    edge: Arc<Edge>,
    listen: SocketAddr,
    workers: usize,
    limits: Limits,
) -> io::Result<RunningEdge> {
    let listener = TcpListener::bind(listen)?;
    let addr = listener.local_addr()?;
    listener.set_nonblocking(true)?;
    let stop = Arc::new(AtomicBool::new(false));
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(QUEUE);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (edge, receiver, stop) = (Arc::clone(&edge), Arc::clone(&receiver), Arc::clone(&stop));
        handles.push(thread::spawn(move || {
            worker(&edge, &receiver, &stop, limits);
        }));
    }
    let accept = {
        let stop = Arc::clone(&stop);
        thread::spawn(move || accept_loop(&listener, &sender, &stop))
    };
    Ok(RunningEdge {
        addr,
        stop,
        accept: Some(accept),
        workers: handles,
    })
}

impl RunningEdge {
    /// The address that the listener bound. With port 0, this holds the port that the system chose.
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// The base URL of the edge, for example `http://127.0.0.1:8090`.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// The flag that stops the edge. Set it from a signal handler.
    pub fn stop_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Stop the edge. A request in progress ends first, and each thread ends.
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

impl Drop for RunningEdge {
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
    edge: &Edge,
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
            Ok(stream) => serve(edge, stream, stop, limits),
            Err(RecvTimeoutError::Timeout) => {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn serve(edge: &Edge, stream: TcpStream, stop: &Arc<AtomicBool>, limits: Limits) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_nodelay(true);
    let mut connection = Connection::new(stream, Arc::clone(stop));
    while !stop.load(Ordering::SeqCst) {
        match connection.read_head(&limits) {
            ReadHead::Closed => return,
            ReadHead::Reject(reply) => {
                // The request is not valid HTTP. The edge cannot read a key from it.
                edge.log_line("-", "-", reply.status, "bad request");
                let _ = connection.write_reply(&reply, false);
                return;
            }
            ReadHead::Head(head) => {
                let path = head.path().to_owned();
                match edge.decide(&head.headers) {
                    Verdict::Refuse { reply, cause } => {
                        edge.log_line(&head.method, &path, reply.status, &cause.label());
                        // The edge needs no part of the body (9.8). It closes the connection.
                        connection.refuse_and_close(&reply);
                        return;
                    }
                    Verdict::Forward { token, subject } => {
                        let body = match connection.read_body(&head, &limits) {
                            Ok(body) => body,
                            Err(reply) => {
                                edge.log_line(&head.method, &path, reply.status, "body");
                                connection.refuse_and_close(&reply);
                                return;
                            }
                        };
                        let request = edge.forward_request(
                            &head.method,
                            &head.target,
                            &head.headers,
                            body,
                            &token,
                        );
                        match edge
                            .upstream()
                            .forward(&request, &mut connection, head.keep_alive)
                        {
                            Relayed::Done { status, reusable } => {
                                edge.log_line(
                                    &head.method,
                                    &path,
                                    status,
                                    &format!("subject {subject}"),
                                );
                                if !reusable {
                                    return;
                                }
                            }
                            Relayed::NoAnswer(status) => {
                                edge.log_line(&head.method, &path, status, "service");
                                let reply: HttpReply = failure_reply(status);
                                if connection.write_reply(&reply, head.keep_alive).is_err()
                                    || !head.keep_alive
                                {
                                    return;
                                }
                            }
                            Relayed::Broken => {
                                edge.log_line(&head.method, &path, 502, "service, broken answer");
                                return;
                            }
                        }
                    }
                }
            }
        }
    }
}
