//! The server: build it from the data, bind a port, serve, stop.
//!
//! A [`Server`] holds the checked data and the options. It opens no port.
//! [`Server::start`] binds the port and gives a [`RunningServer`]. A fixed
//! pool of worker threads serves the connections. One open connection uses
//! one worker, so a PEP that keeps a few connections open needs a pool of that size.

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use procurauth_core::directory::{Directory, analyze_value};
use procurauth_core::finding::{Finding, Report};
use procurauth_core::json::parse_str;
use serde_json::Value;

use crate::clock::Clock;
use crate::config::{
    ConfigLine, DEFAULT_EVALUATIONS_MAX_BYTES, DEFAULT_EVALUATIONS_MAX_ITEMS,
    DEFAULT_IDLE_MAX_SECONDS, DEFAULT_USAGE_MAX_SECONDS, MAX_WORKERS, Options, Settings,
};
use crate::counters::CounterView;
use crate::error::StartError;
use crate::faults::{Fault, FaultSet};
use crate::http::{Connection, Limits, ReadResult};
use crate::log::{EntryLog, LogEntry};
use crate::pdp::Pdp;
use crate::service::{Action, Auth, Shared, State};

/// The most connections that wait for a free worker.
const QUEUE: usize = 64;

/// A server that has its data and its options and that has no open port.
pub struct Server {
    directory: Directory,
    warnings: Vec<Finding>,
    options: Options,
    settings: Settings,
    clock: Clock,
}

impl Server {
    /// Check the text of a data file and build the server. The reader is strict:
    /// a duplicate member is an error. The function returns every finding.
    ///
    /// # Errors
    /// Returns [`StartError::Data`] with every finding when the data is bad, and
    /// [`StartError::Config`] when an option is bad or contradicts the data.
    pub fn from_text(text: &str, options: Options) -> Result<Self, StartError> {
        match parse_str(text) {
            Ok(value) => Self::from_value(&value, options),
            Err(error) => {
                let mut report = Report::new();
                report.error(
                    &error.path,
                    "directory",
                    "bad_json",
                    format!("The text is not valid JSON: {error}."),
                );
                Err(StartError::Data(report.into_findings()))
            }
        }
    }

    /// Check a data file value and build the server.
    ///
    /// # Errors
    /// Returns [`StartError::Data`] with every finding when the data is bad, and
    /// [`StartError::Config`] when an option is bad or contradicts the data.
    pub fn from_value(value: &Value, options: Options) -> Result<Self, StartError> {
        let (directory, report) = analyze_value(value);
        match directory {
            Some(directory) => Self::from_directory(directory, report.into_findings(), options),
            None => Err(StartError::Data(report.into_findings())),
        }
    }

    /// Build the server from a directory that a reader checked.
    /// `warnings` are the findings of the reader that are not errors.
    ///
    /// # Errors
    /// Returns [`StartError::Config`] when an option is bad or contradicts the data.
    pub fn from_directory(
        directory: Directory,
        warnings: Vec<Finding>,
        options: Options,
    ) -> Result<Self, StartError> {
        if !(1..=MAX_WORKERS).contains(&options.workers) {
            return Err(StartError::Config(format!(
                "Key `--workers`: expected a whole number from 1 to {MAX_WORKERS}, found {}.",
                options.workers
            )));
        }
        if let (Some(flag), Some(file)) = (options.clock_start, directory.clock_now) {
            return Err(StartError::Config(format!(
                "Keys `--clock-start` and `clock.now` contradict each other: the flag is {flag} and the data file is {file}. Give only one."
            )));
        }
        let start = options.clock_start.or(directory.clock_now);
        let clock = match start {
            Some(seconds) => Clock::fixed(seconds).map_err(|e| {
                let key = if options.clock_start.is_some() {
                    "--clock-start"
                } else {
                    "clock.now"
                };
                StartError::Config(format!("Key `{key}`: {e}"))
            })?,
            None => Clock::system(),
        };
        let meta = &directory.metadata;
        let settings = Settings {
            usage_max_seconds: meta.usage_max_seconds.unwrap_or(DEFAULT_USAGE_MAX_SECONDS),
            idle_max_seconds: meta.idle_max_seconds.unwrap_or(DEFAULT_IDLE_MAX_SECONDS),
            evaluations_max_bytes: meta
                .evaluations_max_bytes
                .unwrap_or(DEFAULT_EVALUATIONS_MAX_BYTES),
            evaluations_max_items: meta
                .evaluations_max_items
                .unwrap_or(DEFAULT_EVALUATIONS_MAX_ITEMS),
            admin: options.admin,
            workers: options.workers,
            clock_start: start,
        };
        if usize::try_from(settings.evaluations_max_bytes).is_err() {
            return Err(StartError::Config(format!(
                "Key `metadata.evaluations_max_bytes`: expected a whole number up to {}, found {}.",
                usize::MAX,
                settings.evaluations_max_bytes
            )));
        }
        Ok(Self {
            directory,
            warnings,
            options,
            settings,
            clock,
        })
    }

    /// The findings that are warnings. The data is good, and a value can be a mistake.
    pub fn warnings(&self) -> &[Finding] {
        &self.warnings
    }

    /// The values that apply, with the defaults.
    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    /// The directory.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The clock. A test can move it before the server starts.
    pub fn clock(&self) -> &Clock {
        &self.clock
    }

    /// The effective configuration: each key, the value that applies, and its source.
    /// A secret never shows. The credential shows as its origin only.
    pub fn effective_config(&self) -> Vec<ConfigLine> {
        let s = &self.settings;
        let meta = &self.directory.metadata;
        let source = |given: bool| if given { "data file" } else { "default" };
        let mut out = vec![
            ConfigLine::new(
                "--workers",
                s.workers,
                if s.workers == crate::config::DEFAULT_WORKERS {
                    "default"
                } else {
                    "flag"
                },
            ),
            ConfigLine::new(
                "--admin",
                if s.admin { "on" } else { "off" },
                if s.admin { "flag" } else { "default" },
            ),
        ];
        match s.clock_start {
            Some(seconds) => out.push(ConfigLine::new(
                if self.options.clock_start.is_some() {
                    "--clock-start"
                } else {
                    "clock.now"
                },
                seconds,
                if self.options.clock_start.is_some() {
                    "flag"
                } else {
                    "data file"
                },
            )),
            None => out.push(ConfigLine::new("clock", "system", "default")),
        }
        out.push(ConfigLine::new(
            "metadata.usage_max_seconds",
            s.usage_max_seconds,
            source(meta.usage_max_seconds.is_some()),
        ));
        out.push(ConfigLine::new(
            "metadata.idle_max_seconds",
            s.idle_max_seconds,
            source(meta.idle_max_seconds.is_some()),
        ));
        out.push(ConfigLine::new(
            "metadata.evaluations_max_bytes",
            s.evaluations_max_bytes,
            source(meta.evaluations_max_bytes.is_some()),
        ));
        out.push(ConfigLine::new(
            "metadata.evaluations_max_items",
            s.evaluations_max_items,
            source(meta.evaluations_max_items.is_some()),
        ));
        match &self.options.credential {
            Some(credential) => out.push(ConfigLine::new(
                "--credential-file",
                format!("{} (value hidden)", credential.source()),
                "flag",
            )),
            None => out.push(ConfigLine::new("--credential-file", "none", "default")),
        }
        let digests = self
            .directory
            .services
            .iter()
            .filter(|svc| svc.credential_sha256.is_some())
            .count();
        out.push(ConfigLine::new(
            "services.credential_sha256",
            format!(
                "{digests} of {} services (values hidden)",
                self.directory.services.len()
            ),
            "data file",
        ));
        out.push(ConfigLine::new(
            "failures",
            format!(
                "{} from the data file, {} from the failure file",
                self.directory.failures.len(),
                self.options.extra_faults.len()
            ),
            "data file",
        ));
        out.push(ConfigLine::new(
            "directory",
            format!(
                "{} services, {} subjects, {} counters",
                self.directory.services.len(),
                self.directory.subjects.len(),
                self.directory.counters.len()
            ),
            "data file",
        ));
        out
    }

    /// Open the port and start the threads. Port 0 chooses a free port.
    ///
    /// # Errors
    /// Returns [`StartError::Bind`] when the port cannot open.
    pub fn start(self, address: impl ToSocketAddrs) -> Result<RunningServer, StartError> {
        let wanted = address
            .to_socket_addrs()
            .map_err(|source| StartError::Bind {
                address: "the given address".to_owned(),
                source,
            })?
            .next()
            .ok_or_else(|| StartError::Config("The address does not resolve.".to_owned()))?;
        let listener = TcpListener::bind(wanted).map_err(|source| StartError::Bind {
            address: wanted.to_string(),
            source,
        })?;
        let addr = listener.local_addr().map_err(|source| StartError::Bind {
            address: wanted.to_string(),
            source,
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|source| StartError::Bind {
                address: wanted.to_string(),
                source,
            })?;

        let Server {
            directory,
            options,
            settings,
            clock,
            ..
        } = self;
        let mut faults: Vec<Fault> = directory.failures.iter().map(Fault::from_core).collect();
        faults.extend(options.extra_faults);
        let auth = Auth {
            global: options.credential.as_ref().map(|c| c.digest()),
            services: directory
                .services
                .iter()
                .filter_map(|s| {
                    s.credential_sha256
                        .as_deref()
                        .and_then(digest_from_hex)
                        .map(|d| (s.id.clone(), d))
                })
                .collect(),
        };
        let stop = Arc::new(AtomicBool::new(false));
        let now = clock.now_seconds();
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                pdp: Pdp::new(directory, now),
                faults: FaultSet::new(faults),
                entries: EntryLog::default(),
                seq: 0,
                out: options.log,
            }),
            diagnostics: Mutex::new(options.diagnostics),
            clock,
            settings: settings.clone(),
            auth,
            stop: Arc::clone(&stop),
            addr,
        });
        let limits = Limits {
            max_body: usize::try_from(settings.evaluations_max_bytes).unwrap_or(usize::MAX),
            read_timeout: options.read_timeout,
            idle: Duration::from_secs(settings.idle_max_seconds),
        };

        let (sender, receiver) = mpsc::sync_channel::<TcpStream>(QUEUE);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::new();
        for _ in 0..settings.workers {
            let shared = Arc::clone(&shared);
            let receiver = Arc::clone(&receiver);
            workers.push(thread::spawn(move || worker(&shared, &receiver, limits)));
        }
        let accept = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || accept_loop(&listener, &sender, &stop))
        };
        Ok(RunningServer {
            shared,
            accept: Some(accept),
            workers,
        })
    }
}

fn digest_from_hex(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0_u8; 32];
    for (byte, pair) in out.iter_mut().zip(text.as_bytes().chunks(2)) {
        let pair = std::str::from_utf8(pair).ok()?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn accept_loop(listener: &TcpListener, sender: &SyncSender<TcpStream>, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let mut stream = Some(stream);
                while let Some(waiting) = stream.take() {
                    match sender.try_send(waiting) {
                        Ok(()) => {}
                        Err(TrySendError::Full(back)) => {
                            if stop.load(Ordering::SeqCst) {
                                return;
                            }
                            stream = Some(back);
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

fn worker(shared: &Shared, receiver: &Mutex<Receiver<TcpStream>>, limits: Limits) {
    loop {
        let next = receiver
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .recv_timeout(Duration::from_millis(50));
        match next {
            Ok(stream) => serve(shared, stream, limits),
            Err(RecvTimeoutError::Timeout) => {
                if shared.stop.load(Ordering::SeqCst) {
                    return;
                }
            }
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

fn serve(shared: &Shared, stream: TcpStream, limits: Limits) {
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let mut connection = Connection::new(stream, Arc::clone(&shared.stop));
    let idle_seconds = shared.settings.idle_max_seconds;
    while !shared.stop.load(Ordering::SeqCst) {
        match connection.read_request(&limits) {
            ReadResult::Closed => return,
            ReadResult::Reject(response) => {
                shared.note_transport_reject(response.status);
                let _ = connection.write_response(&response, false, idle_seconds);
                return;
            }
            ReadResult::Request(request) => {
                let keep = request.keep_alive && !shared.stop.load(Ordering::SeqCst);
                match shared.handle(&request) {
                    Action::Respond(response) => {
                        if connection
                            .write_response(&response, keep, idle_seconds)
                            .is_err()
                            || !keep
                        {
                            return;
                        }
                    }
                    Action::Close => {
                        connection.close();
                        return;
                    }
                    Action::Hold => {
                        connection.hold_open();
                        return;
                    }
                }
            }
        }
    }
}

/// A server that listens. Drop it, or call [`RunningServer::shutdown`], to stop it.
pub struct RunningServer {
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
    workers: Vec<JoinHandle<()>>,
}

impl RunningServer {
    /// The address that the listener bound. With port 0, this holds the port that the system chose.
    pub fn local_addr(&self) -> SocketAddr {
        self.shared.addr
    }

    /// The base URL of the server, for example `http://127.0.0.1:8181`.
    pub fn url(&self) -> String {
        format!("http://{}", self.shared.addr)
    }

    /// The clock of the server. A change takes effect at once for all threads.
    pub fn clock(&self) -> &Clock {
        &self.shared.clock
    }

    /// The values that apply.
    pub fn settings(&self) -> &Settings {
        &self.shared.settings
    }

    /// The counters of the current windows.
    pub fn counters(&self) -> Vec<CounterView> {
        self.shared.counter_view()
    }

    /// Put the counters back to the first values of the data.
    pub fn reset_counters(&self) {
        let now = self.shared.now_seconds();
        self.shared.state().pdp.reset_counters(now);
    }

    /// The last questions, oldest first.
    pub fn log(&self) -> Vec<LogEntry> {
        self.shared.state().entries.entries()
    }

    /// Replace all the failure rules.
    pub fn set_faults(&self, faults: Vec<Fault>) {
        self.shared.state().faults.replace(faults);
    }

    /// Stop the server. A request in progress ends first, and each thread ends.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
        if let Some(out) = &mut self.shared.state().out {
            let _ = out.flush();
        }
    }

    /// True when a stop was asked for.
    pub fn is_stopped(&self) -> bool {
        self.shared.stop.load(Ordering::SeqCst)
    }
}

impl Drop for RunningServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_digest_in_hexadecimal_is_read_and_a_bad_one_is_not() {
        let good = "ab".repeat(32);
        assert_eq!(digest_from_hex(&good), Some([0xab; 32]));
        assert_eq!(digest_from_hex("ab"), None);
        assert_eq!(digest_from_hex(&"zz".repeat(32)), None);
    }

    #[test]
    fn two_clocks_contradict_each_other() {
        let data = serde_json::json!({"services": [], "subjects": [], "clock": {"now": 5}});
        let options = Options {
            clock_start: Some(6),
            ..Options::default()
        };
        let message = Server::from_value(&data, options)
            .err()
            .unwrap()
            .to_string();
        assert!(
            message.contains("--clock-start") && message.contains("clock.now"),
            "{message}"
        );
        assert!(message.contains('6') && message.contains('5'), "{message}");
    }

    #[test]
    fn the_flag_gives_a_fixed_clock_and_the_effective_configuration_shows_the_source() {
        let data = serde_json::json!({"services": [], "subjects": []});
        let options = Options {
            clock_start: Some(77),
            admin: true,
            ..Options::default()
        };
        let server = Server::from_value(&data, options).unwrap();
        assert_eq!(server.clock().now_seconds(), 77);
        let lines = server.effective_config();
        let find = |key: &str| lines.iter().find(|l| l.key == key).unwrap().clone();
        assert_eq!(find("--clock-start").source, "flag");
        assert_eq!(find("--admin").value, "on");
        assert_eq!(find("metadata.usage_max_seconds").source, "default");
    }

    #[test]
    fn bad_data_gives_every_finding() {
        let data = serde_json::json!({"services": 1, "subjects": [{"id": "key:abc"}], "x": 1});
        match Server::from_value(&data, Options::default()) {
            Err(StartError::Data(findings)) => assert!(findings.len() >= 3, "{findings:?}"),
            other => panic!("{:?}", other.err()),
        }
        assert!(matches!(
            Server::from_text(r#"{"services": [], "services": []}"#, Options::default()),
            Err(StartError::Data(_))
        ));
    }
}
