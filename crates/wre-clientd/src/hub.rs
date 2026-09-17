use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use wre_client::client::{Client, Registry, prepare_params};
use wre_client::context::{Call, Counters, Ctx, EventSink, Services};
use wre_client::diag::{DiagConfig, Recorder};
use wre_client::error::{ClientError, ClientResult};
use wre_client::proto::{DiagReply, Envelope, Frame, OpenReply, OpenRequest, ops};
use wre_client::spec::{BundleDescriptor, Concurrency, Hello, PROTOCOL_VERSION};

use crate::registry::BUNDLE;

pub enum Outgoing {
    Frame(Frame),
    Stop,
}

pub enum Action {
    Continue,
    Shutdown,
}

pub type Cancels = Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>>;

pub fn descriptor(registry: &Registry) -> BundleDescriptor {
    BundleDescriptor {
        protocol: PROTOCOL_VERSION,
        bundle: BUNDLE.to_string(),
        toolkit_version: wre_core::VERSION.to_string(),
        binary_version: env!("CARGO_PKG_VERSION").to_string(),
        clients: registry.descriptors(),
    }
}

struct FrameEvents {
    out: Sender<Outgoing>,
}

impl EventSink for FrameEvents {
    fn emit(&self, id: u64, event: &str, data: Value) {
        if let Ok(frame) = Frame::from_envelope(&Envelope::event(id, event, data)) {
            let _ = self.out.send(Outgoing::Frame(frame));
        }
    }
}

enum Job {
    Open {
        id: u64,
        session: String,
        target: String,
        config: Value,
        diag: Value,
        host: Value,
        capabilities: Value,
        client_version: String,
        out: Sender<Outgoing>,
    },
    Call {
        id: u64,
        session: String,
        op: String,
        params: Value,
        bin: Vec<u8>,
        deadline: Option<Instant>,
        cancel: Arc<AtomicBool>,
        cancels: Cancels,
        out: Sender<Outgoing>,
    },
    Close {
        id: Option<u64>,
        session: String,
        out: Option<Sender<Outgoing>>,
    },
    Stop,
}

/// A worker slot. `load` lives OUTSIDE the mutex so `pick_worker` and
/// `metrics` read it without locking; `slot` holds the pieces that must be
/// replaced atomically when a dead thread is revived.
struct Worker {
    load: Arc<AtomicUsize>,
    slot: Mutex<WorkerSlot>,
}

struct WorkerSlot {
    jobs: Sender<Job>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// Spawn one worker thread and hand back the channel that feeds it.
///
/// Extracted from `Hub::new` so `Hub::send` can rebuild a slot in place. The
/// `.expect("worker thread")` that used to stand here is gone: a spawn failure
/// at revival time is an ordinary error the caller can retry, not a reason to
/// take the process down.
fn spawn_worker(
    index: usize,
    registry: Arc<Registry>,
    services: Arc<Services>,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    load: Arc<AtomicUsize>,
) -> std::io::Result<WorkerSlot> {
    let (jobs, inbox) = channel();
    let handle = std::thread::Builder::new()
        .name(format!("wred-worker-{index}"))
        .spawn(move || run_worker(index, inbox, registry, services, sessions, load))?;
    Ok(WorkerSlot { jobs, handle: Some(handle) })
}

#[derive(Debug, Clone)]
struct SessionEntry {
    worker: usize,
    connection: u64,
    target: String,
}

pub struct Hub {
    registry: Arc<Registry>,
    services: Arc<Services>,
    counters: Arc<Counters>,
    workers: Vec<Worker>,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    next_session: AtomicU64,
    started: Instant,
    stopping: AtomicBool,
}

impl Hub {
    pub fn new(
        registry: Registry,
        services: Arc<Services>,
        counters: Arc<Counters>,
        worker_count: usize,
    ) -> Arc<Self> {
        let registry = Arc::new(registry);
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let mut workers = Vec::with_capacity(worker_count.max(1));

        for index in 0..worker_count.max(1) {
            let load = Arc::new(AtomicUsize::new(0));
            let slot = spawn_worker(
                index,
                Arc::clone(&registry),
                Arc::clone(&services),
                Arc::clone(&sessions),
                Arc::clone(&load),
            )
            .expect("worker thread");
            workers.push(Worker { load, slot: Mutex::new(slot) });
        }

        Arc::new(Self {
            registry,
            services,
            counters,
            workers,
            sessions,
            next_session: AtomicU64::new(1),
            started: Instant::now(),
            stopping: AtomicBool::new(false),
        })
    }

    pub fn hello(&self) -> Hello {
        let descriptor = self.describe();
        Hello {
            protocol: PROTOCOL_VERSION,
            bundle: BUNDLE.to_string(),
            binary_version: env!("CARGO_PKG_VERSION").to_string(),
            toolkit_version: wre_core::VERSION.to_string(),
            schema_hash: descriptor.schema_hash(),
            targets: self.registry.ids(),
            workers: self.workers.len(),
            pid: std::process::id(),
        }
    }

    pub fn describe(&self) -> BundleDescriptor {
        descriptor(&self.registry)
    }

    pub fn targets(&self) -> Vec<String> {
        self.registry.ids()
    }

    pub fn metrics(&self) -> Value {
        let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
        let per_worker: Vec<usize> = self
            .workers
            .iter()
            .map(|worker| worker.load.load(Ordering::Relaxed))
            .collect();

        json!({
            "uptime_ms": self.started.elapsed().as_millis() as u64,
            "sessions": sessions.len(),
            "workers": per_worker,
            "counters": self.counters.snapshot(),
        })
    }

    pub fn handle(
        &self,
        connection: u64,
        envelope: Envelope,
        bin: Vec<u8>,
        out: &Sender<Outgoing>,
        cancels: &Cancels,
    ) -> Action {
        match envelope {
            Envelope::Cancel { id, .. } => {
                let map = cancels.lock().unwrap_or_else(|error| error.into_inner());
                if let Some(flag) = map.get(&id) {
                    flag.store(true, Ordering::Relaxed);
                }
                Action::Continue
            }

            Envelope::Req { v, id, op, session, params, deadline_ms } => {
                if v != PROTOCOL_VERSION {
                    reply_error(
                        out,
                        id,
                        ClientError::protocol(format!(
                            "this host speaks protocol {PROTOCOL_VERSION} and the caller sent {v}"
                        )),
                    );
                    return Action::Continue;
                }

                self.dispatch(connection, id, &op, session, params, bin, deadline_ms, out, cancels)
            }

            other => {
                tracing::debug!("ignoring {:?} from a caller", other);
                Action::Continue
            }
        }
    }

    fn dispatch(
        &self,
        connection: u64,
        id: u64,
        op: &str,
        session: Option<String>,
        params: Value,
        bin: Vec<u8>,
        deadline_ms: Option<u64>,
        out: &Sender<Outgoing>,
        cancels: &Cancels,
    ) -> Action {
        match op {
            ops::HELLO => {
                reply_value(out, id, serde_json::to_value(self.hello()).unwrap_or(Value::Null));
                Action::Continue
            }

            ops::DESCRIBE => {
                reply_value(out, id, serde_json::to_value(self.describe()).unwrap_or(Value::Null));
                Action::Continue
            }

            ops::TARGETS => {
                reply_value(out, id, json!(self.targets()));
                Action::Continue
            }

            ops::METRICS => {
                reply_value(out, id, self.metrics());
                Action::Continue
            }

            ops::SHUTDOWN => {
                self.stopping.store(true, Ordering::Relaxed);
                reply_value(out, id, json!({ "stopping": true }));
                Action::Shutdown
            }

            ops::OPEN => {
                match self.open(connection, id, params, out) {
                    Ok(()) => {}
                    Err(error) => reply_error(out, id, error),
                }
                Action::Continue
            }

            _ => {
                let Some(session) = session else {
                    reply_error(
                        out,
                        id,
                        ClientError::bad_input(format!("{op} needs a session, open one first"))
                            .with_op(op),
                    );
                    return Action::Continue;
                };

                match self.route(id, op, session, params, bin, deadline_ms, out, cancels) {
                    Ok(()) => {}
                    Err(error) => reply_error(out, id, error.with_op(op)),
                }
                Action::Continue
            }
        }
    }

    fn open(
        &self,
        connection: u64,
        id: u64,
        params: Value,
        out: &Sender<Outgoing>,
    ) -> ClientResult<()> {
        let request: OpenRequest = serde_json::from_value(params)
            .map_err(|error| ClientError::bad_input(format!("open rejected: {error}")))?;

        if self.registry.descriptor(&request.target).is_none() {
            return Err(ClientError::unsupported(format!(
                "target {} is not in this build, it has {}",
                request.target,
                list(&self.registry.ids())
            )));
        }

        let session = format!("s{}", self.next_session.fetch_add(1, Ordering::Relaxed));
        let worker = self.pick_worker(&request.target);

        {
            let mut sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
            sessions.insert(
                session.clone(),
                SessionEntry { worker, connection, target: request.target.clone() },
            );
        }

        self.workers[worker].load.fetch_add(1, Ordering::Relaxed);

        let descriptor = self
            .registry
            .descriptor(&request.target)
            .ok_or_else(|| ClientError::internal(format!("target {} vanished", request.target)))?;

        let job = Job::Open {
            id,
            session,
            target: request.target.clone(),
            config: request.config,
            diag: request.diag,
            host: serde_json::to_value(self.hello()).unwrap_or(Value::Null),
            capabilities: serde_json::to_value(&descriptor.capabilities).unwrap_or(Value::Null),
            client_version: descriptor.version.clone(),
            out: out.clone(),
        };

        self.send(worker, job)
    }

    fn route(
        &self,
        id: u64,
        op: &str,
        session: String,
        params: Value,
        bin: Vec<u8>,
        deadline_ms: Option<u64>,
        out: &Sender<Outgoing>,
        cancels: &Cancels,
    ) -> ClientResult<()> {
        let entry = {
            let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
            sessions.get(&session).cloned()
        };

        let entry = entry.ok_or_else(|| {
            ClientError::unsupported(format!("session {session} is closed or was never opened"))
        })?;

        let descriptor = self
            .registry
            .descriptor(&entry.target)
            .ok_or_else(|| ClientError::internal(format!("target {} vanished", entry.target)))?;

        if op == ops::CLOSE {
            self.forget(&session);
            self.workers[entry.worker].load.fetch_sub(1, Ordering::Relaxed);
            return self.send(
                entry.worker,
                Job::Close { id: Some(id), session, out: Some(out.clone()) },
            );
        }

        let (params, deadline) = if op == ops::HEALTH || op == ops::WARMUP || op == ops::DIAG {
            (params, deadline_ms.map(millis))
        } else {
            let prepared = prepare_params(descriptor, op, params)?;
            let declared = descriptor.find(op).map(|spec| spec.deadline_ms).unwrap_or(0);
            let chosen = deadline_ms.or(if declared > 0 { Some(declared) } else { None });
            (prepared, chosen.map(millis))
        };

        let cancel = Arc::new(AtomicBool::new(false));
        {
            let mut map = cancels.lock().unwrap_or_else(|error| error.into_inner());
            map.insert(id, Arc::clone(&cancel));
        }

        self.send(
            entry.worker,
            Job::Call {
                id,
                session,
                op: op.to_string(),
                params,
                bin,
                deadline,
                cancel,
                cancels: Arc::clone(cancels),
                out: out.clone(),
            },
        )
    }

    fn pick_worker(&self, target: &str) -> usize {
        let pinned = self
            .registry
            .descriptor(target)
            .map(|descriptor| descriptor.capabilities.concurrency == Concurrency::SingleThread)
            .unwrap_or(false);

        if pinned {
            let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
            if let Some(entry) = sessions.values().find(|entry| entry.target == target) {
                return entry.worker;
            }
        }

        // A worker whose thread has exited (e.g. a panic inside V8) still owns
        // its `load` counter, and that counter never rises again because the
        // worker processes nothing. `min_by_key` therefore PREFERS dead workers,
        // turning a single panic into a black hole that attracts every
        // subsequent job — each of which fails with "worker N is gone".
        //
        // Observed in production 2026-08-26: one V8 isolate-ordering panic
        // degraded into 7 of 32 workers dead and ~40% of all jobs failing,
        // with no recovery short of a process restart.
        //
        // Skip finished threads. If every worker is dead we fall back to index
        // 0, which `send` now REVIVES rather than reporting gone — so an
        // all-dead hub heals on the next job instead of staying dead.
        self.workers
            .iter()
            .enumerate()
            .filter(|(_, worker)| {
                let slot = worker.slot.lock().unwrap_or_else(|e| e.into_inner());
                slot.handle.as_ref().is_none_or(|handle| !handle.is_finished())
            })
            .min_by_key(|(_, worker)| worker.load.load(Ordering::Relaxed))
            .map(|(index, _)| index)
            .unwrap_or(0)
    }

    fn send(&self, worker: usize, job: Job) -> ClientResult<()> {
        // REVIVE THE WORKER. Do not merely report it dead.
        //
        // Worker threads were spawned once, in `Hub::new`, and nothing ever
        // rebuilt one. A panic inside V8 therefore retired that worker for the
        // lifetime of the process: `pick_worker` skipped it, and once every
        // worker had panicked its all-dead fallback to index 0 made each
        // subsequent job fail instantly with "worker 0 is gone".
        //
        // Measured in production 2026-09-17: 1338 of ~1900 dining calls in 75
        // minutes returned exactly that, at durationMs 4 — the sidecar was up,
        // listening and reporting 8 workers, every one of them a corpse. The
        // failure is permanent without a process restart, which is why dining
        // stayed down for 33 hours rather than degrading and recovering.
        //
        // A dead thread drops its Receiver, so `send` on the old channel would
        // have errored anyway; the error was never the problem. The problem was
        // that nothing replaced the thread. So: rebuild the slot, reset its
        // load, and drop the session bindings that pointed into the dead
        // isolate (the new thread has none of that state, and a session that
        // silently resolves to a fresh isolate is worse than one that is gone).
        let revived = {
            let mut slot = self.workers[worker].slot.lock().unwrap_or_else(|e| e.into_inner());
            let dead = slot.handle.as_ref().is_some_and(|handle| handle.is_finished());
            if dead && !self.stopping() {
                let fresh = spawn_worker(
                    worker,
                    Arc::clone(&self.registry),
                    Arc::clone(&self.services),
                    Arc::clone(&self.sessions),
                    Arc::clone(&self.workers[worker].load),
                )
                .map_err(|err| {
                    ClientError::internal(format!("worker {worker} died and could not be respawned: {err}"))
                })?;
                *slot = fresh;
                self.workers[worker].load.store(0, Ordering::Relaxed);
                true
            } else {
                false
            }
        };

        if revived {
            let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
            sessions.retain(|_, entry| entry.worker != worker);
            tracing::warn!(worker, "worker thread had exited; respawned it");
        }

        let slot = self.workers[worker].slot.lock().unwrap_or_else(|e| e.into_inner());
        slot.jobs
            .send(job)
            .map_err(|_| ClientError::internal(format!("worker {worker} is gone")))
    }

    fn forget(&self, session: &str) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
        sessions.remove(session);
    }

    pub fn close_connection(&self, connection: u64) {
        let owned: Vec<(String, usize)> = {
            let sessions = self.sessions.lock().unwrap_or_else(|error| error.into_inner());
            sessions
                .iter()
                .filter(|(_, entry)| entry.connection == connection)
                .map(|(id, entry)| (id.clone(), entry.worker))
                .collect()
        };

        for (session, worker) in owned {
            self.forget(&session);
            self.workers[worker].load.fetch_sub(1, Ordering::Relaxed);
            let _ = self.send(worker, Job::Close { id: None, session, out: None });
        }
    }

    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        for worker in &self.workers {
            let slot = worker.slot.lock().unwrap_or_else(|e| e.into_inner());
            let _ = slot.jobs.send(Job::Stop);
        }
    }
}

impl Drop for Hub {
    fn drop(&mut self) {
        for worker in &mut self.workers {
            let mut slot = worker.slot.lock().unwrap_or_else(|e| e.into_inner());
            let _ = slot.jobs.send(Job::Stop);
            if let Some(handle) = slot.handle.take() {
                let _ = handle.join();
            }
        }
    }
}

fn millis(value: u64) -> Instant {
    Instant::now() + Duration::from_millis(value)
}

fn list(values: &[String]) -> String {
    if values.is_empty() { "none".to_string() } else { values.join(", ") }
}

fn reply_value(out: &Sender<Outgoing>, id: u64, value: Value) {
    if let Ok(frame) = Frame::from_envelope(&Envelope::ok(id, value, 0)) {
        let _ = out.send(Outgoing::Frame(frame));
    }
}

fn reply_error(out: &Sender<Outgoing>, id: u64, error: ClientError) {
    if let Ok(frame) = Frame::from_envelope(&Envelope::failed(id, error, 0)) {
        let _ = out.send(Outgoing::Frame(frame));
    }
}

fn reply(out: &Sender<Outgoing>, id: u64, outcome: ClientResult<Value>, took_ms: u64, bin: Vec<u8>) {
    let envelope = match outcome {
        Ok(value) => Envelope::ok(id, value, took_ms),
        Err(error) => Envelope::failed(id, error, took_ms),
    };

    if let Ok(frame) = Frame::from_envelope(&envelope) {
        let _ = out.send(Outgoing::Frame(frame.with_bin(bin)));
    }
}

struct Live {
    client: Box<dyn Client>,
    recorder: Arc<Recorder>,
}

fn diagnostics_dir(services: &Services) -> std::path::PathBuf {
    services.state_root().join("diagnostics")
}

fn maybe_report(
    recorder: &Arc<Recorder>,
    services: &Arc<Services>,
    reason: &str,
    error: ClientError,
    client: Value,
) -> ClientError {
    if !recorder.should_write(true) {
        return error;
    }

    let report = recorder.report(reason, Some(&error), client);

    match recorder.write(&report, &diagnostics_dir(services)) {
        Ok(path) => {
            tracing::warn!("wrote diagnostics for {} to {}", recorder.target(), path.display());
            with_report_path(error, &path)
        }
        Err(inner) => {
            tracing::warn!("diagnostics could not be written: {inner}");
            error
        }
    }
}

fn with_report_path(mut error: ClientError, path: &std::path::Path) -> ClientError {
    let entry = json!(path.display().to_string());

    match error.detail.as_object_mut() {
        Some(entries) => {
            entries.insert("diagnostics".to_string(), entry);
        }
        None => {
            error.detail = json!({ "diagnostics": entry });
        }
    }

    error
}

fn diagnose(live: &mut Live, services: &Arc<Services>, params: &Value) -> ClientResult<Value> {
    let write = params.get("write").and_then(Value::as_bool).unwrap_or(true);
    let include_events = params.get("events").and_then(Value::as_bool).unwrap_or(true);

    let extra = live.client.diagnostics();
    let mut report = live.recorder.report("requested", None, extra);

    if !include_events {
        report.events.clear();
    }

    let path = if write && live.recorder.enabled() {
        match live.recorder.write(&report, &diagnostics_dir(services)) {
            Ok(path) => Some(path.display().to_string()),
            Err(error) => {
                tracing::warn!("diagnostics could not be written: {error}");
                None
            }
        }
    } else {
        live.recorder.last_report().map(|path| path.display().to_string())
    };

    let reply = DiagReply {
        target: live.recorder.target().to_string(),
        session: live.recorder.session().to_string(),
        mode: live.recorder.mode().as_str().to_string(),
        path,
        report: serde_json::to_value(&report).unwrap_or(Value::Null),
    };

    serde_json::to_value(reply)
        .map_err(|error| ClientError::internal(format!("diag reply failed: {error}")))
}

fn run_worker(
    index: usize,
    inbox: Receiver<Job>,
    registry: Arc<Registry>,
    services: Arc<Services>,
    sessions: Arc<Mutex<HashMap<String, SessionEntry>>>,
    load: Arc<AtomicUsize>,
) {
    let mut clients: HashMap<String, Live> = HashMap::new();

    while let Ok(job) = inbox.recv() {
        match job {
            Job::Stop => break,

            Job::Open { id, session, target, config, diag, host, capabilities, client_version, out } => {
                let started = Instant::now();

                let mut settings = DiagConfig::from_env();
                settings.merge(&diag);

                let recorder = Arc::new(Recorder::new(settings, target.clone(), session.clone()));
                recorder.set_host(host);
                recorder.set_capabilities(capabilities);
                recorder.set_client_version(client_version);
                recorder.set_config(&config);
                recorder.record("info", "session.open", "session opened", json!({ "target": target }));

                let ctx = Ctx::new(target.clone(), session.clone(), Arc::clone(&services))
                    .with_recorder(Arc::clone(&recorder));

                match registry.build(&target, ctx, config) {
                    Ok(client) => {
                        let ops = registry
                            .descriptor(&target)
                            .map(|descriptor| {
                                descriptor.ops.iter().map(|spec| spec.name.clone()).collect()
                            })
                            .unwrap_or_default();

                        clients.insert(session.clone(), Live { client, recorder });

                        let value = serde_json::to_value(OpenReply {
                            session,
                            target,
                            worker: index,
                            ops,
                        })
                        .unwrap_or(Value::Null);

                        reply(&out, id, Ok(value), started.elapsed().as_millis() as u64, Vec::new());
                    }
                    Err(error) => {
                        {
                            let mut map =
                                sessions.lock().unwrap_or_else(|inner| inner.into_inner());
                            map.remove(&session);
                        }
                        load.fetch_sub(1, Ordering::Relaxed);

                        recorder.op_finished(id, ops::OPEN, 0, Err(&error));
                        let error = maybe_report(
                            &recorder,
                            &services,
                            "open failed",
                            error,
                            Value::Null,
                        );

                        reply(
                            &out,
                            id,
                            Err(error),
                            started.elapsed().as_millis() as u64,
                            Vec::new(),
                        );
                    }
                }
            }

            Job::Call { id, session, op, params, bin, deadline, cancel, cancels, out } => {
                let started = Instant::now();
                let events = Arc::new(FrameEvents { out: out.clone() });
                let call = Call::new(id, op.clone(), deadline, cancel, events).with_input(bin);

                let outcome = match clients.get_mut(&session) {
                    Some(live) => {
                        let call = call.with_recorder(Arc::clone(&live.recorder));
                        live.recorder.op_started(id, &op, &params);

                        let outcome = match op.as_str() {
                            ops::HEALTH => live.client.health(),
                            ops::WARMUP => {
                                live.client.warmup(&call).map(|_| json!({ "warm": true }))
                            }
                            ops::DIAG => diagnose(live, &services, &params),
                            _ => live.client.call(&op, params, &call),
                        };

                        let took = started.elapsed().as_millis() as u64;
                        live.recorder.op_finished(
                            id,
                            &op,
                            took,
                            outcome.as_ref().map_err(|error| error),
                        );

                        let outcome = match outcome {
                            Ok(value) => Ok(value),
                            Err(error) => {
                                let extra = live.client.diagnostics();
                                Err(maybe_report(
                                    &live.recorder,
                                    &services,
                                    &format!("{op} failed"),
                                    error,
                                    extra,
                                ))
                            }
                        };

                        (outcome, call.take_output())
                    }
                    None => (
                        Err(ClientError::unsupported(format!(
                            "session {session} is not on this worker"
                        ))),
                        Vec::new(),
                    ),
                };

                let (outcome, produced) = outcome;
                reply(&out, id, outcome, started.elapsed().as_millis() as u64, produced);

                let mut pending = cancels.lock().unwrap_or_else(|inner| inner.into_inner());
                pending.remove(&id);
            }

            Job::Close { id, session, out } => {
                let outcome = match clients.remove(&session) {
                    Some(mut live) => {
                        live.recorder.record("info", "session.close", "session closed", Value::Null);
                        live.client.close().map(|_| json!({ "closed": true }))
                    }
                    None => Ok(json!({ "closed": false })),
                };

                if let (Some(id), Some(out)) = (id, out) {
                    reply(&out, id, outcome, 0, Vec::new());
                }
            }
        }
    }

    for (_, mut live) in clients.drain() {
        let _ = live.client.close();
    }
}


#[cfg(test)]
mod dead_worker_tests {
    use super::*;
    use wre_client::MetricSink;
    use std::sync::mpsc::channel;
    use std::time::Duration;

    /// A worker slot whose thread has exited.
    ///
    /// This is what a V8 panic leaves behind, and until 2026-09-17 it was
    /// PERMANENT: threads were spawned once in `Hub::new` and nothing ever
    /// rebuilt one. Production ran out of live workers entirely and every
    /// subsequent job failed instantly with "worker 0 is gone" — 1338 of ~1900
    /// dining calls in 75 minutes, at durationMs 4, against a sidecar that was
    /// up and reporting 8 workers.
    fn dead_slot() -> WorkerSlot {
        let (jobs, rx) = channel::<Job>();
        let handle = std::thread::spawn(move || {
            let _rx = rx;
        });
        while !handle.is_finished() {
            std::thread::sleep(Duration::from_millis(5));
        }
        WorkerSlot { jobs, handle: Some(handle) }
    }

    fn hub_with(slot: WorkerSlot) -> Hub {
        let dir = std::env::temp_dir().join(format!("wred-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let counters = Arc::new(Counters::default());
        let services = Services::new(None, dir, Arc::clone(&counters) as Arc<dyn MetricSink>)
            .expect("services");
        Hub {
            registry: Arc::new(Registry::default()),
            services,
            counters,
            workers: vec![Worker { load: Arc::new(AtomicUsize::new(7)), slot: Mutex::new(slot) }],
            sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session: AtomicU64::new(0),
            started: Instant::now(),
            stopping: AtomicBool::new(false),
        }
    }

    /// THE regression test for the 33-hour dining outage.
    ///
    /// Pre-fix this returns Err("worker 0 is gone") forever, for every job, for
    /// the life of the process. Post-fix the slot is rebuilt and the job lands.
    #[test]
    fn send_respawns_a_worker_whose_thread_has_exited() {
        let hub = hub_with(dead_slot());

        hub.send(0, Job::Close { id: None, session: "s".into(), out: None })
            .expect("a dead worker must be revived, not reported gone forever");

        let slot = hub.workers[0].slot.lock().unwrap();
        assert!(
            !slot.handle.as_ref().unwrap().is_finished(),
            "the slot must now hold a LIVE thread, not the corpse it started with"
        );
        assert_eq!(
            hub.workers[0].load.load(Ordering::Relaxed),
            0,
            "a revived worker starts at zero load; a stale count would make \
             pick_worker mis-rank it forever"
        );
    }

    /// Sessions bound to the dead isolate must NOT survive the respawn.
    ///
    /// The fresh thread has none of that state, so a session that silently
    /// resolves to a new isolate is worse than one that is gone — the caller
    /// would get a confusing wrong-state answer instead of a clean retry.
    #[test]
    fn respawning_purges_the_sessions_bound_to_the_dead_worker() {
        let hub = hub_with(dead_slot());
        hub.sessions.lock().unwrap().insert(
            "stale".into(),
            SessionEntry { worker: 0, connection: 1, target: "t".into() },
        );

        hub.send(0, Job::Close { id: None, session: "s".into(), out: None }).expect("revived");

        assert!(
            hub.sessions.lock().unwrap().is_empty(),
            "sessions pointing into the dead isolate must be dropped"
        );
    }

    /// A shutting-down hub must NOT resurrect workers it just told to stop.
    #[test]
    fn a_stopping_hub_does_not_respawn() {
        let hub = hub_with(dead_slot());
        hub.stopping.store(true, Ordering::Relaxed);

        let result = hub.send(0, Job::Close { id: None, session: "s".into(), out: None });

        assert!(result.is_err(), "no revival during shutdown");
    }

    /// A worker that is ALIVE but BLOCKED — the case this fix does NOT cover.
    ///
    /// Recorded deliberately so nobody mistakes respawn for a cure-all. A thread
    /// wedged inside V8 reports `is_finished() == false` and its channel is
    /// connected, so the job is accepted and the caller waits out its own
    /// timeout. Fixing that needs a per-job deadline inside the worker loop.
    #[test]
    fn a_blocked_but_living_worker_is_not_caught_by_the_respawn_check() {
        let (jobs, rx) = channel::<Job>();
        let blocked = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(30));
            drop(rx);
        });
        let slot = WorkerSlot { jobs, handle: Some(blocked) };

        assert!(
            !slot.handle.as_ref().unwrap().is_finished(),
            "a wedged worker reports as alive"
        );
        assert!(
            slot.jobs.send(Job::Close { id: None, session: "s".into(), out: None }).is_ok(),
            "and accepts jobs it will never process — the caller hangs"
        );
    }
}
