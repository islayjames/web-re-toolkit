use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::channel;
use std::sync::{Arc, Mutex};

use wre_client::proto::{read_frame, write_frame};

use crate::hub::{Action, Cancels, Hub, Outgoing};

static CONNECTIONS: AtomicU64 = AtomicU64::new(1);

/// Live connections right now. Paired with `MAX_LIVE_CONNECTIONS` to bound the
/// accept loop.
static LIVE: AtomicUsize = AtomicUsize::new(0);

/// Ceiling on concurrent connections.
///
/// Each connection costs TWO OS threads — the detached handler at the accept
/// loop and the `wred-writer-N` pump — and neither is reclaimed until `run()`
/// returns. The container this ships in has `pids.max = 1000`, so an unbounded
/// accept loop is a PID bomb waiting on any client that forgets to close.
///
/// It waited, and then it went off: a caller leaked a socket on four failure
/// paths, threads climbed monotonically, and `Builder::spawn` eventually
/// returned EAGAIN. Dining availability was down 23 hours.
///
/// 200 connections = 400 threads, leaving headroom over the 8 worker threads
/// and the ~15-thread lazily-created baseline. A server should survive a
/// misbehaving client by refusing it, not by dying with it.
const MAX_LIVE_CONNECTIONS: usize = 200;

/// Idle timeout on a connection socket.
///
/// This is what actually RECLAIMS a leaked connection rather than merely
/// capping it: without it, "the client forgot to close" is permanent. The
/// sibling crate already does this — `wre-sandbox/src/capture.rs` sets 20s
/// read/write timeouts — so this is applying an in-tree convention, not
/// inventing one.
///
/// The write timeout matters independently: a peer that stops reading fills the
/// socket buffer, `write_frame` blocks forever, the pump never sees `Stop`, and
/// `pump.join()` deadlocks the handler thread too. Both threads leak on a
/// connection that DID signal EOF.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Consecutive idle timeouts tolerated before a connection is reclaimed.
///
/// A timeout is NOT an error — the reference client legitimately holds a warm
/// Akamai session idle between sweeps (15 min idle TTL, 30 min absolute max in
/// `wreProvider.ts`), so treating the first timeout as EOF would destroy every
/// cached session and turn a leak fix into a throughput regression.
///
/// 60s x 35 = 35 minutes: comfortably past the client's own 30-minute ceiling,
/// so a connection is only reclaimed once it is genuinely abandoned rather than
/// merely quiet.
const MAX_IDLE_STRIKES: u32 = 35;

/// Decrements `LIVE` however the connection thread exits — including on a
/// panic, which is the case a bare decrement at the end would miss.
struct LiveGuard;

impl Drop for LiveGuard {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn stdio(hub: &Arc<Hub>) {
    let reader = BufReader::new(std::io::stdin());
    let writer = BufWriter::new(std::io::stdout());
    let _ = run(hub, reader, writer);
}

#[cfg(unix)]
pub fn socket(hub: &Arc<Hub>, path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::net::UnixListener;

    if path.exists() {
        std::fs::remove_file(path)?;
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(path)?;
    tracing::info!("listening on {}", path.display());

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!("accept failed: {error}");
                continue;
            }
        };

        // Refuse rather than die. Above the cap we drop the stream, which the
        // client sees as a closed connection — a clean, retryable failure of ONE
        // request instead of an EAGAIN panic that costs the whole process.
        let live = LIVE.load(Ordering::SeqCst);
        if live >= MAX_LIVE_CONNECTIONS {
            tracing::error!(
                "refusing connection: {live} live >= cap {MAX_LIVE_CONNECTIONS}. \
                 A client is leaking connections; each costs 2 threads and this \
                 process has a PID ceiling."
            );
            drop(stream);
            continue;
        }

        // Idle timeouts, set before the handler starts, so a wedged connection
        // unwinds instead of pinning two threads forever.
        if let Err(error) = stream.set_read_timeout(Some(IO_TIMEOUT)) {
            tracing::warn!("could not set read timeout: {error}");
        }
        if let Err(error) = stream.set_write_timeout(Some(IO_TIMEOUT)) {
            tracing::warn!("could not set write timeout: {error}");
        }

        let writer = match stream.try_clone() {
            Ok(clone) => clone,
            Err(error) => {
                tracing::warn!("connection could not be split: {error}");
                continue;
            }
        };

        LIVE.fetch_add(1, Ordering::SeqCst);
        let worker_hub = Arc::clone(hub);
        std::thread::spawn(move || {
            let _guard = LiveGuard;
            let stop = run(&worker_hub, BufReader::new(stream), BufWriter::new(writer));
            if stop {
                worker_hub.stop();
                std::process::exit(0);
            }
        });

        if hub.stopping() {
            break;
        }
    }

    let _ = std::fs::remove_file(path);
    Ok(())
}

#[cfg(not(unix))]
pub fn socket(_hub: &Arc<Hub>, _path: &std::path::Path) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "socket mode needs a unix platform, use --stdio",
    ))
}

fn run<R, W>(hub: &Arc<Hub>, mut reader: R, mut writer: W) -> bool
where
    R: Read,
    W: Write + Send + 'static,
{
    let connection = CONNECTIONS.fetch_add(1, Ordering::Relaxed);
    let cancels: Cancels = Arc::new(Mutex::new(HashMap::new()));
    let (out, outbox) = channel::<Outgoing>();

    let pump = std::thread::Builder::new()
        .name(format!("wred-writer-{connection}"))
        .spawn(move || {
            while let Ok(message) = outbox.recv() {
                match message {
                    Outgoing::Frame(frame) => {
                        if let Err(error) = write_frame(&mut writer, &frame) {
                            tracing::debug!("write failed, dropping connection: {error}");
                            return;
                        }
                    }
                    Outgoing::Stop => return,
                }
            }
        });

        // Do NOT panic here.
        //
        // `.expect()` on this spawn is what turned thread exhaustion into a
        // process-level failure: EAGAIN became a panic, the connection died, the
        // caller retried, another spawn was attempted, another panic. Thread ids
        // reached ~3,535,317 and the container could no longer fork at all.
        //
        // A server out of threads should refuse a connection, not take itself
        // down. The sibling crate already does exactly this —
        // `wre-sandbox/src/capture.rs` logs a warning on spawn failure instead
        // of unwrapping.
        //
        // Returning here drops `reader`/`writer`, closing the socket, so the
        // client sees a clean disconnect and can retry. The bound above means we
        // should never get here; this is the backstop for when we do.
        let pump = match pump {
            Ok(handle) => handle,
            Err(error) => {
                tracing::error!(
                    "could not spawn writer thread ({error}); refusing this connection. \
                     This means the process is at its thread ceiling."
                );
                return false;
            }
        };

    let mut shutdown = false;

    let mut idle_strikes: u32 = 0;

    loop {
        let frame = match read_frame(&mut reader) {
            Ok(Some(frame)) => {
                idle_strikes = 0;
                frame
            }
            Ok(None) => break,
            // A read timeout means QUIET, not broken. Only a sustained silence
            // past the client's own session ceiling is treated as abandonment —
            // which is what reclaims the two threads a leaked connection pins.
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                idle_strikes += 1;
                if idle_strikes >= MAX_IDLE_STRIKES {
                    tracing::warn!(
                        "connection {connection} idle for {}s with no frames; reclaiming it \
                         and its two threads",
                        IO_TIMEOUT.as_secs() * u64::from(MAX_IDLE_STRIKES)
                    );
                    break;
                }
                continue;
            }
            Err(error) => {
                tracing::debug!("read failed: {error}");
                break;
            }
        };

        let envelope = match frame.envelope() {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::warn!("frame rejected: {error}");
                continue;
            }
        };

        match hub.handle(connection, envelope, frame.bin, &out, &cancels) {
            Action::Continue => {}
            Action::Shutdown => {
                shutdown = true;
                break;
            }
        }
    }

    hub.close_connection(connection);
    let _ = out.send(Outgoing::Stop);
    let _ = pump.join();

    shutdown
}
