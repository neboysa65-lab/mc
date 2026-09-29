//! In-app diagnostics log: a ring buffer of the most recent log lines (and
//! optionally a log file), installed as the global `tracing` subscriber.
//!
//! GUI and mobile clients have no console, so "it doesn't connect" used to
//! be undiagnosable. With this, every connection stage and every failed
//! OS command is recorded and can be copied into a bug report.

use std::collections::VecDeque;
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use tracing_subscriber::fmt::MakeWriter;

const DEFAULT_CAP: usize = 400;

struct Inner {
    lines: Mutex<VecDeque<String>>,
    cap: usize,
    file: Mutex<Option<std::fs::File>>,
    partial: Mutex<Vec<u8>>,
}

impl Inner {
    fn new(cap: usize) -> Self {
        Inner {
            lines: Mutex::new(VecDeque::with_capacity(cap)),
            cap,
            file: Mutex::new(None),
            partial: Mutex::new(Vec::new()),
        }
    }
}

static GLOBAL: OnceLock<Arc<Inner>> = OnceLock::new();

#[derive(Clone)]
struct RingMake(Arc<Inner>);

struct RingWriter(Arc<Inner>);

impl Write for RingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(f) = self.0.file.lock().unwrap().as_mut() {
            let _ = f.write_all(buf);
        }
        let mut partial = self.0.partial.lock().unwrap();
        partial.extend_from_slice(buf);
        while let Some(pos) = partial.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = partial.drain(..=pos).collect();
            let text = String::from_utf8_lossy(&line).trim_end().to_string();
            let mut lines = self.0.lines.lock().unwrap();
            if lines.len() >= self.0.cap {
                lines.pop_front();
            }
            lines.push_back(text);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(f) = self.0.file.lock().unwrap().as_mut() {
            let _ = f.flush();
        }
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for RingMake {
    type Writer = RingWriter;
    fn make_writer(&'a self) -> Self::Writer {
        RingWriter(Arc::clone(&self.0))
    }
}

/// Install the ring-buffer logger as the global tracing subscriber. Safe to
/// call more than once (later calls only update the log file).
pub fn init(log_file: Option<PathBuf>) {
    let inner = GLOBAL.get_or_init(|| Arc::new(Inner::new(DEFAULT_CAP)));
    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Start each run with a fresh file so a bug report is one session.
        if let Ok(f) = std::fs::File::create(&path) {
            *inner.file.lock().unwrap() = Some(f);
        }
    }
    let _ = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcvpn=info".into()),
        )
        .with_writer(RingMake(Arc::clone(inner)))
        .try_init();
}

/// The recent log, oldest first, one line per event.
pub fn snapshot() -> String {
    match GLOBAL.get() {
        Some(inner) => inner
            .lines
            .lock()
            .unwrap()
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ring_keeps_only_the_latest_lines() {
        let inner = Arc::new(Inner::new(3));
        let mut w = RingWriter(Arc::clone(&inner));
        for i in 0..5 {
            w.write_all(format!("line {i}\n").as_bytes()).unwrap();
        }
        // A line split across two writes is reassembled.
        w.write_all(b"half ").unwrap();
        w.write_all(b"line\n").unwrap();
        let lines: Vec<String> = inner.lines.lock().unwrap().iter().cloned().collect();
        assert_eq!(lines, vec!["line 3", "line 4", "half line"]);
    }
}
