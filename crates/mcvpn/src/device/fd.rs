//! Raw fd device (Android VpnService ParcelFileDescriptor, or tests).
//! Two OS threads shuttle packets; the reader polls so shutdown is prompt.

use super::DeviceHandle;
use std::os::fd::{FromRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

pub fn from_raw_fd(name: &str, fd: RawFd) -> DeviceHandle {
    let (inbox_tx, inbox_rx) = mpsc::channel::<Vec<u8>>(512);
    let (outbox_tx, mut outbox_rx) = mpsc::channel::<Vec<u8>>(512);

    let read_fd = unsafe { libc::dup(fd) };
    let write_fd = unsafe { libc::dup(fd) };
    unsafe { libc::close(fd) };
    // Reader polls with O_NONBLOCK so the stop flag is honored promptly.
    unsafe {
        let flags = libc::fcntl(read_fd, libc::F_GETFL);
        libc::fcntl(read_fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stop);
    let stop_writer = Arc::clone(&stop);

    std::thread::Builder::new()
        .name(format!("{name}-rd"))
        .spawn(move || {
            let mut read_file = unsafe { std::fs::File::from_raw_fd(read_fd) };
            use std::io::Read;
            let mut buf = vec![0u8; 65536];
            let mut pollfd = libc::pollfd {
                fd: read_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                if stop_reader.load(Ordering::Relaxed) {
                    break;
                }
                let r = unsafe { libc::poll(&mut pollfd, 1, 200) };
                if r < 0 {
                    break;
                }
                if r == 0 {
                    continue;
                }
                loop {
                    match read_file.read(&mut buf) {
                        Ok(0) => {
                            stop_reader.store(true, Ordering::Relaxed);
                            break;
                        }
                        Ok(n) => {
                            if inbox_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                stop_reader.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => {
                            stop_reader.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }
                if stop_reader.load(Ordering::Relaxed) {
                    break;
                }
            }
        })
        .expect("spawn device reader");

    std::thread::Builder::new()
        .name(format!("{name}-wr"))
        .spawn(move || {
            let mut write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            use std::io::Write;
            while let Some(pkt) = outbox_rx.blocking_recv() {
                if stop_writer.load(Ordering::Relaxed) {
                    break;
                }
                if write_file.write_all(&pkt).is_err() {
                    break;
                }
            }
        })
        .expect("spawn device writer");

    let mut handle = DeviceHandle {
        inbox: inbox_rx,
        outbox: outbox_tx,
        name: name.to_string(),
        stop: None,
        cleanup: None,
    };
    handle.stop = Some(stop);
    handle
}
