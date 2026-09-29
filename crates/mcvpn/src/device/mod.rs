//! IP device abstraction: a pair of channels plus a background thread
//! shuttling packets to/from the OS device (TUN / wintun / Android fd).

use tokio::sync::mpsc;

pub struct DeviceHandle {
    /// Packets read from the device (ready to be sent into the tunnel).
    pub inbox: mpsc::Receiver<Vec<u8>>,
    /// Packets from the tunnel, to be written into the device.
    pub outbox: mpsc::Sender<Vec<u8>>,
    pub name: String,
    pub(crate) stop: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    /// Platform cleanup (e.g. Windows route removal) run when the handle drops.
    pub(crate) cleanup: Option<Box<dyn FnOnce() + Send>>,
}

pub mod fd;
pub mod mock;

#[cfg(target_os = "linux")]
pub mod tun;

#[cfg(target_os = "windows")]
pub mod wintun;

impl DeviceHandle {
    pub async fn write_packet(&self, pkt: &[u8]) -> crate::error::VpnResult<()> {
        self.outbox
            .send(pkt.to_vec())
            .await
            .map_err(|_| crate::error::VpnError::Device("device closed".into()))
    }

    /// Stop background device threads promptly.
    pub fn stop_device(&self) {
        if let Some(s) = &self.stop {
            s.store(true, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

impl Drop for DeviceHandle {
    fn drop(&mut self) {
        self.stop_device();
        if let Some(c) = self.cleanup.take() {
            c();
        }
    }
}

