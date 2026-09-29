//! In-memory device pair for tests: whatever one side writes to its device
//! appears in the other side's inbox.

use super::DeviceHandle;
use tokio::sync::mpsc;

pub fn mock_pair() -> (DeviceHandle, DeviceHandle) {
    let (a_to_b_tx, b_inbox) = mpsc::channel(256);
    let (b_to_a_tx, a_inbox) = mpsc::channel(256);
    let a = DeviceHandle {
        inbox: a_inbox,
        outbox: a_to_b_tx,
        name: "mock-a".into(),
        stop: None,
        cleanup: None,
    };
    let b = DeviceHandle {
        inbox: b_inbox,
        outbox: b_to_a_tx,
        name: "mock-b".into(),
        stop: None,
        cleanup: None,
    };
    (a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn packets_cross_sides() {
        let (mut a, mut b) = mock_pair();
        a.outbox.send(vec![1, 2, 3]).await.unwrap();
        let got = b.inbox.recv().await.unwrap();
        assert_eq!(got, vec![1, 2, 3]);
        b.outbox.send(vec![4]).await.unwrap();
        assert_eq!(a.inbox.recv().await.unwrap(), vec![4]);
    }
}
