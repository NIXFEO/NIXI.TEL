//! Startup smoke test: the SBC binds a UDP listener on an ephemeral port
//! and runs its background tasks. Call-level behaviour is covered by the
//! in-crate transaction tests (`crates/sbc-core/src/sbc/*.rs`), which drive
//! the handlers over channels without sockets.

use sbc_core::config::{ListenerConfig, NetworkConfig, TransportType};
use sbc_core::Sbc;
use std::time::Duration;

#[tokio::test]
async fn sbc_starts_on_an_ephemeral_udp_port() {
    let mut sbc = Sbc::new();
    let config = NetworkConfig {
        listeners: vec![ListenerConfig {
            transport: TransportType::UDP,
            bind_address: "127.0.0.1".parse().unwrap(),
            bind_port: 0,
            cert_file: None,
            key_file: None,
        }],
        public_ipv4: None,
        public_ipv6: None,
    };

    sbc.start(&config, None).await.expect("SBC starts");
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(sbc.b2bua().stats().await.total_active, 0);
    assert_eq!(sbc.media().stats().allocated_ports, 0);
}
