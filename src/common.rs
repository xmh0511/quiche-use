use std::net::{SocketAddr, ToSocketAddrs};

// QUIC 协议常量
pub const PROTO_VERSION: u32 = quiche::PROTOCOL_VERSION;
pub const MAX_DATAGRAM_SIZE: usize = 1350;
pub const MAX_DATA: u64 = 10_000_000; // 10 MB
pub const MAX_STREAM_DATA: u64 = 1_000_000; // 1 MB
pub const MAX_STREAMS_BIDI: u64 = 100;

// 解析地址字符串到套接字地址
pub fn resolve_address(address: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let addr = address
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| "Failed to resolve address".to_string())?;
    Ok(addr)
}

// 创建 QUIC 连接的配置
pub fn configure_quiche() -> Result<quiche::Config, Box<dyn std::error::Error>> {
    let mut config = quiche::Config::new(PROTO_VERSION)?;

    config.load_cert_chain_from_pem_file("cert.pem")?;
    config.load_priv_key_from_pem_file("key.pem")?;
    
    // 设置 QUIC 连接的参数
    config.set_application_protos(&[b"\x05hello"])?;
    config.set_max_idle_timeout(5000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(MAX_STREAM_DATA);
    config.set_initial_max_stream_data_bidi_remote(MAX_STREAM_DATA);
    config.set_initial_max_streams_bidi(MAX_STREAMS_BIDI);
    config.set_disable_active_migration(true);
    
    // 使用 CUBIC 拥塞控制算法
    config.set_cc_algorithm(quiche::CongestionControlAlgorithm::CUBIC);
    
    Ok(config)
}