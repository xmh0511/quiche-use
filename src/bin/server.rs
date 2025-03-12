use std::collections::HashMap;
use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use quiche::{ConnectionId, RecvInfo};
use ring::rand::*;

mod common {
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 服务器设置
    let addr = "127.0.0.1:4433";

    // 创建 UDP 套接字
    let socket = UdpSocket::bind(addr)?;
    let local_addr = socket.local_addr().unwrap();
    //socket.set_nonblocking(true)?;

    // 创建 QUIC 配置
    let mut config = common::configure_quiche()?;

    // 配置为服务器
    config.verify_peer(false);

    // 生成随机源连接 ID
    let rng = SystemRandom::new();
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();

    // 创建连接映射
    let mut connections: HashMap<Vec<u8>, quiche::Connection> = HashMap::new();

    // 创建接收数据报的缓冲区
    let mut buf = [0; 65535];
    let mut out = [0; common::MAX_DATAGRAM_SIZE];

    // 简单的轮询循环
    loop {
        // 尝试接收数据
        match socket.recv_from(&mut buf) {
            Ok((len, src)) => {
                println!("从 {} 接收到 {} 字节", src, len);

                // 尝试找到现有连接
                let hdr = match quiche::Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN)
                {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("无效的 QUIC 头: {:?}", e);
                        continue;
                    }
                };

                let conn_id = hdr.dcid.to_vec();

                // 如果我们有现有连接，则处理数据
                if let Some(conn) = connections.get_mut(&conn_id) {
                    let recv_info = RecvInfo {
                        from: src,
                        to: local_addr,
                    };
                    match conn.recv(&mut buf[..len], recv_info) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            eprintln!("连接错误: {:?}", e);
                            continue;
                        }
                    }

                    // 处理任何可读的流
                    for stream_id in conn.readable() {
                        let mut data = vec![0; 1024];

                        match conn.stream_recv(stream_id, &mut data) {
                            Ok((len, _)) => {
                                if len > 0 {
                                    let received_data = &data[..len];
                                    match std::str::from_utf8(received_data) {
                                        Ok(str_data) => {
                                            println!("从客户端接收到: {}", str_data);
                                        }
                                        Err(_) => {
                                            println!("接收到非 UTF-8 数据: {:?}", received_data);
                                        }
                                    }

                                    let mut echo_data = Vec::new();
                                    echo_data.extend_from_slice("服务端收到消息：".as_bytes());
                                    echo_data.extend_from_slice(received_data);
                                    // 回显数据
                                    if let Err(e) = conn.stream_send(stream_id, &echo_data, true) {
                                        eprintln!("发送响应失败: {:?}", e);
                                    }
                                }
                            }
                            Err(quiche::Error::Done) => {}
                            Err(e) => {
                                eprintln!("流读取失败: {:?}", e);
                            }
                        }
                    }
                } else if hdr.ty == quiche::Type::Initial {
                    // 新连接
                    println!("来自 {} 的新连接", src);

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    rng.fill(&mut scid).unwrap();
                    let scid = ConnectionId::from_ref(&scid);

                    let mut conn = match quiche::accept(&scid, None, local_addr, src, &mut config) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("创建连接失败: {:?}", e);
                            continue;
                        }
                    };

                    let recv_info = RecvInfo {
                        from: src,
                        to: local_addr,
                    };
                    // 处理初始数据包
                    match conn.recv(&mut buf[..len], recv_info) {
                        Ok(_) => {}
                        Err(e) => {
                            eprintln!("处理初始数据包失败: {:?}", e);
                            continue;
                        }
                    }

                    connections.insert(scid.to_vec(), conn);
                }

                // 为所有连接发送任何传出数据包
                for (_, conn) in connections.iter_mut() {
                    loop {
                        match conn.send(&mut out) {
                            Ok((len, send_info)) => {
                                let out_slice = &out[..len];
                                if let Err(e) = socket.send_to(out_slice, send_info.to) {
                                    if e.kind() != io::ErrorKind::WouldBlock {
                                        eprintln!("发送错误: {:?}", e);
                                    }
                                }
                            }
                            Err(quiche::Error::Done) => {
                                break;
                            }
                            Err(e) => {
                                eprintln!("连接发送失败: {:?}", e);
                            }
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // 没有数据可用，处理超时和清理操作

                // 处理所有连接的超时
                let now = Instant::now();
                for (_, conn) in connections.iter_mut() {
                    if let Some(timeout) = conn.timeout() {
                        if timeout.as_millis() == 0 {
                            conn.on_timeout();
                        }
                    }

                    // 发送任何传出数据包
                    loop {
                        match conn.send(&mut out) {
                            Ok((len, send_info)) => {
                                if let Err(e) = socket.send_to(&out[..len], send_info.to) {
                                    if e.kind() != io::ErrorKind::WouldBlock {
                                        eprintln!("发送错误: {:?}", e);
                                    }
                                }
                            }
                            Err(quiche::Error::Done) => {
                                break;
                            }
                            Err(e) => {
                                eprintln!("连接发送失败: {:?}", e);
                            }
                        }
                    }
                }

                // 清理已关闭的连接
                connections.retain(|_, conn| !conn.is_closed());

                // 短暂睡眠，避免 CPU 空转
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("接收错误: {:?}", e);
                return Err(Box::new(e));
            }
        }
    }
}
