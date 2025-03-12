use std::io;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use quiche::{ConnectionId, RecvInfo};
use ring::rand::*;

mod common;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志

    // 客户端设置
    let server_addr = common::resolve_address("127.0.0.1:4433")?;
    let client_addr = common::resolve_address("0.0.0.0:0")?;
    let message = "你好，这是 QUIC 客户端!";

    // 创建 UDP 套接字
    let socket = UdpSocket::bind(client_addr)?;
    //socket.set_nonblocking(true)?;
    let local_addr = socket.local_addr().unwrap();

    println!("客户端从 {} 启动", socket.local_addr()?);

    // 创建 QUIC 配置
    let mut config = common::configure_quiche()?;
    config.load_verify_locations_from_file("rootCA.pem")?;

    // 生成随机源连接 ID
    let rng = SystemRandom::new();
    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
    rng.fill(&mut scid).unwrap();
    let connect_id = ConnectionId::from_ref(&scid);

    // 创建 QUIC 连接
    let mut conn = quiche::connect(None, &connect_id, local_addr, server_addr, &mut config)?;

    println!("连接到 {}", server_addr);

    let start = Instant::now();
    let mut buf = [0; 65535];
    let mut out = [0; common::MAX_DATAGRAM_SIZE];
    let mut stream_id = 0;
    let mut sent = false;

    loop {
        // 发送传出数据包
        loop {
            match conn.send(&mut out) {
                Ok((len, _)) => {
                    if let Err(e) = socket.send_to(&out[..len], server_addr) {
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
                    return Err(Box::new(e));
                }
            }
        }

        // 如果连接已建立，发送数据
        if conn.is_established() && !sent {
            println!("连接已建立!");

            // 向服务器发送消息
            match conn.stream_send(stream_id, message.as_bytes(), true) {
                Ok(_) => {
                    println!("发送消息: {}", message);
                    sent = true;
                }
                Err(e) => {
                    eprintln!("发送数据失败: {:?}", e);
                    return Err(Box::new(e));
                }
            }

            stream_id += 4;
        }

        // 尝试接收数据
        match socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                println!("从 {} 接收到 {} 字节", from, len);

                let recv_info = RecvInfo {
                    from,
                    to: local_addr,
                };
                // 处理数据包
                match conn.recv(&mut buf[..len], recv_info) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => {}
                    Err(e) => {
                        eprintln!("QUIC 接收错误: {:?}", e);
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
                                        println!("收到响应: {}", str_data);
                                    }
                                    Err(_) => {
                                        println!("收到非 UTF-8 数据: {:?}", received_data);
                                    }
                                }
                            }
                        }
                        Err(quiche::Error::Done) => {}
                        Err(e) => {
                            eprintln!("流读取失败: {:?}", e);
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                // 没有数据可用，处理超时
                if let Some(timeout) = conn.timeout() {
                    if Instant::now() >= start + timeout {
                        conn.on_timeout();
                    }
                }

                // 短暂睡眠，避免 CPU 空转
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(e) => {
                eprintln!("接收错误: {:?}", e);
                return Err(Box::new(e));
            }
        }

        // 如果连接已关闭，退出
        if conn.is_closed() {
            println!("连接已关闭");
            break;
        }
    }

    Ok(())
}
