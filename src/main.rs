// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// Based on https://github.com/cloudflare/quiche/blob/0.4.0/examples/client.rs

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Instant;

use ring::rand::*;
use url::Url;

type Error = Box<dyn std::error::Error>;
type Scid = [u8; quiche::MAX_CONN_ID_LEN];

const MAX_DATAGRAM_SIZE: usize = 1350;
const HTTP_REQ_STREAM_ID: u64 = 4;

fn main() -> Result<(), Error> {
    let url = Url::parse("https://quic.tech:4433/")?;

    let peer_addr = url
        .socket_addrs(|| None)?
        .into_iter()
        .next()
        .ok_or("Failed to resolve remote address")?;
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(peer_addr)?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(b"\x05hq-27\x08http/0.9")?;
    config.set_max_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let scid = new_scid()?;
    let mut conn = quiche::connect(url.domain(), &scid, &mut config)?;

    println!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr()?,
        HexDump(&scid),
    );

    let mut out = [0; MAX_DATAGRAM_SIZE];
    let write = conn.send(&mut out)?;
    socket.send(&out[..write])?;

    println!("written {}", write);

    let req_start = Instant::now();
    let mut req_sent = false;

    let (tx, rx) = mpsc::sync_channel(0);
    thread::spawn({
        let socket = socket.try_clone()?;
        move || recv_loop(&socket, tx)
    });

    loop {
        let res = match conn.timeout() {
            Some(timeout) => rx.recv_timeout(timeout),
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };

        match res {
            Ok(mut buf) => {
                let read = match conn.recv(&mut buf[..]) {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("recv failed: {}", e);
                        continue;
                    }
                };
                println!("processed bytes: {}", read);
            }
            Err(RecvTimeoutError::Timeout) => {
                println!("timed out");
                conn.on_timeout();
            }
            Err(e) => {
                panic!(e);
            }
        };
        println!("done reading");

        if conn.is_closed() {
            println!("connection closed, {:?}", conn.stats());
            break;
        }

        if conn.is_established() && !req_sent {
            println!("sending HTTP request for {}", url.path());

            let req = format!("GET {}\r\n", url.path());
            conn.stream_send(HTTP_REQ_STREAM_ID, req.as_bytes(), true)?;

            req_sent = true;
        }

        let mut buf = [0; 65536];
        for s in conn.readable() {
            while let Ok((read, fin)) = conn.stream_recv(s, &mut buf) {
                println!("received {} bytes", read);

                let stream_buf = &buf[..read];

                println!("stream {} has {} bytes (fin? {})", s, stream_buf.len(), fin);

                print!("Content: {}", unsafe {
                    std::str::from_utf8_unchecked(&stream_buf)
                });

                // The server reported that it has no more data to send, which
                // we got the full response. Close the connection.
                if s == HTTP_REQ_STREAM_ID && fin {
                    println!("response received in {:?}, closing...", req_start.elapsed());

                    conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            }
        }
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let write = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    println!("done writing");
                    break;
                }

                Err(e) => {
                    eprintln!("send failed: {:?}", e);

                    conn.close(false, 0x1, b"fail").ok();
                    break;
                }
            };

            if let Err(e) = socket.send(&out[..write]) {
                panic!("send() failed: {:?}", e);
            }

            println!("written {}", write);
        }

        if conn.is_closed() {
            println!("connection closed, {:?}", conn.stats());
            break;
        }
    }

    Ok(())
}

fn recv_loop(socket: &UdpSocket, tx: SyncSender<Vec<u8>>) {
    loop {
        let mut buf = vec![0; 65536];
        let len = socket.recv(&mut buf).unwrap();
        buf.truncate(len);
        if let Err(_) = tx.send(buf) {
            println!("channel closed");
            break;
        }
    }
}

fn new_scid() -> Result<Scid, Error> {
    let mut scid = Scid::default();
    SystemRandom::new()
        .fill(&mut scid[..])
        .map_err(|_| "crypto error")?;
    Ok(scid)
}

struct HexDump<'a>(&'a [u8]);

impl fmt::Display for HexDump<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}
