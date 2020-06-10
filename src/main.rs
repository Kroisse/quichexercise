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

// Based on https://github.com/cloudflare/quiche/blob/0.4.0/examples/http3-client.rs

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::Instant;

use anyhow::{anyhow, Context, Error};
use ring::rand::*;
use url::Url;

type Scid = [u8; quiche::MAX_CONN_ID_LEN];

const MAX_DATAGRAM_SIZE: usize = 1350;
const HTTP_REQ_STREAM_ID: u64 = 4;

fn main() -> Result<(), Error> {
    let url = Url::parse("https://quic.tech:8443/")?;

    let peer_addr = url
        .socket_addrs(|| None)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("Failed to resolve remote address"))?;
    let bind_addr = match peer_addr {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(peer_addr)?;

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)?;
    config.verify_peer(false);
    config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;
    config.set_max_idle_timeout(5000);
    config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);

    let mut http3_conn = None;

    let scid = new_scid()?;
    let mut conn = quiche::connect(url.domain(), &scid, &mut config)?;

    println!(
        "connecting to {:} from {:} with scid {}",
        peer_addr,
        socket.local_addr()?,
        HexDump(&scid),
    );

    let mut out = [0; MAX_DATAGRAM_SIZE];
    let write = conn.send(&mut out).context("initial send failed")?;
    socket.send(&out[..write]).context("initial send failed")?;

    println!("written {}", write);

    let h3_config = quiche::h3::Config::new()?;
    let req = prepare_request(&url);
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

        // Create a new HTTP/3 connection once the QUIC connection is established.
        if conn.is_established() && http3_conn.is_none() {
            http3_conn = Some(quiche::h3::Connection::with_transport(
                &mut conn, &h3_config,
            )?);
        }

        if let (Some(h3_conn), false) = (&mut http3_conn, req_sent) {
            println!("sending HTTP request for {}", url.path());
            h3_conn.send_request(&mut conn, &req, true)?;
            req_sent = true;
        }

        if let Some(http3_conn) = &mut http3_conn {
            let mut buf = [0; 65536];

            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        println!("got response headers {:?} on stream id {}", list, stream_id);
                    }

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        if let Ok(read) = http3_conn.recv_body(&mut conn, stream_id, &mut buf) {
                            println!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );

                            print!("{}", unsafe { std::str::from_utf8_unchecked(&buf[..read]) });
                        }
                    }

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        println!("response received in {:?}, closing...", req_start.elapsed());

                        conn.close(true, 0x00, b"kthxbye").unwrap();
                    }

                    Err(quiche::h3::Error::Done) => {
                        break;
                    }

                    Err(e) => {
                        eprintln!("HTTP/3 processing failed: {:?}", e);

                        break;
                    }
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

fn prepare_request(url: &Url) -> Vec<quiche::h3::Header> {
    use quiche::h3::Header;
    use url::Position;

    vec![
        Header::new(":method", "GET"),
        Header::new(":scheme", url.scheme()),
        Header::new(
            ":authority",
            &url[Position::BeforeUsername..Position::AfterPort],
        ),
        Header::new(":path", &url[Position::BeforePath..Position::AfterQuery]),
        Header::new("user-agent", "quiche"),
    ]
}

fn recv_loop(socket: &UdpSocket, tx: SyncSender<Vec<u8>>) {
    loop {
        let mut buf = vec![0; 65536];
        let len = match socket.recv(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("recv failed: {}", e);
                return;
            }
        };
        buf.truncate(len);
        if let Err(_) = tx.send(buf) {
            println!("channel closed");
            return;
        }
    }
}

fn new_scid() -> Result<Scid, Error> {
    let mut scid = Scid::default();
    SystemRandom::new()
        .fill(&mut scid[..])
        .map_err(|_| anyhow!("crypto error"))?;
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
