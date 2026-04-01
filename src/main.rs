use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use std::time::Instant;

enum ProbeResult {
    Hop(Ipv4Addr, Duration),     // Type 11 - Time Exceeded
    Reached(Ipv4Addr, Duration), // Type 3 - Destination Unreachable
    Timeout,                     // No reply
}

fn probe(target: Ipv4Addr, ttl: u32) -> std::io::Result<ProbeResult> {
    // UDP socket to send the probe
    let send_sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    send_sock.set_ttl_v4(ttl)?;

    // Raw ICMP socket to catch Time Exceeded replies
    let recv_sock = Socket::new(
        Domain::IPV4,
        Type::from(libc::SOCK_RAW),
        Some(Protocol::ICMPV4),
    )?;
    recv_sock.set_read_timeout(Some(Duration::from_secs(2)))?;

    // Send UDP packet to high port (33434)
    let dest = SockAddr::from(SocketAddrV4::new(target, 33434));
    let start = Instant::now();
    send_sock.send_to(&[0u8; 32], &dest)?;

    // Listen for ICMP reply
    let mut buf = [MaybeUninit::<u8>::uninit(); 512];
    match recv_sock.recv(&mut buf) {
        Ok(n) => {
            // Safety:: recv wrote n bytes into buf
            let buf: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
            // IP Header is first 20 bytes, source IP is at bytes 12-16
            if buf.len() >= 21 {
                let ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                let elapsed = start.elapsed();
                match buf[20] {
                    11 => Ok(ProbeResult::Hop(ip, elapsed)),
                    3 if ip == target => Ok(ProbeResult::Reached(ip, elapsed)),
                    3 => Ok(ProbeResult::Hop(ip, elapsed)),
                    _ => Ok(ProbeResult::Timeout),
                }
            } else {
                Ok(ProbeResult::Timeout)
            }
        }
        Err(_) => Ok(ProbeResult::Timeout),
    }
}

fn main() -> std::io::Result<()> {
    // Manually set `8.8.8.8` (Google DNS) for now.
    let target: Ipv4Addr = Ipv4Addr::new(8, 8, 8, 8);
    for ttl in 1..=15 {
        let mut reached = false;
        let mut last_ip: Option<Ipv4Addr> = None;
        print!("{:>2} ", ttl);
        for _ in 0..3 {
            match probe(target, ttl)? {
                ProbeResult::Hop(ip, rtt) => {
                    if last_ip != Some(ip) {
                        print!("{} ", ip);
                        last_ip = Some(ip)
                    }
                    print!("{:.3}ms ", rtt.as_secs_f64() * 1000.0)
                }
                ProbeResult::Reached(ip, rtt) => {
                    if last_ip != Some(ip) {
                        print!("{} ", ip);
                        last_ip = Some(ip);
                    }
                    print!("{:.3}ms ", rtt.as_secs_f64() * 1000.0);
                    reached = true;
                }
                ProbeResult::Timeout => print!("* "),
            }
        }
        println!();
        if reached {
            break;
        }
    }
    Ok(())
}
