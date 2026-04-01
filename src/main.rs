use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;

fn probe(target: Ipv4Addr, ttl: u32) -> std::io::Result<Option<Ipv4Addr>> {
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

    // Sned UDP packet to high port (33434)
    let dest = SockAddr::from(SocketAddrV4::new(target, 33434));
    send_sock.send_to(&[0u8; 32], &dest)?;

    // Listen for ICMP reply
    let mut buf = [MaybeUninit::<u8>::uninit(); 512];
    match recv_sock.recv(&mut buf) {
        Ok(n) => {
            // Safety:: recv wrote n bytes into buf
            let buf: &[u8] = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, n) };
            // IP Header is first 20 bytes, source IP is at bytes 12-16
            if buf.len() >= 20 {
                let ip = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
                Ok(Some(ip))
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None),
    }
}

fn main() -> std::io::Result<()> {
    // Manually set `github.com`'s IP for now.
    let target: Ipv4Addr = Ipv4Addr::new(20, 207, 73, 82);
    for ttl in 1..=30 {
        let hop = probe(target, ttl)?;
        match hop {
            Some(ip) => println!("{:>2} {}", ttl, ip),
            None => println!("{:>2} *", ttl),
        }
        if hop == Some(target) {
            break;
        }
    }
    Ok(())
}
