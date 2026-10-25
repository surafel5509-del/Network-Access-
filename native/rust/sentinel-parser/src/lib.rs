//! SentinelNet native packet parser (ADR-0003).
//!
//! Metadata-only dissection for VpnService capture. Packet payload bytes are
//! never copied into a returned structure, which is both a privacy requirement
//! and the streaming design that keeps memory below the 300 MB baseline.
//!
//! The Kotlin implementation in `:core:pure` implements the same grammar and is
//! used as the reference oracle by the conformance suite.

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const LINKTYPE_RAW: u32 = 101;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppKind {
    Unknown,
    Tcp,
    Udp,
    Icmp,
    Http,
    Tls,
    Dns,
    Ssdp,
    MDns,
    Dhcp,
    Ntp,
    Quic,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub protocol: u8,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub tcp_flags: u8,
    pub length: usize,
    pub application: AppKind,
}

/// Parses a raw IPv4 packet. Returns `None` for truncated or malformed input
/// rather than panicking — capture data is untrusted input.
pub fn parse_ipv4(packet: &[u8]) -> Option<ParsedPacket> {
    if packet.len() < 20 {
        return None;
    }
    if packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if ihl < 20 || packet.len() < ihl {
        return None;
    }
    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    let end = if total_length >= ihl && total_length <= packet.len() {
        total_length
    } else {
        packet.len()
    };
    let protocol = packet[9];
    let src_ip = [packet[12], packet[13], packet[14], packet[15]];
    let dst_ip = [packet[16], packet[17], packet[18], packet[19]];

    let mut parsed = ParsedPacket {
        src_ip,
        dst_ip,
        protocol,
        src_port: None,
        dst_port: None,
        tcp_flags: 0,
        length: packet.len(),
        application: AppKind::Unknown,
    };

    match protocol {
        PROTO_TCP => {
            if ihl + 20 > end {
                return Some(parsed);
            }
            let (sport, dport) = (
                read_u16(packet, ihl)?,
                read_u16(packet, ihl + 2)?,
            );
            let data_offset = ((packet[ihl + 12] >> 4) as usize) * 4;
            parsed.tcp_flags = packet[ihl + 13];
            parsed.src_port = Some(sport);
            parsed.dst_port = Some(dport);
            let payload_start = (ihl + data_offset.max(20)).min(end);
            parsed.application = classify_tcp(packet, payload_start, end, sport, dport);
        }
        PROTO_UDP => {
            if ihl + 8 > end {
                return Some(parsed);
            }
            let (sport, dport) = (
                read_u16(packet, ihl)?,
                read_u16(packet, ihl + 2)?,
            );
            parsed.src_port = Some(sport);
            parsed.dst_port = Some(dport);
            parsed.application = classify_udp(sport, dport);
        }
        PROTO_ICMP => parsed.application = AppKind::Icmp,
        _ => {}
    }
    Some(parsed)
}

fn read_u16(packet: &[u8], offset: usize) -> Option<u16> {
    if offset + 1 >= packet.len() {
        return None;
    }
    Some(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

fn classify_tcp(
    packet: &[u8],
    start: usize,
    end: usize,
    sport: u16,
    dport: u16,
) -> AppKind {
    if start >= end {
        return AppKind::Tcp;
    }
    if packet[start] == 0x16 && start + 1 < end && packet[start + 1] == 3 {
        return AppKind::Tls;
    }
    let prefix_len = (end - start).min(12);
    let prefix = &packet[start..start + prefix_len];
    if prefix.starts_with(b"GET ")
        || prefix.starts_with(b"POST ")
        || prefix.starts_with(b"HEAD ")
        || prefix.starts_with(b"PUT ")
        || prefix.starts_with(b"HTTP/")
    {
        return AppKind::Http;
    }
    match (sport, dport) {
        (443, _) | (_, 443) | (8443, _) | (_, 8443) => AppKind::Tls,
        (53, _) | (_, 53) => AppKind::Dns,
        _ => AppKind::Tcp,
    }
}

fn classify_udp(sport: u16, dport: u16) -> AppKind {
    match (sport, dport) {
        (53, _) | (_, 53) => AppKind::Dns,
        (1900, _) | (_, 1900) => AppKind::Ssdp,
        (5353, _) | (_, 5353) => AppKind::MDns,
        (67, _) | (_, 67) | (68, _) | (_, 68) => AppKind::Dhcp,
        (123, _) | (_, 123) => AppKind::Ntp,
        (443, _) | (_, 443) => AppKind::Quic,
        _ => AppKind::Udp,
    }
}

/// Reads a possibly-compressed DNS name. Returns `(name, offset_after_name)`.
/// Pointer loops are bounded to 16 jumps (RFC 1035 compression can be malicious).
pub fn read_dns_name(packet: &[u8], start: usize, end: usize) -> Option<(String, usize)> {
    // Callers may hand us an `end` derived from an untrusted IP length field.
    // Clamp it so no path can index past the slice.
    let end = end.min(packet.len());
    let mut pos = start;
    let mut labels: Vec<String> = Vec::new();
    let mut jumps = 0usize;
    let mut next_pos: Option<usize> = None;
    while pos < end && jumps <= 16 {
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= end {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | (packet[pos + 1] as usize);
            if pointer >= end {
                return None;
            }
            if next_pos.is_none() {
                next_pos = Some(pos + 2);
            }
            pos = pointer;
            jumps += 1;
        } else if len > 63 {
            return None;
        } else {
            if pos + 1 + len > end {
                return None;
            }
            labels.push(String::from_utf8_lossy(&packet[pos + 1..pos + 1 + len]).into_owned());
            pos += 1 + len;
        }
    }
    if labels.is_empty() || jumps > 16 {
        return None;
    }
    Some((labels.join("."), next_pos.unwrap_or(pos)))
}

/// DNS question names from a DNS message starting at `start`.
pub fn dns_queries(packet: &[u8], start: usize, end: usize) -> Vec<String> {
    let end = end.min(packet.len());
    if start + 12 > end {
        return Vec::new();
    }
    let count = u16::from_be_bytes([packet[start + 4], packet[start + 5]]) as usize;
    if count == 0 || count > 64 {
        return Vec::new();
    }
    let mut pos = start + 12;
    let mut out = Vec::new();
    for _ in 0..count {
        match read_dns_name(packet, pos, end) {
            Some((name, after)) => {
                out.push(name);
                pos = after + 4; // QTYPE + QCLASS
                if pos > end {
                    break;
                }
            }
            None => break,
        }
    }
    out
}

fn le32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// Classic libpcap global header (little-endian), Wireshark-compatible.
pub fn pcap_global_header(link_type: u32, snap_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    le32(&mut out, 0xA1B2_C3D4);
    le32(&mut out, 0x0004_0002); // version 2.4
    le32(&mut out, 0); // thiszone
    le32(&mut out, 0); // sigfigs
    le32(&mut out, snap_len);
    le32(&mut out, link_type);
    out
}

pub fn pcap_packet_record(timestamp_ms: u64, captured_len: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(16);
    le32(&mut out, (timestamp_ms / 1000) as u32);
    le32(&mut out, ((timestamp_ms % 1000) * 1000) as u32);
    le32(&mut out, captured_len);
    le32(&mut out, captured_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2] = (total >> 8) as u8;
        p[3] = total as u8;
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&[192, 168, 1, 10]);
        p[16..20].copy_from_slice(&[192, 168, 1, 1]);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut q = vec![0u8; 12];
        q[0] = 0x12;
        q[1] = 0x34;
        q[2] = 0x01;
        q[5] = 0x01; // QDCOUNT
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    #[test]
    fn parses_udp_fields() {
        let p = udp_packet(43210, 1900, b"hello");
        let parsed = parse_ipv4(&p).expect("valid packet");
        assert_eq!(parsed.src_ip, [192, 168, 1, 10]);
        assert_eq!(parsed.dst_ip, [192, 168, 1, 1]);
        assert_eq!(parsed.protocol, PROTO_UDP);
        assert_eq!(parsed.src_port, Some(43210));
        assert_eq!(parsed.dst_port, Some(1900));
        assert_eq!(parsed.application, AppKind::Ssdp);
    }

    #[test]
    fn classifies_tls_client_hello() {
        let hello = [0x16u8, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5];
        let mut p = vec![0u8; 40 + hello.len()];
        p[0] = 0x45;
        p[3] = p.len() as u8;
        p[9] = PROTO_TCP;
        p[20..22].copy_from_slice(&51000u16.to_be_bytes());
        p[22..24].copy_from_slice(&443u16.to_be_bytes());
        p[32] = 0x50;
        p[33] = 0x02;
        p[40..].copy_from_slice(&hello);
        let parsed = parse_ipv4(&p).unwrap();
        assert_eq!(parsed.application, AppKind::Tls);
        assert_eq!(parsed.tcp_flags, 0x02);
    }

    #[test]
    fn dns_names_and_compression() {
        let q = dns_query("api.example.com");
        let p = udp_packet(53000, 53, &q);
        let queries = dns_queries(&p, 28, p.len());
        assert_eq!(queries, ["api.example.com"]);

        let mut compressed = q.clone();
        compressed.push(0xC0);
        compressed.push(12);
        let (name, after) = read_dns_name(&compressed, compressed.len() - 2, compressed.len()).unwrap();
        assert_eq!(name, "api.example.com");
        assert_eq!(after, compressed.len());
    }

    #[test]
    fn truncated_and_malformed_packets_are_safe() {
        assert!(parse_ipv4(&[]).is_none());
        assert!(parse_ipv4(&[0x45, 0x00]).is_none());
        let mut bad = udp_packet(1, 2, b"");
        bad[0] = 0x65; // IPv6 in an IPv4 parser
        assert!(parse_ipv4(&bad).is_none());
    }

    #[test]
    fn pcap_header_is_wireshark_compatible() {
        let h = pcap_global_header(LINKTYPE_RAW, 65535);
        assert_eq!(h.len(), 24);
        assert_eq!(&h[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert_eq!(&h[20..24], &101u32.to_le_bytes());
        let r = pcap_packet_record(1_700_000_000_123, 42);
        assert_eq!(r.len(), 16);
        assert_eq!(&r[8..12], &42u32.to_le_bytes());
    }

    #[test]
    fn pointer_loop_is_bounded() {
        let mut p = [0u8; 4];
        p[0] = 0xC0;
        p[1] = 2;
        p[2] = 0xC0;
        p[3] = 0;
        assert!(read_dns_name(&p, 0, 4).is_none());
    }
}
