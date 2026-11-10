// Just enough DNS to look up A and AAAA records through a tunnel's own servers.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const MAX_POINTERS: usize = 32;

pub fn query(id: u16, name: &str, record: u16) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]);
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    let name = name.trim_end_matches('.');
    if name.is_empty() || name.len() > 253 {
        return Err(format!("\"{name}\" isn't a host name"));
    }
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_') {
            return Err(format!("\"{name}\" isn't a host name"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&record.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Answer {
    Addresses(Vec<IpAddr>),
    Truncated,
    NoSuchName,
    Failed(u8),
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    bytes.get(at..at + 2).map(|pair| u16::from_be_bytes([pair[0], pair[1]])).ok_or_else(|| "short DNS reply".to_string())
}

/// Skips a name, following at most a few compression pointers. Returns where the name ends in `bytes`.
fn skip_name(bytes: &[u8], mut at: usize) -> Result<usize, String> {
    let mut end = None;
    for _ in 0..MAX_POINTERS {
        let len = *bytes.get(at).ok_or("short DNS reply")?;
        match len {
            0 => return Ok(end.unwrap_or(at + 1)),
            len if len & 0xc0 == 0xc0 => {
                let pointer = usize::from(u16_at(bytes, at)? & 0x3fff);
                end.get_or_insert(at + 2);
                at = pointer;
            }
            len if len < 64 => at += 1 + usize::from(len),
            _ => return Err("bad DNS name".to_string()),
        }
    }
    Err("too many DNS name pointers".to_string())
}

pub fn parse(bytes: &[u8], id: u16) -> Result<Answer, String> {
    if u16_at(bytes, 0)? != id {
        return Err("DNS reply for another query".to_string());
    }
    let flags = u16_at(bytes, 2)?;
    if flags & 0x8000 == 0 {
        return Err("not a DNS reply".to_string());
    }
    if flags & 0x0200 != 0 {
        return Ok(Answer::Truncated);
    }
    match (flags & 0x000f) as u8 {
        0 => {}
        3 => return Ok(Answer::NoSuchName),
        code => return Ok(Answer::Failed(code)),
    }
    let questions = u16_at(bytes, 4)?;
    let answers = u16_at(bytes, 6)?;
    let mut at = 12;
    for _ in 0..questions {
        at = skip_name(bytes, at)? + 4;
    }
    let mut found = Vec::new();
    for _ in 0..answers {
        at = skip_name(bytes, at)?;
        let record = u16_at(bytes, at)?;
        let class = u16_at(bytes, at + 2)?;
        let len = usize::from(u16_at(bytes, at + 8)?);
        let data = bytes.get(at + 10..at + 10 + len).ok_or("short DNS reply")?;
        at += 10 + len;
        match (record, class, len) {
            (TYPE_A, CLASS_IN, 4) => found.push(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3]))),
            (TYPE_AAAA, CLASS_IN, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                found.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            _ => {}
        }
    }
    Ok(Answer::Addresses(found))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(query: &[u8], answers: &[(u16, &[u8])]) -> Vec<u8> {
        let mut out = query.to_vec();
        out[2] = 0x81;
        out[3] = 0x80;
        out[6..8].copy_from_slice(&(answers.len() as u16).to_be_bytes());
        for (record, data) in answers {
            out.extend_from_slice(&[0xc0, 12]);
            out.extend_from_slice(&record.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&60u32.to_be_bytes());
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[test]
    fn builds_a_query() {
        let bytes = query(0x1234, "db.lab.internal.", TYPE_A).unwrap();
        assert_eq!(&bytes[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(&bytes[12..16], &[2, b'd', b'b', 3]);
        assert_eq!(&bytes[bytes.len() - 4..], &[0, 1, 0, 1]);
        assert!(query(1, "bad name", TYPE_A).is_err());
        assert!(query(1, "a..b", TYPE_A).is_err());
    }

    #[test]
    fn reads_compressed_answers() {
        let request = query(7, "db.lab.internal", TYPE_A).unwrap();
        let bytes = reply(&request, &[(5, &[0xc0, 12]), (TYPE_A, &[10, 8, 0, 9]), (TYPE_AAAA, &[0; 16])]);
        assert_eq!(parse(&bytes, 7).unwrap(), Answer::Addresses(vec!["10.8.0.9".parse().unwrap(), "::".parse().unwrap()]));
        assert!(parse(&bytes, 8).is_err());
    }

    #[test]
    fn reports_truncation_and_errors() {
        let request = query(7, "x.example", TYPE_A).unwrap();
        let mut truncated = reply(&request, &[]);
        truncated[2] |= 0x02;
        assert_eq!(parse(&truncated, 7).unwrap(), Answer::Truncated);
        let mut missing = reply(&request, &[]);
        missing[3] = 0x83;
        assert_eq!(parse(&missing, 7).unwrap(), Answer::NoSuchName);
    }

    #[test]
    fn pointer_loops_are_refused() {
        let request = query(7, "x.example", TYPE_A).unwrap();
        let mut bytes = reply(&request, &[(TYPE_A, &[1, 2, 3, 4])]);
        let at = request.len();
        bytes[at] = 0xc0;
        bytes[at + 1] = at as u8;
        assert!(parse(&bytes, 7).is_err());
    }
}
