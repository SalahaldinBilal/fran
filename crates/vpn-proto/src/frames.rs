use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Bigger than any IP packet plus room for a profile with long certificate chains.
pub const MAX_FRAME: usize = 1024 * 1024;
pub const MAX_PACKET: usize = 65_535;

const KIND_PACKET: u8 = 1;
const KIND_MESSAGE: u8 = 2;

/// What the worker learned when OpenVPN 3 set up the tunnel.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TunnelSettings {
    pub addr4: Option<(Ipv4Addr, u8)>,
    pub addr6: Option<(Ipv6Addr, u8)>,
    pub gw4: Option<Ipv4Addr>,
    pub gw6: Option<Ipv6Addr>,
    pub dns: Vec<SocketAddr>,
    pub domains: Vec<String>,
    pub split_domains: Vec<String>,
    pub mtu: Option<u16>,
}

/// Wiped by the worker once OpenVPN 3 has it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub username: String,
    pub password: String,
    pub response: String,
    /// The server's CRV1 cookie when `response` answers its second sign-in step.
    #[serde(default)]
    pub dynamic_cookie: String,
}

impl std::fmt::Debug for Login {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Login").field("username", &self.username).finish_non_exhaustive()
    }
}

impl Drop for Login {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        self.response.zeroize();
        self.dynamic_cookie.zeroize();
    }
}

/// One WireGuard peer and the interface it's reached through. Keys are base64, as in a .conf file.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WireGuardStart {
    pub private_key: String,
    pub peer_public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint_host: String,
    pub endpoint_port: u16,
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub keepalive_secs: Option<u16>,
    pub addresses: Vec<(IpAddr, u8)>,
    pub dns: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub mtu: Option<u16>,
}

impl std::fmt::Debug for WireGuardStart {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireGuardStart")
            .field("peer_public_key", &self.peer_public_key)
            .field("endpoint_host", &self.endpoint_host)
            .field("endpoint_port", &self.endpoint_port)
            .field("allowed_ips", &self.allowed_ips)
            .finish_non_exhaustive()
    }
}

impl Drop for WireGuardStart {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
        if let Some(key) = self.preshared_key.as_mut() {
            key.zeroize();
        }
    }
}

/// How the service sets up the computer's adapter for this tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterOptions {
    /// Follow the server's redirect-gateway. Off means only the VPN's own networks go through it.
    pub route_all: bool,
    pub use_vpn_dns: bool,
}

/// The computer's adapter once the service has set it up.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AdapterInfo {
    pub name: String,
    pub index: u32,
    pub addr4: Option<(Ipv4Addr, u8)>,
    pub addr6: Option<(Ipv6Addr, u8)>,
    pub dns: Vec<IpAddr>,
    /// The computer's DNS was pointed at the VPN's servers. False where that couldn't be done, like Linux without systemd-resolved.
    pub dns_set: bool,
    pub routes_all: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Access {
    /// Any account signed in on this computer. Not service accounts or network logins.
    Everyone,
    /// Administrators and members of the service's group.
    Group,
}

impl Access {
    pub fn as_arg(self) -> &'static str {
        match self {
            Self::Everyone => "everyone",
            Self::Group => "group",
        }
    }

    pub fn from_arg(text: &str) -> Option<Self> {
        match text.trim() {
            "everyone" => Some(Self::Everyone),
            "group" => Some(Self::Group),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceInfo {
    pub build: String,
    pub access: Access,
    pub allowed: bool,
    /// Why the caller isn't allowed.
    pub refused: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum ToWorker {
    Hello {
        version: u32,
    },
    #[serde(rename_all = "camelCase")]
    Start {
        profile: String,
        cert: String,
        chain: String,
        gui_version: String,
        timeout_secs: i32,
        login: Option<Login>,
        /// Set when the service runs the tunnel on a real adapter.
        #[serde(default)]
        adapter: Option<AdapterOptions>,
    },
    StartWireGuard {
        config: WireGuardStart,
        /// Set when the service runs the tunnel on a real adapter.
        #[serde(default)]
        adapter: Option<AdapterOptions>,
    },
    SignReply {
        id: u64,
        signature: Option<String>,
        error: Option<String>,
    },
    Stop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum FromWorker {
    /// `service` is only set by the service.
    Hello { version: u32, service: Option<ServiceInfo> },
    /// The session was refused before it started: another protocol version, a caller who isn't allowed, or a profile the check turned down.
    Refused { message: String },
    #[serde(rename_all = "camelCase")]
    Evaluated { autologin: bool, external_pki: bool, static_challenge: Option<String>, static_echo: bool },
    EvalFailed { message: String },
    Event { name: String, info: String, error: bool, fatal: bool },
    Log { line: String },
    #[serde(rename_all = "camelCase")]
    Sign { id: u64, data: String, algorithm: String, hash: String, salt_len: String },
    /// For WireGuard, sent once the first handshake is done, since nothing before that says the server is there.
    TunUp { settings: TunnelSettings },
    AdapterUp { adapter: AdapterInfo },
    /// A later WireGuard handshake finished. The tunnel and adapter from the first one stay as they are.
    Handshake,
    TunFailed { message: String },
    TunDown,
    #[serde(rename_all = "camelCase")]
    Stats { bytes_in: i64, bytes_out: i64 },
    Ended { error: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame<T> {
    Packet(Vec<u8>),
    Message(T),
}

fn bad(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn encode_packet(packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() > MAX_PACKET {
        return Err(bad("packet too large"));
    }
    let mut out = Vec::with_capacity(5 + packet.len());
    out.extend_from_slice(&(packet.len() as u32 + 1).to_be_bytes());
    out.push(KIND_PACKET);
    out.extend_from_slice(packet);
    Ok(out)
}

pub fn encode_message<T: Serialize>(message: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(message).map_err(|error| bad(error.to_string()))?;
    if body.len() + 1 > MAX_FRAME {
        return Err(bad("message too large"));
    }
    let mut out = Vec::with_capacity(5 + body.len());
    out.extend_from_slice(&(body.len() as u32 + 1).to_be_bytes());
    out.push(KIND_MESSAGE);
    out.extend_from_slice(&body);
    Ok(out)
}

fn body_len(header: [u8; 4]) -> io::Result<usize> {
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(bad(format!("frame of {len} bytes")));
    }
    Ok(len)
}

fn decode<T: DeserializeOwned>(body: Vec<u8>) -> io::Result<Frame<T>> {
    let (kind, payload) = body.split_first().ok_or_else(|| bad("empty frame"))?;
    match *kind {
        KIND_PACKET if payload.len() <= MAX_PACKET => Ok(Frame::Packet(payload.to_vec())),
        KIND_PACKET => Err(bad("packet too large")),
        KIND_MESSAGE => serde_json::from_slice(payload).map(Frame::Message).map_err(|error| bad(error.to_string())),
        other => Err(bad(format!("unknown frame kind {other}"))),
    }
}

/// None at a clean end of the stream. A stream cut inside a frame is an error.
pub fn read_frame<T: DeserializeOwned>(reader: &mut impl Read) -> io::Result<Option<Frame<T>>> {
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut body = vec![0u8; body_len(header)?];
    reader.read_exact(&mut body)?;
    decode(body).map(Some)
}

#[cfg(feature = "async")]
pub async fn read_frame_async<T: DeserializeOwned>(reader: &mut (impl tokio::io::AsyncRead + Unpin)) -> io::Result<Option<Frame<T>>> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 4];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut body = vec![0u8; body_len(header)?];
    reader.read_exact(&mut body).await?;
    decode(body).map(Some)
}

pub fn write_frame(writer: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    writer.write_all(bytes)?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(bytes: &[u8]) -> io::Result<Vec<Frame<ToWorker>>> {
        let mut cursor = io::Cursor::new(bytes);
        let mut frames = Vec::new();
        while let Some(frame) = read_frame(&mut cursor)? {
            frames.push(frame);
        }
        Ok(frames)
    }

    #[test]
    fn round_trip() {
        let mut bytes = encode_packet(&[0x45, 0, 0, 20]).unwrap();
        bytes.extend(encode_message(&ToWorker::Stop).unwrap());
        bytes.extend(encode_message(&ToWorker::SignReply { id: 7, signature: Some("c2ln".to_string()), error: None }).unwrap());
        let frames = read_all(&bytes).unwrap();
        assert_eq!(frames[0], Frame::Packet(vec![0x45, 0, 0, 20]));
        assert_eq!(frames[1], Frame::Message(ToWorker::Stop));
        assert!(matches!(frames[2], Frame::Message(ToWorker::SignReply { id: 7, .. })));
    }

    #[test]
    fn oversized_frames_are_refused_before_reading_them() {
        let mut bytes = ((MAX_FRAME + 1) as u32).to_be_bytes().to_vec();
        bytes.push(KIND_PACKET);
        assert!(read_all(&bytes).is_err());
        assert!(encode_packet(&vec![0; MAX_PACKET + 1]).is_err());
        assert!(read_all(&0u32.to_be_bytes()).is_err());
    }

    #[test]
    fn cut_and_garbage_frames_are_errors() {
        let whole = encode_message(&ToWorker::Stop).unwrap();
        assert!(read_all(&whole[..whole.len() - 1]).is_err());

        let mut garbage = 5u32.to_be_bytes().to_vec();
        garbage.extend_from_slice(&[9, 1, 2, 3, 4]);
        assert!(read_all(&garbage).is_err());

        let mut not_json = 4u32.to_be_bytes().to_vec();
        not_json.extend_from_slice(&[KIND_MESSAGE, b'{', b'x', b'}']);
        assert!(read_all(&not_json).is_err());
    }

    #[test]
    fn wireguard_keys_stay_out_of_debug_output() {
        let start = ToWorker::StartWireGuard {
            config: WireGuardStart {
                private_key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=".to_string(),
                peer_public_key: "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=".to_string(),
                preshared_key: Some("FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE=".to_string()),
                endpoint_host: "vpn.example.com".to_string(),
                endpoint_port: 51820,
                allowed_ips: vec![("0.0.0.0".parse().unwrap(), 0)],
                keepalive_secs: Some(25),
                addresses: vec![("10.64.0.2".parse().unwrap(), 32)],
                dns: vec!["10.64.0.1".parse().unwrap()],
                search_domains: Vec::new(),
                mtu: None,
            },
            adapter: None,
        };
        let text = format!("{start:?}");
        assert!(!text.contains("yAnz5TF") && !text.contains("FpCyhws9"), "a key leaked into {text}");
        assert!(text.contains("vpn.example.com"));
    }

    #[cfg(feature = "async")]
    #[tokio::test]
    async fn async_reader_matches() {
        let bytes = encode_message(&FromWorker::TunDown).unwrap();
        let mut slice = bytes.as_slice();
        let frame: Option<Frame<FromWorker>> = read_frame_async(&mut slice).await.unwrap();
        assert_eq!(frame, Some(Frame::Message(FromWorker::TunDown)));
        let end: Option<Frame<FromWorker>> = read_frame_async(&mut slice).await.unwrap();
        assert_eq!(end, None);
    }
}
