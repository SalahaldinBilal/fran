use std::net::{IpAddr, Ipv6Addr};

use base64ct::{Base64, Encoding};
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};

pub const MAX_LINE: usize = 64 * 1024;

/// A second sign-in step the server asks for after the password (OpenVPN's dynamic challenge, CRV1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicChallenge {
    pub state_id: String,
    pub username: String,
    pub text: String,
    pub echo: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Event {
    Hold,
    NeedAuth { challenge: bool },
    /// Another secret OpenVPN needs, like a smartcard PIN (`Need 'Token' password`).
    NeedPassword { name: String },
    AuthFailed { dynamic: Option<DynamicChallenge> },
    Sign(SignRequest),
    State { name: String, address: Option<String>, address6: Option<Ipv6Addr> },
    Bytes { bytes_in: i64, bytes_out: i64 },
    Fatal(String),
    /// The DNS servers in the server's PUSH_REPLY, as OpenVPN logs it.
    Dns(Vec<IpAddr>),
    Log { error: bool, text: String },
    Other,
}

/// `CRV1:flags:state_id:username_base64:text`, where the text may hold colons.
pub fn dynamic_challenge(text: &str) -> Option<DynamicChallenge> {
    let start = text.find("CRV1:")? + 5;
    let rest = text[start..].trim_end_matches(['\'', ']', ' ']);
    let mut parts = rest.splitn(4, ':');
    let flags = parts.next()?;
    let state_id = parts.next()?.to_string();
    let username = Base64::decode_vec(parts.next()?).ok().and_then(|bytes| String::from_utf8(bytes).ok())?;
    let text = parts.next().unwrap_or_default().to_string();
    Some(DynamicChallenge { state_id, username, text, echo: flags.split(',').any(|flag| flag == "E") })
}

/// `dhcp-option DNS x` and 2.6's `dns server N address x[:port]` from a PUSH_REPLY.
fn pushed_dns(text: &str) -> Option<Vec<IpAddr>> {
    let reply = text.split_once("PUSH_REPLY,")?.1.trim_end_matches(['\'', ' ']);
    let mut servers = Vec::new();
    for option in reply.split(',') {
        let words: Vec<&str> = option.split_whitespace().collect();
        let address = match words.as_slice() {
            ["dhcp-option", "DNS" | "DNS6", address, ..] => *address,
            ["dns", "server", _, "address", address, ..] => *address,
            _ => continue,
        };
        let bare = address.trim_start_matches('[').split(']').next().unwrap_or(address);
        let parsed = bare.parse::<IpAddr>().ok().or_else(|| bare.rsplit_once(':').and_then(|(host, _)| host.parse().ok()));
        if let Some(address) = parsed.filter(|address| !servers.contains(address)) {
            servers.push(address);
        }
    }
    Some(servers)
}

#[derive(Debug, PartialEq, Eq)]
pub struct SignRequest {
    pub data: String,
    pub algorithm: String,
    pub hash: String,
    pub salt_len: String,
    /// OpenVPN sends the whole message (and Fran hashes it) only with `management-external-key digest`.
    pub message: bool,
}

/// One real-time line from OpenVPN's management interface.
pub fn parse_line(line: &str) -> Event {
    let Some((source, text)) = line.strip_prefix('>').and_then(|rest| rest.split_once(':')) else {
        return Event::Other;
    };
    match source {
        "HOLD" => Event::Hold,
        "PASSWORD" if text.starts_with("Need 'Auth'") => Event::NeedAuth { challenge: text.contains(" SC:") },
        "PASSWORD" if text.starts_with("Verification Failed: 'Auth'") => Event::AuthFailed { dynamic: dynamic_challenge(text) },
        "PASSWORD" if text.starts_with("Need '") => match text["Need '".len()..].split_once("' password") {
            Some((name, _)) if !name.is_empty() => Event::NeedPassword { name: name.to_string() },
            _ => Event::Other,
        },
        "PK_SIGN" => {
            let (data, rest) = text.split_once(',').unwrap_or((text, ""));
            let mut parts = rest.split(',');
            let algorithm = parts.next().unwrap_or_default().to_string();
            let mut request = SignRequest { data: data.to_string(), algorithm, hash: String::new(), salt_len: String::new(), message: false };
            for part in parts {
                match part.split_once('=') {
                    Some(("hashalg", value)) => request.hash = value.to_string(),
                    Some(("saltlen", value)) => request.salt_len = value.to_string(),
                    Some(("data", "message")) => request.message = true,
                    _ => {}
                }
            }
            Event::Sign(request)
        }
        "STATE" => {
            let fields: Vec<&str> = text.split(',').collect();
            Event::State {
                name: fields.get(1).copied().unwrap_or_default().to_string(),
                address: fields.get(3).map(|value| value.trim()).filter(|value| !value.is_empty()).map(str::to_string),
                address6: fields.get(8).and_then(|value| value.trim().parse().ok()),
            }
        }
        "BYTECOUNT" => match text.split_once(',') {
            Some((bytes_in, bytes_out)) => Event::Bytes { bytes_in: bytes_in.trim().parse().unwrap_or(0), bytes_out: bytes_out.trim().parse().unwrap_or(0) },
            None => Event::Other,
        },
        "FATAL" => Event::Fatal(text.trim().to_string()),
        "LOG" => {
            let mut fields = text.splitn(3, ',');
            let _time = fields.next();
            let flags = fields.next().unwrap_or_default();
            let message = fields.next().unwrap_or_default().trim();
            match pushed_dns(message) {
                Some(servers) => Event::Dns(servers),
                None => Event::Log { error: flags.contains('F') || flags.contains('N'), text: message.to_string() },
            }
        }
        _ => Event::Other,
    }
}

/// A command argument in double quotes. Line breaks would start another command, so they're refused.
pub fn quote(value: &str, what: &str) -> AppResult<String> {
    if value.chars().any(char::is_control) {
        return Err(AppError::general(format!("The {what} has a line break or control character")));
    }
    Ok(format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\"")))
}

/// The two commands that answer `>PASSWORD:Need 'Auth'`. A static challenge answer goes in OpenVPN's SCRV1 form.
pub fn login_commands(user: &str, password: &str, response: Option<&str>) -> AppResult<Zeroizing<String>> {
    let password = match response {
        Some(response) => Zeroizing::new(format!(
            "SCRV1:{}:{}",
            Base64::encode_string(password.as_bytes()),
            Base64::encode_string(response.as_bytes())
        )),
        None => Zeroizing::new(password.to_string()),
    };
    let quoted = Zeroizing::new(quote(&password, "VPN password")?);
    Ok(Zeroizing::new(format!("username \"Auth\" {}\npassword \"Auth\" {}\n", quote(user, "VPN user name")?, quoted.as_str())))
}

pub fn signature_command(signature_base64: &str) -> String {
    let mut out = String::from("pk-sig\n");
    for chunk in signature_base64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("END\n");
    out
}

/// The answer to `>PASSWORD:Need 'name' password`.
pub fn password_command(name: &str, value: &str) -> AppResult<Zeroizing<String>> {
    let value = Zeroizing::new(quote(value, "PIN")?);
    Ok(Zeroizing::new(format!("password {} {}\n", quote(name, "token name")?, value.as_str())))
}

/// The answer to a dynamic challenge, sent on the `>PASSWORD:Need 'Auth'` that follows it.
pub fn challenge_commands(challenge: &DynamicChallenge, response: &str) -> AppResult<Zeroizing<String>> {
    if challenge.state_id.contains(':') || response.chars().any(char::is_control) {
        return Err(AppError::general("The second sign-in step can't be answered with that"));
    }
    let password = Zeroizing::new(quote(&format!("CRV1::{}::{response}", challenge.state_id), "answer")?);
    Ok(Zeroizing::new(format!(
        "username \"Auth\" {}\npassword \"Auth\" {}\n",
        quote(&challenge.username, "VPN user name")?,
        password.as_str()
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_openvpn_sends() {
        assert_eq!(parse_line(">HOLD:Waiting for hold release:0"), Event::Hold);
        assert_eq!(parse_line(">PASSWORD:Need 'Auth' username/password"), Event::NeedAuth { challenge: false });
        assert_eq!(parse_line(">PASSWORD:Need 'Auth' username/password SC:1,Enter code"), Event::NeedAuth { challenge: true });
        assert_eq!(parse_line(">PASSWORD:Verification Failed: 'Auth'"), Event::AuthFailed { dynamic: None });
        assert_eq!(parse_line(">PASSWORD:Need 'YubiKey PIV' password"), Event::NeedPassword { name: "YubiKey PIV".to_string() });
        assert_eq!(password_command("YubiKey PIV", "1234").unwrap().as_str(), "password \"YubiKey PIV\" \"1234\"\n");
        assert_eq!(
            parse_line(">STATE:1700000000,CONNECTED,SUCCESS,10.8.0.2,203.0.113.5,1194,,,fd00::2"),
            Event::State { name: "CONNECTED".to_string(), address: Some("10.8.0.2".to_string()), address6: Some("fd00::2".parse().unwrap()) }
        );
        assert_eq!(parse_line(">STATE:1700000000,WAIT,,,,,,"), Event::State { name: "WAIT".to_string(), address: None, address6: None });
        assert_eq!(parse_line(">BYTECOUNT:1024,2048"), Event::Bytes { bytes_in: 1024, bytes_out: 2048 });
        assert_eq!(parse_line(">LOG:1700000000,N,TLS Error: a, b"), Event::Log { error: true, text: "TLS Error: a, b".to_string() });
        assert_eq!(parse_line("SUCCESS: hold release succeeded"), Event::Other);
    }

    #[test]
    fn dynamic_challenges() {
        let Event::AuthFailed { dynamic: Some(challenge) } =
            parse_line(">PASSWORD:Verification Failed: 'Auth' ['CRV1:R,E:Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l:Y3Ix:Please enter token PIN: now']")
        else {
            panic!()
        };
        assert_eq!(
            challenge,
            DynamicChallenge {
                state_id: "Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l".to_string(),
                username: "cr1".to_string(),
                text: "Please enter token PIN: now".to_string(),
                echo: true,
            }
        );
        let commands = challenge_commands(&challenge, "8675309").unwrap();
        assert_eq!(commands.as_str(), "username \"Auth\" \"cr1\"\npassword \"Auth\" \"CRV1::Om01u7Fh4LrGBS7uh0SWmzwabUiGiW6l::8675309\"\n");
        assert!(challenge_commands(&challenge, "1\nsignal SIGTERM").is_err());
    }

    #[test]
    fn pushed_dns_servers() {
        let line = ">LOG:1700000000,,PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN lab.internal,dns server 0 address [fd00::1]:53 10.8.0.1,ifconfig 10.8.0.2 255.255.255.0'";
        assert_eq!(parse_line(line), Event::Dns(vec!["10.8.0.1".parse().unwrap(), "fd00::1".parse().unwrap()]));
        assert_eq!(
            parse_line(">LOG:1,,PUSH: Received control message: 'PUSH_REPLY,route-gateway 10.8.0.1'"),
            Event::Dns(Vec::new())
        );
    }

    #[test]
    fn sign_requests() {
        assert_eq!(
            parse_line(">PK_SIGN:AAAA,RSA_PKCS1_PSS_PADDING,hashalg=SHA256,saltlen=digest,data=message"),
            Event::Sign(SignRequest {
                data: "AAAA".to_string(),
                algorithm: "RSA_PKCS1_PSS_PADDING".to_string(),
                hash: "SHA256".to_string(),
                salt_len: "digest".to_string(),
                message: true,
            })
        );
        let Event::Sign(request) = parse_line(">PK_SIGN:AAAA,ECDSA") else { panic!() };
        assert!(!request.message);
        let Event::Sign(request) = parse_line(">PK_SIGN:AAAA,ED25519,data=message") else { panic!() };
        assert_eq!((request.algorithm.as_str(), request.message), ("ED25519", true));
    }

    #[test]
    fn logins_are_quoted_and_line_breaks_refused() {
        let commands = login_commands("al\"ice", "p\\w", None).unwrap();
        assert_eq!(commands.as_str(), "username \"Auth\" \"al\\\"ice\"\npassword \"Auth\" \"p\\\\w\"\n");
        let commands = login_commands("bob", "bar", Some("8675309")).unwrap();
        assert!(commands.contains("password \"Auth\" \"SCRV1:YmFy:ODY3NTMwOQ==\"\n"));
        assert!(login_commands("bob", "bar\nsignal SIGTERM", None).is_err());
    }

    #[test]
    fn signatures_end_with_end() {
        let command = signature_command(&"A".repeat(100));
        assert_eq!(command, format!("pk-sig\n{}\n{}\nEND\n", "A".repeat(64), "A".repeat(36)));
    }
}
