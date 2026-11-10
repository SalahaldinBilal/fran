//! The service runs profiles sent by a normal user as SYSTEM or root, so it only takes what Fran's own profile
//! writer produces (`config::core_profile` in the app), not whatever OpenVPN 3 would accept.

const MAX_REMOTES: usize = 32;
const MAX_LINES: usize = 4096;

const CIPHERS: &[&str] = &["AES-128-GCM", "AES-192-GCM", "AES-256-GCM", "CHACHA20-POLY1305"];
const DIGESTS: &[&str] = &["SHA1", "SHA224", "SHA256", "SHA384", "SHA512"];
const BLOCKS: &[&str] = &["ca", "peer-fingerprint", "tls-auth", "tls-crypt", "tls-crypt-v2"];

/// OpenVPN's tokenizer, the same one the app reads .ovpn files with.
fn tokens(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut started = false;
    let mut chars = line.chars();
    while let Some(character) = chars.next() {
        match (quote, character) {
            (Some('"'), '\\') => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            (Some(open), close) if open == close => quote = None,
            (Some(_), other) => current.push(other),
            (None, '"' | '\'') => {
                quote = Some(character);
                started = true;
            }
            (None, other) if other.is_whitespace() => {
                if started {
                    out.push(std::mem::take(&mut current));
                    started = false;
                }
            }
            (None, '#' | ';') if !started => break,
            (None, other) => {
                current.push(other);
                started = true;
            }
        }
    }
    if started {
        out.push(current);
    }
    out
}

fn plain(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|character| character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ':' | '[' | ']'))
}

fn number<T: std::str::FromStr>(value: &str) -> Option<T> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse().ok()
}

fn directive(name: &str, args: &[&str]) -> Result<(), String> {
    let fits = match (name, args) {
        ("client" | "nobind" | "remote-random" | "auth-user-pass", []) => true,
        ("dev", ["tun"]) | ("remote-cert-tls", ["server"]) | ("comp-lzo", ["no"]) => true,
        ("setenv", ["CLIENT_CERT", "0"]) => true,
        ("tls-version-min", ["1.2" | "1.3"]) | ("key-direction", ["0" | "1"]) => true,
        ("compress", ["stub" | "stub-v2"]) => true,
        ("remote", [host, port, "udp" | "tcp"]) => plain(host) && number::<u16>(port).is_some_and(|port| port > 0),
        ("verify-x509-name", [text, "subject" | "name" | "name-prefix"]) => !text.chars().any(char::is_control),
        ("static-challenge", [text, "0" | "1"]) => !text.chars().any(char::is_control),
        ("data-ciphers", [list]) => list.split(':').all(|cipher| CIPHERS.contains(&cipher)),
        ("cipher", [cipher]) => CIPHERS.contains(cipher),
        ("auth", [digest]) => DIGESTS.contains(digest),
        ("reneg-sec", [seconds]) => number::<u32>(seconds).is_some(),
        _ => false,
    };
    if fits { Ok(()) } else { Err(format!("The profile has a line Fran doesn't write: {name}")) }
}

/// Ok when every line is one Fran's writer produces. Inline blocks only hold certificates, fingerprints and TLS keys.
pub fn check(text: &str) -> Result<(), String> {
    let mut seen: Vec<String> = Vec::new();
    let mut remotes = 0;
    let mut block: Option<&str> = None;
    for (index, raw) in text.lines().enumerate() {
        if index >= MAX_LINES {
            return Err("The profile is too long".to_string());
        }
        let line = raw.trim();
        if let Some(tag) = block {
            if line == format!("</{tag}>") {
                block = None;
            } else if line.contains(['<', '>']) {
                return Err(format!("The {tag} block in the profile isn't closed"));
            }
            continue;
        }
        if line.is_empty() {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|rest| rest.strip_suffix('>')) {
            let known = BLOCKS.iter().find(|known| **known == tag).ok_or_else(|| format!("The profile has a block Fran doesn't write: {tag}"))?;
            if seen.iter().any(|name| name == tag) {
                return Err(format!("The profile has the {tag} block twice"));
            }
            seen.push(tag.to_string());
            block = Some(known);
            continue;
        }
        let words = tokens(line);
        let Some((name, args)) = words.split_first() else {
            return Err(format!("The profile has a line Fran doesn't write: {line}"));
        };
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        directive(name, &args)?;
        if name == "remote" {
            remotes += 1;
            if remotes > MAX_REMOTES {
                return Err("The profile has too many servers".to_string());
            }
        } else if seen.iter().any(|seen| seen == name) {
            return Err(format!("The profile has {name} twice"));
        } else {
            seen.push(name.clone());
        }
    }
    if let Some(tag) = block {
        return Err(format!("The {tag} block in the profile isn't closed"));
    }
    if remotes == 0 {
        return Err("The profile has no server".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::check;

    const WRITTEN: &str = "client\ndev tun\nnobind\nremote vpn.example.com 1194 udp\nremote 10.0.0.1 443 tcp\nremote-cert-tls server\n\
        verify-x509-name \"C=US, CN=vpn \\\"main\\\"\" subject\ntls-version-min 1.2\ndata-ciphers AES-256-GCM:CHACHA20-POLY1305\n\
        auth SHA256\nreneg-sec 3600\ncompress stub-v2\nauth-user-pass\nstatic-challenge \"Enter code\" 1\nkey-direction 1\n\
        <ca>\n-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n</ca>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\nab\n-----END OpenVPN Static key V1-----\n</tls-auth>\n";

    #[test]
    fn what_the_writer_produces_passes() {
        check(WRITTEN).unwrap();
    }

    #[test]
    fn scripts_and_local_options_are_refused() {
        for line in [
            "up /bin/sh",
            "script-security 2",
            "plugin /lib/evil.so",
            "management 127.0.0.1 7505",
            "log /etc/passwd",
            "dev tap",
            "setenv FOO bar",
            "tls-version-min 1.0",
            "data-ciphers BF-CBC",
            "comp-lzo yes",
            "remote host;rm 1194 udp",
            "route-up \"/bin/sh -c id\"",
        ] {
            let text = format!("{WRITTEN}{line}\n");
            assert!(check(&text).is_err(), "{line} was let through");
        }
    }

    #[test]
    fn blocks_are_limited_to_what_the_writer_inlines() {
        assert!(check("client\nremote a 1 udp\n<key>\nsecret\n</key>\n").is_err());
        assert!(check("client\nremote a 1 udp\n<ca>\nup /bin/sh\n<dh>\n</ca>\n").is_err());
        assert!(check("client\nremote a 1 udp\n<ca>\nx\n").is_err());
        assert!(check("client\nremote a 1 udp\n<ca>\nx\n</ca>\n<ca>\ny\n</ca>\n").is_err());
    }

    #[test]
    fn a_profile_without_a_server_is_refused() {
        assert!(check("client\ndev tun\n").is_err());
    }
}
