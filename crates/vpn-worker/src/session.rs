use std::{
    collections::HashMap,
    io::{Read, Write},
    sync::{
        Arc, Mutex, OnceLock, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use openvpn_rust_bindings::{CoreEvent, Credentials, Engine, EngineConfig, EngineEvents, SignRequest, TunSettings};
use vpn_proto::{
    PROTOCOL_VERSION,
    frames::{self, AdapterOptions, Frame, FromWorker, ServiceInfo, ToWorker, TunnelSettings},
};
use zeroize::Zeroizing;

use crate::wireguard;

const SIGN_TIMEOUT: Duration = Duration::from_secs(30);
const STATS_EVERY: Duration = Duration::from_secs(2);

pub struct Out {
    writer: Mutex<Box<dyn Write + Send>>,
}

impl Out {
    pub fn new(writer: Box<dyn Write + Send>) -> Arc<Self> {
        Arc::new(Self { writer: Mutex::new(writer) })
    }

    pub fn write(&self, bytes: &[u8]) -> bool {
        match self.writer.lock() {
            Ok(mut writer) => frames::write_frame(&mut *writer, bytes).is_ok(),
            Err(_) => false,
        }
    }

    pub fn send(&self, message: &FromWorker) -> bool {
        frames::encode_message(message).is_ok_and(|bytes| self.write(&bytes))
    }
}

/// What takes packets headed into the VPN: OpenVPN 3 or a WireGuard session.
pub trait Uplink: Send + Sync {
    fn send(&self, packet: &[u8]);
}

impl Uplink for Engine {
    fn send(&self, packet: &[u8]) {
        self.send_packet(packet);
    }
}

/// Where a tunnel's packets go: back to Fran in frames, or onto the computer's adapter.
pub trait Tun: Send + Sync {
    /// What to tell Fran once the tunnel is set up. Packets read from an adapter go to `uplink`.
    fn up(&self, settings: TunSettings, uplink: Arc<dyn Uplink>) -> Result<FromWorker, String>;
    fn packet(&self, packet: &[u8]) -> bool;
    fn down(&self);
    /// Fran sends packets in frames only to an own tunnel.
    fn takes_packets(&self) -> bool;
}

/// An own tunnel: packets go to Fran's network stack over the pipe.
pub struct FrameTun {
    pub out: Arc<Out>,
}

impl Tun for FrameTun {
    fn up(&self, from: TunSettings, _uplink: Arc<dyn Uplink>) -> Result<FromWorker, String> {
        Ok(FromWorker::TunUp {
            settings: TunnelSettings {
                addr4: from.addr4,
                addr6: from.addr6,
                gw4: from.gw4,
                gw6: from.gw6,
                dns: from.dns,
                domains: from.domains,
                split_domains: from.split_domains,
                mtu: from.mtu,
            },
        })
    }

    fn packet(&self, packet: &[u8]) -> bool {
        frames::encode_packet(packet).is_ok_and(|bytes| self.out.write(&bytes))
    }

    fn down(&self) {
        self.out.send(&FromWorker::TunDown);
    }

    fn takes_packets(&self) -> bool {
        true
    }
}

struct Events {
    out: Arc<Out>,
    tun: Arc<dyn Tun>,
    engine: OnceLock<Weak<Engine>>,
    signs: Mutex<HashMap<u64, mpsc::Sender<Result<String, String>>>>,
    next_sign: AtomicU64,
}

impl EngineEvents for Events {
    fn event(&self, event: CoreEvent) {
        self.out.send(&FromWorker::Event { name: event.name, info: event.info, error: event.error, fatal: event.fatal });
    }

    fn log(&self, line: &str) {
        self.out.send(&FromWorker::Log { line: line.to_string() });
    }

    // Blocks Core's thread until Fran answers, which is what Core's own clients do with a hardware key.
    fn sign(&self, request: SignRequest) -> Result<String, String> {
        let id = self.next_sign.fetch_add(1, Ordering::SeqCst);
        let (reply, answer) = mpsc::channel();
        self.signs.lock().map_err(|_| "sign lock poisoned".to_string())?.insert(id, reply);
        let asked = self.out.send(&FromWorker::Sign {
            id,
            data: request.data_base64,
            algorithm: request.algorithm,
            hash: request.hash,
            salt_len: request.salt_len,
        });
        let result = if asked {
            answer.recv_timeout(SIGN_TIMEOUT).unwrap_or_else(|_| Err("Fran didn't sign in time".to_string()))
        } else {
            Err("Fran is gone".to_string())
        };
        if let Ok(mut signs) = self.signs.lock() {
            signs.remove(&id);
        }
        result
    }

    fn tun_up(&self, result: Result<TunSettings, String>) {
        let engine = self.engine.get().and_then(Weak::upgrade);
        let reply = match (result, &engine) {
            (Ok(settings), Some(engine)) => self.tun.up(settings, engine.clone()),
            (Ok(_), None) => Err("OpenVPN 3 is gone".to_string()),
            (Err(message), _) => Err(message),
        };
        match reply {
            Ok(message) => {
                self.out.send(&message);
            }
            Err(message) => {
                self.out.send(&FromWorker::TunFailed { message });
                // Not from Core's own thread, which is the one calling this.
                if let Some(engine) = engine {
                    thread::spawn(move || engine.stop());
                }
            }
        }
    }

    fn packet(&self, packet: &[u8]) -> bool {
        self.tun.packet(packet)
    }

    fn tun_down(&self) {
        self.tun.down();
    }
}

/// Builds the tunnel's packet path once Fran's Start says which kind it wants.
pub type MakeTun<'a> = dyn FnOnce(Option<AdapterOptions>) -> Result<Arc<dyn Tun>, String> + 'a;

/// One OpenVPN 3 or WireGuard session over a pipe or socket. `service` is what the service tells the caller in its hello,
/// and a caller it doesn't allow gets that hello and nothing more.
pub fn run(mut reader: impl Read, out: Arc<Out>, service: Option<ServiceInfo>, make_tun: Box<MakeTun<'_>>) -> i32 {
    match frames::read_frame::<ToWorker>(&mut reader) {
        Ok(Some(Frame::Message(ToWorker::Hello { version }))) if version == PROTOCOL_VERSION => {}
        Ok(Some(Frame::Message(ToWorker::Hello { .. }))) => {
            out.send(&FromWorker::Refused {
                message: format!("Fran's VPN {} doesn't match this version of Fran", if service.is_some() { "service" } else { "worker" }),
            });
            return 1;
        }
        _ => return 1,
    }
    let allowed = service.as_ref().is_none_or(|info| info.allowed);
    out.send(&FromWorker::Hello { version: PROTOCOL_VERSION, service });
    if !allowed {
        return 1;
    }

    let (profile, cert, chain, gui_version, timeout_secs, login, adapter) = match frames::read_frame::<ToWorker>(&mut reader) {
        Ok(Some(Frame::Message(ToWorker::Start { profile, cert, chain, gui_version, timeout_secs, login, adapter }))) => {
            (Zeroizing::new(profile), cert, chain, gui_version, timeout_secs, login, adapter)
        }
        Ok(Some(Frame::Message(ToWorker::StartWireGuard { config, adapter }))) => {
            return match make_tun(adapter) {
                Ok(tun) => wireguard::run(reader, out, tun, config),
                Err(message) => {
                    out.send(&FromWorker::Refused { message });
                    1
                }
            };
        }
        _ => return 0,
    };
    if let Err(message) = vpn_proto::profile::check(&profile) {
        out.send(&FromWorker::Refused { message });
        return 1;
    }
    let tun = match make_tun(adapter) {
        Ok(tun) => tun,
        Err(message) => {
            out.send(&FromWorker::Refused { message });
            return 1;
        }
    };

    let events = Arc::new(Events { out: out.clone(), tun: tun.clone(), engine: OnceLock::new(), signs: Mutex::new(HashMap::new()), next_sign: AtomicU64::new(1) });
    let engine = match Engine::new(events.clone()) {
        Ok(engine) => Arc::new(engine),
        Err(message) => {
            out.send(&FromWorker::EvalFailed { message });
            return 1;
        }
    };
    let _ = events.engine.set(Arc::downgrade(&engine));

    let config = EngineConfig {
        profile: profile.to_string(),
        cert_pem: cert,
        chain_pem: chain,
        gui_version,
        conn_timeout_secs: timeout_secs,
        ..Default::default()
    };
    drop(profile);
    let evaluated = engine.eval(&config);
    drop(config);
    let evaluated = match evaluated {
        Ok(evaluated) => evaluated,
        Err(error) => {
            out.send(&FromWorker::EvalFailed { message: error.to_string() });
            return 1;
        }
    };
    out.send(&FromWorker::Evaluated {
        autologin: evaluated.autologin,
        external_pki: evaluated.external_pki,
        static_challenge: evaluated.static_challenge.as_ref().map(|(text, _)| text.clone()),
        static_echo: evaluated.static_challenge.as_ref().is_some_and(|(_, echo)| *echo),
    });
    if let Some(login) = &login {
        let credentials = Credentials {
            username: login.username.clone(),
            password: Zeroizing::new(login.password.clone()),
            response: Zeroizing::new(login.response.clone()),
            dynamic_cookie: login.dynamic_cookie.clone(),
        };
        if let Err(error) = engine.provide_credentials(&credentials) {
            out.send(&FromWorker::EvalFailed { message: error.to_string() });
            return 1;
        }
    }
    drop(login);

    let running = Arc::new(AtomicBool::new(true));
    let session = {
        let engine = engine.clone();
        let out = out.clone();
        let running = running.clone();
        thread::spawn(move || {
            let result = engine.connect();
            running.store(false, Ordering::SeqCst);
            out.send(&FromWorker::Ended { error: result.err().map(|error| error.to_string()) });
        })
    };
    {
        let engine = engine.clone();
        let out = out.clone();
        let running = running.clone();
        thread::spawn(move || {
            while running.load(Ordering::SeqCst) {
                thread::sleep(STATS_EVERY);
                let stats = engine.transport_stats();
                if !out.send(&FromWorker::Stats { bytes_in: stats.bytes_in, bytes_out: stats.bytes_out }) {
                    break;
                }
            }
        });
    }

    loop {
        match frames::read_frame::<ToWorker>(&mut reader) {
            Ok(Some(Frame::Packet(packet))) if tun.takes_packets() => {
                engine.send_packet(&packet);
            }
            Ok(Some(Frame::Message(ToWorker::SignReply { id, signature, error }))) => {
                let reply = events.signs.lock().ok().and_then(|mut signs| signs.remove(&id));
                if let Some(reply) = reply {
                    let _ = reply.send(signature.ok_or_else(|| error.unwrap_or_else(|| "Fran couldn't sign".to_string())));
                }
            }
            Ok(Some(Frame::Message(ToWorker::Stop))) => engine.stop(),
            Ok(Some(Frame::Message(ToWorker::Hello { .. } | ToWorker::Start { .. } | ToWorker::StartWireGuard { .. }))) => {}
            // Fran closed the connection, sent something malformed, or sent packets the service doesn't take.
            Ok(Some(Frame::Packet(_))) | Ok(None) | Err(_) => break,
        }
    }

    engine.stop();
    let _ = session.join();
    tun.down();
    0
}
