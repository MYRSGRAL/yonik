//! Versioned typed IPC. Ни raw config, ни открытого Value constructor.
use super::{
    CompiledProfileSystem, OwnedRuntimePlan, ProfileCompileError as Error, ValidatedGraph,
};
use serde::{
    Deserialize, Serialize,
    de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    io::{self, Write},
    marker::PhantomData,
};
use yonik_import::{NativeProfile, ProfileEntry};

pub const MAX_INTENT_BYTES: usize = 64 * 1024;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireTransportKind {
    Tcp = 1,
    Grpc = 2,
    Xhttp = 3,
    Hysteria = 4,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireSecurity {
    None = 0,
    Tls = 1,
    Reality = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireNetwork {
    Tcp = 6,
    Udp = 17,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum WireAction {
    PhysicalStatic = 1,
    Chain = 2,
    DirectDynamic = 3,
    NoDial = 4,
}

/// Заимствованная DATA-проекция. Не выбирает actual mux branch и не даёт grant.
/// Конструктор закрыт: значения выводятся из тех же private typed fields.
pub struct BranchProjection<'a> {
    dial: Option<WireNetwork>,
    carrier: Option<WireNetwork>,
    active_stream: bool,
    action: WireAction,
    next_subject: Option<&'a str>,
}
impl BranchProjection<'_> {
    pub fn dial(&self) -> Option<WireNetwork> {
        self.dial
    }
    pub fn carrier(&self) -> Option<WireNetwork> {
        self.carrier
    }
    pub fn active_stream(&self) -> bool {
        self.active_stream
    }
    pub fn action(&self) -> WireAction {
        self.action
    }
    pub fn next_subject(&self) -> Option<&str> {
        self.next_subject
    }
}

// Все extension objects закрыты. Семантический validator P3 остаётся единственным
// источником правил protocol/reference/chain/resource, wire его не заменяет.
macro_rules! object {
    ($name:ident { $($(#[$attr:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        #[derive(Serialize, Deserialize)]
        #[serde(deny_unknown_fields, rename_all = "camelCase")]
        struct $name { $($(#[$attr])* #[serde(skip_serializing_if = "Option::is_none")] $field: Option<$ty>),* }
    }
}
#[derive(Serialize)]
#[serde(transparent)]
struct List<T, const N: usize = 32768>(Vec<T>);
impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for List<T, N> {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Bounded<T, const N: usize>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for Bounded<T, N> {
            type Value = List<T, N>;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded array")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Self::Value, A::Error> {
                let mut items = Vec::new();
                while items.len() < N {
                    match a.next_element()? {
                        Some(v) => items.push(v),
                        None => return Ok(List(items)),
                    }
                }
                if a.next_element::<de::IgnoredAny>()?.is_some() {
                    return Err(de::Error::custom("array budget"));
                }
                Ok(List(items))
            }
        }
        d.deserialize_seq(Bounded::<T, N>(PhantomData))
    }
}
object!(Graph { log: Log, inbounds: List<Inbound,16>, outbounds: List<Outbound,256>, routing: Routing, dns: Dns, observatory: Observatory });
object!(Log { loglevel: String });
object!(Inbound {
    tag: String,
    port: u64,
    listen: String,
    protocol: String,
    settings: InboundSettings,
    sniffing: Sniffing
});
object!(InboundSettings {
    udp: bool,
    auth: String
});
object!(Sniffing { enabled: bool, route_only: bool, dest_override: List<String> });
object!(Outbound {
    tag: String,
    protocol: Protocol,
    settings: Settings,
    stream_settings: Stream,
    mux: Mux,
    proxy_settings: Chain
});
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Protocol {
    Vless,
    Shadowsocks,
    Hysteria,
    Freedom,
    Blackhole,
    Dns,
}
object!(Settings { vnext: List<Next,1>, servers: List<Server,1>, address: String, port: u64, version: u64, domain_strategy: String });
object!(Next { address: String, port: u64, users: List<User,1> });
object!(User {
    id: String,
    encryption: String,
    flow: String
});
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Server {
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    uot: Option<bool>,
    #[serde(rename = "UoTVersion", skip_serializing_if = "Option::is_none")]
    uot_version: Option<u64>,
}
object!(Stream {
    network: String,
    security: String,
    tcp_settings: Empty,
    grpc_settings: Grpc,
    xhttp_settings: Xhttp,
    hysteria_settings: Hysteria,
    tls_settings: Tls,
    reality_settings: Reality,
    finalmask: Mask
});
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
object!(Grpc {
    service_name: String,
    authority: String,
    multi_mode: bool,
    mode: bool
});
object!(Xhttp {
    mode: String,
    host: String,
    path: String,
    extra: Extra
});
object!(Extra { xmux: Xmux });
object!(Xmux {
    max_connections: u64
});
object!(Hysteria {
    version: u64,
    auth: String
});
object!(Tls { server_name: String, enable_session_resumption: bool, fingerprint: String, alpn: List<String>, allow_insecure: bool });
object!(Reality {
    server_name: String,
    public_key: String,
    short_id: String,
    fingerprint: String
});
object!(Mask { tcp: List<MaskEntry>, quic_params: Quic });
object!(MaskEntry {
    r#type: String,
    settings: MaskSettings
});
object!(MaskSettings { clients: List<List<Packet>>, servers: List<List<Packet>> });
object!(Packet {
    r#type: String,
    packet: String,
    rand: u64
});
object!(Quic {
    congestion: String,
    bbr_profile: String,
    #[serde(rename = "disablePathMTUDiscovery")]
    disable_path_mtu_discovery: bool
});
object!(Mux {
    enabled: bool,
    concurrency: i64,
    xudp_concurrency: u64,
    #[serde(rename = "xudpProxyUDP443")]
    xudp_proxy_udp443: String
});
object!(Chain {
    tag: String,
    transport_layer: bool
});
object!(Routing { domain_strategy: String, rules: List<Rule,2048>, balancers: List<Balancer> });
object!(Rule { r#type: String, inbound_tag: List<String>, outbound_tag: String, balancer_tag: String, domain: List<String>, ip: List<String>, port: String, network: String });
object!(Balancer { tag: String, selector: List<String>, strategy: Strategy, fallback_tag: String });
object!(Strategy { r#type: String });
object!(Dns { hosts: BTreeMap<String,String>, servers: List<DnsServer>, query_strategy: String, disable_fallback_if_match: bool, disable_fallback: bool, disable_cache: bool, tag: String });
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum DnsServer {
    Address(String),
    Scoped(ScopedDns),
}
object!(ScopedDns { address: String, tag: String, domains: List<String>, skip_fallback: bool, final_query: bool, port: u64 });
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Observatory {
    #[serde(rename = "probeURL", skip_serializing_if = "Option::is_none")]
    probe_url_upper: Option<String>,
    #[serde(rename = "probeUrl", skip_serializing_if = "Option::is_none")]
    probe_url: Option<String>,
    #[serde(rename = "probeInterval", skip_serializing_if = "Option::is_none")]
    interval: Option<String>,
    #[serde(rename = "subjectSelector", skip_serializing_if = "Option::is_none")]
    subjects: Option<List<String>>,
    #[serde(rename = "enableConcurrency", skip_serializing_if = "Option::is_none")]
    concurrency: Option<bool>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    graph: Graph,
}

/// Закрытый typed graph; Debug намеренно скрывает credentials.
pub struct ProfileIntent {
    wire: Envelope,
}
impl fmt::Debug for ProfileIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProfileIntent(<скрыто>)")
    }
}
impl ProfileIntent {
    /// Проверка alias ownership без повторной компиляции/генерации credentials.
    pub fn validate_ingress_mapping(&self, runtime: &OwnedRuntimePlan) -> Result<(), Error> {
        let inputs = self
            .wire
            .graph
            .inbounds
            .as_ref()
            .map(|i| i.0.as_slice())
            .unwrap_or(&[]);
        if inputs.len() != runtime.ingress_mappings().count() {
            return Err(Error::Ownership);
        }
        let mut occupied: [Option<&Inbound>; 2] = [None, None];
        if let Some(dns) = self.wire.graph.dns.as_ref() {
            let reserved = |tag: Option<&str>| {
                tag.is_some_and(|tag| tag.starts_with("yonik-owned-") || tag == "system-tun")
            };
            if reserved(dns.tag.as_deref())
                || dns.servers.as_ref().is_some_and(|servers| {
                    servers.0.iter().any(
                    |server| matches!(server,DnsServer::Scoped(s) if reserved(s.tag.as_deref())),
                )
                })
            {
                return Err(Error::Ownership);
            }
        }
        for input in inputs {
            let tag = input.tag.as_deref().ok_or(Error::Ownership)?;
            let owned = runtime
                .ingress_mappings()
                .find(|(name, _)| *name == tag)
                .map(|(_, o)| o)
                .ok_or(Error::Ownership)?;
            if owned == super::OwnedIngress::System && !runtime.is_system() {
                return Err(Error::Ownership);
            }
            let index = usize::from(owned == super::OwnedIngress::System);
            if let Some(previous) = occupied[index] {
                // Сравнение borrowed typed fields, без native JSON reconstruction.
                let a = previous.sniffing.as_ref();
                let b = input.sniffing.as_ref();
                if a.map(|s| (s.enabled, s.route_only)) != b.map(|s| (s.enabled, s.route_only))
                    || a.and_then(|s| s.dest_override.as_ref().map(|l| &l.0))
                        != b.and_then(|s| s.dest_override.as_ref().map(|l| &l.0))
                {
                    return Err(Error::Ownership);
                }
                for rule in self
                    .wire
                    .graph
                    .routing
                    .as_ref()
                    .and_then(|r| r.rules.as_ref())
                    .map(|r| r.0.as_slice())
                    .unwrap_or(&[])
                {
                    let tags = rule
                        .inbound_tag
                        .as_ref()
                        .map(|t| t.0.as_slice())
                        .unwrap_or(&[]);
                    if tags
                        .iter()
                        .any(|t| Some(t.as_str()) == previous.tag.as_deref())
                        != tags.iter().any(|t| t == tag)
                    {
                        return Err(Error::Ownership);
                    }
                }
            }
            occupied[index] = Some(input);
            let collision = |name: Option<&str>| name == Some(tag);
            if let Some(dns) = self.wire.graph.dns.as_ref() {
                if collision(dns.tag.as_deref()) || dns.servers.as_ref().is_some_and(|servers|servers.0.iter().any(|server|matches!(server,DnsServer::Scoped(s) if collision(s.tag.as_deref())))) {return Err(Error::Ownership);}
            }
        }
        Ok(())
    }
    /// Разрешённые native branches: bit0 normal, bit1 outbound mux.
    /// None port означает объединение actual решений для port443 и остальных.
    pub fn branch_mask(
        &self,
        subject: &str,
        input: WireNetwork,
        port: Option<u16>,
    ) -> Result<u8, Error> {
        let outbound = self.outbound(subject)?;
        let Some(mux) = outbound.mux.as_ref().filter(|m| m.enabled == Some(true)) else {
            return Ok(1);
        };
        let selected = if input == WireNetwork::Udp && mux.xudp_concurrency.unwrap_or(0) > 0
            || mux.concurrency.unwrap_or(0) >= 0
        {
            2
        } else {
            1
        };
        if input != WireNetwork::Udp {
            return Ok(selected);
        }
        let at443 = match mux.xudp_proxy_udp443.as_deref().unwrap_or("") {
            "" | "reject" => 0,
            "skip" => 1,
            _ => selected,
        };
        Ok(match port {
            Some(443) => at443,
            Some(_) => selected,
            None => selected | at443,
        })
    }
    pub fn proxy_kind(&self, subject: &str) -> Result<u8, Error> {
        let o = self.outbound(subject)?;
        Ok(match o.protocol.as_ref().ok_or(Error::Schema)? {
            Protocol::Vless => 1,
            Protocol::Shadowsocks => {
                let method = o
                    .settings
                    .as_ref()
                    .and_then(|s| s.servers.as_ref())
                    .and_then(|s| s.0.first())
                    .and_then(|s| s.method.as_deref())
                    .ok_or(Error::Schema)?;
                if method.starts_with("2022-") { 3 } else { 2 }
            }
            Protocol::Hysteria => 4,
            Protocol::Freedom => 5,
            Protocol::Blackhole => 6,
            Protocol::Dns => 7,
        })
    }
    /// Вычисляет P→D→C. При mux_worker вход proxy синтетический TCP;
    /// caller обязан отдельно доказать actual native mux decision.
    pub fn project_branch(
        &self,
        subject: &str,
        input: WireNetwork,
        mux_worker: bool,
    ) -> Result<BranchProjection<'_>, Error> {
        let outbound = self.outbound(subject)?;
        let protocol = outbound.protocol.as_ref().ok_or(Error::Schema)?;
        if matches!(protocol, Protocol::Blackhole | Protocol::Dns) {
            return Ok(BranchProjection {
                dial: None,
                carrier: None,
                active_stream: false,
                action: WireAction::NoDial,
                next_subject: None,
            });
        }
        let input = if mux_worker { WireNetwork::Tcp } else { input };
        let dial = match protocol {
            Protocol::Vless | Protocol::Hysteria => WireNetwork::Tcp,
            _ => input,
        };
        let (kind, security) = self.transport_kind(subject)?;
        let stream = outbound.stream_settings.as_ref();
        let exact_h3 = stream
            .and_then(|s| s.tls_settings.as_ref())
            .and_then(|tls| tls.alpn.as_ref())
            .is_some_and(|alpn| alpn.0.len() == 1 && alpn.0[0] == "h3");
        let carrier = if dial == WireNetwork::Udp
            || matches!(protocol, Protocol::Hysteria)
            || kind == WireTransportKind::Hysteria
            || (kind == WireTransportKind::Xhttp && security == WireSecurity::Tls && exact_h3)
        {
            WireNetwork::Udp
        } else {
            WireNetwork::Tcp
        };
        let next_subject = outbound
            .proxy_settings
            .as_ref()
            .and_then(|c| c.tag.as_deref());
        let action = if next_subject.is_some() {
            WireAction::Chain
        } else if matches!(protocol, Protocol::Freedom) {
            WireAction::DirectDynamic
        } else {
            WireAction::PhysicalStatic
        };
        Ok(BranchProjection {
            dial: Some(dial),
            carrier: Some(carrier),
            active_stream: dial == WireNetwork::Tcp,
            action,
            next_subject,
        })
    }
    pub fn decode(wire: &str) -> Result<Self, Error> {
        if wire.len() > MAX_INTENT_BYTES {
            return Err(Error::Budget);
        }
        let mut decoder = serde_json::Deserializer::from_str(wire);
        Scan(0)
            .deserialize(&mut decoder)
            .map_err(|_| Error::Schema)?;
        decoder.end().map_err(|_| Error::Schema)?;
        let wire: Envelope = serde_json::from_str(wire).map_err(|_| Error::Schema)?;
        if wire.version != 1 {
            return Err(Error::Schema);
        }
        let intent = Self { wire };
        intent.validate()?;
        Ok(intent)
    }
    pub fn from_profile(profile: &NativeProfile) -> Result<Self, Error> {
        let graph = super::validate_profile(profile)?;
        let graph = serde_json::from_value(graph.value).map_err(|_| Error::Schema)?;
        Ok(Self {
            wire: Envelope { version: 1, graph },
        })
    }
    pub fn write_sensitive(&self, writer: impl Write) -> Result<(), Error> {
        serde_json::to_writer(Limited { writer, bytes: 0 }, &self.wire).map_err(|_| Error::Budget)
    }
    fn profile(&self) -> Result<NativeProfile, Error> {
        let mut bytes = Vec::new();
        serde_json::to_writer(
            Limited {
                writer: &mut bytes,
                bytes: 0,
            },
            &self.wire.graph,
        )
        .map_err(|_| Error::Budget)?;
        let mut report = yonik_import::import_profiles(bytes).map_err(|_| Error::Schema)?;
        match report.entries.pop() {
            Some(ProfileEntry::Xray(p)) if report.entries.is_empty() => Ok(p),
            _ => Err(Error::Schema),
        }
    }
    pub fn validate(&self) -> Result<ValidatedGraph, Error> {
        super::validate_profile(&self.profile()?)
    }
    pub fn compile_system(
        &self,
        runtime: &OwnedRuntimePlan,
    ) -> Result<CompiledProfileSystem, Error> {
        super::compile_profile_system(&self.profile()?, runtime)
    }
    pub fn compile_local(
        &self,
        runtime: &OwnedRuntimePlan,
    ) -> Result<crate::CompiledConfig, Error> {
        super::compile_profile_local(&self.profile()?, runtime)
    }
    fn outbound(&self, subject: &str) -> Result<&Outbound, Error> {
        self.wire
            .graph
            .outbounds
            .as_ref()
            .and_then(|outbounds| {
                outbounds
                    .0
                    .iter()
                    .find(|o| o.tag.as_deref() == Some(subject))
            })
            .ok_or(Error::Reference)
    }
    pub fn transport_kind(
        &self,
        subject: &str,
    ) -> Result<(WireTransportKind, WireSecurity), Error> {
        let stream = self.outbound(subject)?.stream_settings.as_ref();
        let kind = match stream.and_then(|s| s.network.as_deref()).unwrap_or("tcp") {
            "tcp" => WireTransportKind::Tcp,
            "grpc" => WireTransportKind::Grpc,
            "xhttp" => WireTransportKind::Xhttp,
            "hysteria" => WireTransportKind::Hysteria,
            _ => return Err(Error::UnsupportedTransport),
        };
        let security = match stream.and_then(|s| s.security.as_deref()).unwrap_or("none") {
            "none" => WireSecurity::None,
            "tls" => WireSecurity::Tls,
            "reality" => WireSecurity::Reality,
            _ => return Err(Error::Schema),
        };
        Ok((kind, security))
    }
    /// Canonical P5STRM01 bytes для fingerprint. Не native config и не authority.
    pub fn write_transport_sensitive(
        &self,
        subject: &str,
        writer: impl Write,
    ) -> Result<(), Error> {
        let (kind, security) = self.transport_kind(subject)?;
        let outbound = self.outbound(subject)?;
        let mut writer = Limited { writer, bytes: 0 };
        writer.write_all(b"P5STRM01").map_err(|_| Error::Budget)?;
        writer
            .write_all(&[kind as u8, security as u8])
            .map_err(|_| Error::Budget)?;
        outbound
            .stream_settings
            .canonical(&mut writer)
            .map_err(|_| Error::Budget)?;
        outbound
            .mux
            .canonical(&mut writer)
            .map_err(|_| Error::Budget)
    }
}
trait Canonical {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()>;
}
impl<T: Canonical> Canonical for Option<T> {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&[u8::from(self.is_some())])?;
        if let Some(value) = self {
            value.canonical(w)?;
        }
        Ok(())
    }
}
impl Canonical for String {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&(self.len() as u32).to_be_bytes())?;
        w.write_all(self.as_bytes())
    }
}
impl Canonical for bool {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&[u8::from(*self)])
    }
}
impl Canonical for u64 {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&self.to_be_bytes())
    }
}
impl Canonical for i64 {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&self.to_be_bytes())
    }
}
impl<T: Canonical, const N: usize> Canonical for List<T, N> {
    fn canonical(&self, w: &mut impl Write) -> io::Result<()> {
        w.write_all(&(self.0.len() as u32).to_be_bytes())?;
        for item in &self.0 {
            item.canonical(w)?;
        }
        Ok(())
    }
}
macro_rules! canonical_object { ($name:ident: $($field:ident),*) => {
    impl Canonical for $name { fn canonical(&self,w:&mut impl Write)->io::Result<()> { $(self.$field.canonical(w)?;)* Ok(()) } }
} }
canonical_object!(Stream: network,security,tcp_settings,grpc_settings,xhttp_settings,hysteria_settings,tls_settings,reality_settings,finalmask);
impl Canonical for Empty {
    fn canonical(&self, _: &mut impl Write) -> io::Result<()> {
        Ok(())
    }
}
canonical_object!(Grpc: service_name,authority,multi_mode,mode);
canonical_object!(Xhttp: mode,host,path,extra);
canonical_object!(Extra: xmux);
canonical_object!(Xmux: max_connections);
canonical_object!(Hysteria: version,auth);
canonical_object!(Tls: server_name,enable_session_resumption,fingerprint,alpn,allow_insecure);
canonical_object!(Reality: server_name,public_key,short_id,fingerprint);
canonical_object!(Mask: tcp,quic_params);
canonical_object!(MaskEntry: r#type,settings);
canonical_object!(MaskSettings: clients,servers);
canonical_object!(Packet: r#type,packet,rand);
canonical_object!(Quic: congestion,bbr_profile,disable_path_mtu_discovery);
canonical_object!(Mux: enabled,concurrency,xudp_concurrency,xudp_proxy_udp443);
struct Limited<W> {
    writer: W,
    bytes: usize,
}
impl<W: Write> Write for Limited<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let total = self
            .bytes
            .checked_add(bytes.len())
            .filter(|n| *n <= MAX_INTENT_BYTES)
            .ok_or_else(|| io::Error::other("intent budget"))?;
        let written = self.writer.write(bytes)?;
        self.bytes = total - (bytes.len() - written);
        Ok(written)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

// Первый проход не строит Value, typed arrays или строки значений. Запрещает
// дубликаты/NULL/глубину до materialization; второй проход закрывает field/type
// grammar, проверяет bounded sequences до следующего элемента и unknown fields
// до чтения их значения. Семантическая проверка — затем неизменённый P3.
struct Scan(usize);
impl<'de> DeserializeSeed<'de> for Scan {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        if self.0 > 64 {
            return Err(de::Error::custom("depth budget"));
        }
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Scan {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("closed intent")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        let mut count = 0usize;
        while a.next_element_seed(Scan(self.0 + 1))?.is_some() {
            count += 1;
            if count > 32768 {
                return Err(de::Error::custom("array budget"));
            }
        }
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        while let Some(key) = a.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(de::Error::custom("duplicate field"));
            }
            a.next_value_seed(Scan(self.0 + 1))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_mux_decision_matches_disabled_xudp_and_port443_paths() {
        for (mux, tcp, udp, at443) in [
            (
                serde_json::json!({"enabled":false,"concurrency":0,"xudpProxyUDP443":"reject"}),
                1,
                1,
                1,
            ),
            (serde_json::json!({"enabled":true,"concurrency":0}), 2, 2, 0),
            (
                serde_json::json!({"enabled":true,"concurrency":-1}),
                1,
                1,
                0,
            ),
            (
                serde_json::json!({"enabled":true,"concurrency":-1,"xudpConcurrency":8}),
                1,
                2,
                0,
            ),
            (
                serde_json::json!({"enabled":true,"concurrency":0,"xudpProxyUDP443":"skip"}),
                2,
                3,
                1,
            ),
            (
                serde_json::json!({"enabled":true,"concurrency":0,"xudpProxyUDP443":"reject"}),
                2,
                2,
                0,
            ),
        ] {
            let wire = serde_json::json!({"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","mux":mux}]}});
            let intent = ProfileIntent::decode(&wire.to_string()).unwrap();
            assert_eq!(
                intent.branch_mask("x", WireNetwork::Tcp, None).unwrap(),
                tcp
            );
            assert_eq!(
                intent.branch_mask("x", WireNetwork::Udp, None).unwrap(),
                udp
            );
            assert_eq!(
                intent
                    .branch_mask("x", WireNetwork::Udp, Some(443))
                    .unwrap(),
                at443
            );
            assert_eq!(
                intent.branch_mask("x", WireNetwork::Udp, Some(80)).unwrap(),
                if udp == 3 { 2 } else { udp }
            );
        }
    }
    #[test]
    fn closed_carrier_projection_preserves_raw_udp_and_exact_h3() {
        let wire = serde_json::json!({"version":1,"graph":{"outbounds":[
            {"tag":"ss","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.1","port":443,"method":"aes-128-gcm","password":"fixture"}]},"streamSettings":{"network":"grpc"}},
            {"tag":"v","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.2","port":443,"users":[{"id":"00000000-0000-0000-0000-000000000001","encryption":"none"}]}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h3"]}}}
        ]}});
        let intent = ProfileIntent::decode(&wire.to_string()).unwrap();
        let ss = intent
            .project_branch("ss", WireNetwork::Udp, false)
            .unwrap();
        assert_eq!(ss.dial(), Some(WireNetwork::Udp));
        assert_eq!(ss.carrier(), Some(WireNetwork::Udp));
        assert!(!ss.active_stream());
        let v = intent.project_branch("v", WireNetwork::Udp, false).unwrap();
        assert_eq!(v.dial(), Some(WireNetwork::Tcp));
        assert_eq!(v.carrier(), Some(WireNetwork::Udp));
        assert!(v.active_stream());
        assert_eq!(v.action(), WireAction::PhysicalStatic);
    }
    #[test]
    fn closed_projection_keeps_chain_carrier_separate_from_original_input() {
        let wire = serde_json::json!({"version":1,"graph":{"outbounds":[
            {"tag":"a","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.1","port":443,"method":"aes-128-gcm","password":"fixture"}]},"streamSettings":{"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h3","h2"]}},"proxySettings":{"tag":"b","transportLayer":true}},
            {"tag":"b","protocol":"shadowsocks","settings":{"servers":[{"address":"192.0.2.2","port":443,"method":"aes-128-gcm","password":"fixture"}]}},
            {"tag":"direct","protocol":"freedom"},
            {"tag":"drop","protocol":"blackhole"}
        ]}});
        let intent = ProfileIntent::decode(&wire.to_string()).unwrap();
        let normal = intent.project_branch("a", WireNetwork::Udp, false).unwrap();
        assert_eq!(normal.action(), WireAction::Chain);
        assert_eq!(normal.next_subject(), Some("b"));
        assert_eq!(normal.carrier(), Some(WireNetwork::Udp));
        let worker = intent.project_branch("a", WireNetwork::Udp, true).unwrap();
        assert_eq!(worker.dial(), Some(WireNetwork::Tcp));
        assert_eq!(worker.carrier(), Some(WireNetwork::Tcp));
        let next = intent
            .project_branch("b", worker.carrier().unwrap(), false)
            .unwrap();
        assert_eq!(next.action(), WireAction::PhysicalStatic);
        assert_eq!(
            intent
                .project_branch("direct", WireNetwork::Tcp, false)
                .unwrap()
                .action(),
            WireAction::DirectDynamic
        );
        assert_eq!(next.dial(), Some(WireNetwork::Tcp));
        let drop = intent
            .project_branch("drop", WireNetwork::Tcp, false)
            .unwrap();
        assert_eq!(drop.action(), WireAction::NoDial);
        assert_eq!(drop.dial(), None);
        assert_eq!(drop.carrier(), None);
        assert!(!drop.active_stream());
        assert!(
            intent
                .project_branch("missing", WireNetwork::Tcp, false)
                .is_err()
        );
    }
    #[test]
    fn typed_seven_shapes_roundtrip_through_closed_validation() {
        let fixtures: Vec<serde_json::Value> = serde_json::from_str(include_str!(
            "../../../../tests/fixtures/xray-full-profile-native-schema.json"
        ))
        .unwrap();
        for fixture in fixtures {
            let report =
                yonik_import::import_profiles(serde_json::to_vec(&fixture).unwrap()).unwrap();
            let ProfileEntry::Xray(profile) = &report.entries[0] else {
                panic!("native fixture")
            };
            let intent = ProfileIntent::from_profile(profile).unwrap();
            let mut bytes = Vec::new();
            intent.write_sensitive(&mut bytes).unwrap();
            let decoded = ProfileIntent::decode(std::str::from_utf8(&bytes).unwrap()).unwrap();
            let original = super::super::validate_profile(profile).unwrap();
            for subject in original.subjects() {
                let mut before = Vec::new();
                let mut after = Vec::new();
                intent
                    .write_transport_sensitive(subject, &mut before)
                    .unwrap();
                decoded
                    .write_transport_sensitive(subject, &mut after)
                    .unwrap();
                assert_eq!(before, after);
            }
            assert_eq!(decoded.validate().unwrap().value, original.value);
        }
    }
    #[test]
    fn wire_rejects_unknown_duplicate_null_wrong_version_and_reference() {
        let minimal = serde_json::json!({"version":1,"graph":{"outbounds":[{"tag":"direct","protocol":"freedom"}]}});
        assert!(ProfileIntent::decode(&minimal.to_string()).is_ok());
        for bad in [
            r#"{"version":1,"version":1,"graph":{"outbounds":[]}}"#.to_owned(),
            r#"{"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","settings":{"path":"/tmp/x"}}]}}"#.to_owned(),
            r#"{"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","settings":null}]}}"#.to_owned(),
            r#"{"version":2,"graph":{"outbounds":[{"tag":"x","protocol":"freedom"}]}}"#.to_owned(),
            r#"{"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","proxySettings":{"tag":"missing","transportLayer":true}}]}}"#.to_owned(),
            format!("{} trailing",minimal),
            " ".repeat(MAX_INTENT_BYTES+1),
            format!("{}0{}", "[".repeat(65),"]".repeat(65)),
        ] { assert!(ProfileIntent::decode(&bad).is_err()); }
    }
    #[test]
    fn wire_preserves_provider_dns_absence_and_empty_containers() {
        for dns in [
            None,
            Some(serde_json::json!({})),
            Some(serde_json::json!({"servers":[]})),
        ] {
            let mut graph = serde_json::json!({"outbounds":[{"tag":"x","protocol":"freedom"}]});
            if let Some(dns) = dns {
                graph["dns"] = dns;
            }
            let intent =
                ProfileIntent::decode(&serde_json::json!({"version":1,"graph":graph}).to_string())
                    .unwrap();
            assert_eq!(intent.validate().unwrap().value, graph);
            assert_eq!(
                intent.validate().unwrap().egress().system_resolvers().len(),
                1
            );
        }
    }
    #[test]
    fn transport_canonical_golden_and_typed_field_sensitivity() {
        let direct = r#"{"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom"}]}}"#;
        let intent = ProfileIntent::decode(direct).unwrap();
        let mut bytes = Vec::new();
        intent.write_transport_sensitive("x", &mut bytes).unwrap();
        assert_eq!(bytes, [b"P5STRM01".as_slice(), &[1, 0, 0, 0]].concat());
        assert!(
            intent
                .write_transport_sensitive("missing", Vec::new())
                .is_err()
        );
        let base = serde_json::json!({"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","streamSettings":{"network":"grpc","grpcSettings":{"serviceName":"a","mode":false}},"mux":{"concurrency":-1}}]}});
        let intent = ProfileIntent::decode(&base.to_string()).unwrap();
        let mut before = Vec::new();
        intent.write_transport_sensitive("x", &mut before).unwrap();
        for (pointer, value) in [
            (
                "/graph/outbounds/0/streamSettings/grpcSettings/serviceName",
                serde_json::json!("b"),
            ),
            ("/graph/outbounds/0/mux/concurrency", serde_json::json!(1)),
        ] {
            let mut changed = base.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            let intent = ProfileIntent::decode(&changed.to_string()).unwrap();
            let mut after = Vec::new();
            intent.write_transport_sensitive("x", &mut after).unwrap();
            assert_ne!(before, after);
        }
    }
    #[test]
    fn transport_exact_bytes_cover_utf8_signed_mux_and_nested_packets() {
        // Golden выписаны из P5STRM01 layout, без вызова production encoder
        // для ожидаемых значений. Length у строк считает UTF-8 bytes.
        for (stream, mux, expected) in [
            (
                serde_json::json!({"network":"grpc","grpcSettings":{"serviceName":"я","mode":false}}),
                Some(serde_json::json!({"concurrency":-1})),
                "50355354524d30310200010100000004677270630000010100000002d18f000001000000000000010001ffffffffffffffff0000",
            ),
            (
                serde_json::json!({"network":"tcp","finalmask":{"tcp":[{"type":"header-custom","settings":{"clients":[[{"type":"str","packet":"я"},{"type":"hex","packet":"ff"},{"rand":3}]],"servers":[]}}]}}),
                None,
                "50355354524d3031010001010000000374637000000000000000010100000001010000000d6865616465722d637573746f6d0101000000010000000301000000037374720100000002d18f0001000000036865780100000002666600000001000000000000000301000000000000",
            ),
        ] {
            let mut outbound =
                serde_json::json!({"tag":"x","protocol":"freedom","streamSettings":stream});
            if let Some(mux) = mux {
                outbound["mux"] = mux;
            }
            let wire = serde_json::json!({"version":1,"graph":{"outbounds":[outbound]}});
            let intent = ProfileIntent::decode(&wire.to_string()).unwrap();
            let mut actual = Vec::new();
            intent.write_transport_sensitive("x", &mut actual).unwrap();
            let expected: Vec<u8> = expected
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn explicit_empty_stream_has_a_distinct_exact_golden() {
        let wire = r#"{"version":1,"graph":{"outbounds":[{"tag":"x","protocol":"freedom","streamSettings":{}}]}}"#;
        let intent = ProfileIntent::decode(wire).unwrap();
        let mut bytes = Vec::new();
        intent.write_transport_sensitive("x", &mut bytes).unwrap();
        // kind/security, Stream Some, девять None полей, Mux None.
        assert_eq!(
            bytes,
            [
                b"P5STRM01".as_slice(),
                &[1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            ]
            .concat()
        );
    }
    #[test]
    fn outbound_count_is_bounded_in_typed_decode() {
        let outbounds: Vec<_> = (0..257)
            .map(|i| serde_json::json!({"tag":format!("s{i}"),"protocol":"freedom"}))
            .collect();
        assert!(
            ProfileIntent::decode(
                &serde_json::json!({"version":1,"graph":{"outbounds":outbounds}}).to_string()
            )
            .is_err()
        );
    }
}
