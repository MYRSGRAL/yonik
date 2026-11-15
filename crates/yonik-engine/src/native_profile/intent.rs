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
