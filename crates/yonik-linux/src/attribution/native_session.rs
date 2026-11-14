//! Custody и переходы frozen ABI. Caller FD и окружение не создают authority.
use super::{
    broker::{Broker, Lookup, Unavailable},
    native_wire::{self as wire, Header, Kind, Malformed, Sequence},
};
use crate::managed_network::tun::BoundTun;
use std::{os::fd::OwnedFd, sync::Arc};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Hello,
    Features,
    Ack,
    Active,
    Closed,
}

/// Не имеет публичного конструктора: только verified helper bootstrap может
/// передать уже привязанный TUN и собственные endpoint роли.
pub struct Session {
    phase: Phase,
    epoch: u64,
    digest: [u8; 32],
    nonce: [u8; 32],
    session: [u8; 16],
    generation: u64,
    invocation: [u8; 16],
    app_required: bool,
    roles: Option<Roles>,
    sequence: Sequence,
    scope: Option<crate::helper::native_bootstrap::RuntimeScopeStamp>,
}
struct Roles {
    tun: TunRole,
    worker: OwnedFd,
    broker: Option<Broker>,
}

// Production хранит только helper-owned queue; raw FD доступен лишь fixture.
#[cfg_attr(not(test), allow(dead_code))]
enum TunRole {
    Bound(Arc<BoundTun>),
    #[cfg(test)]
    Fixture {
        fd: Arc<OwnedFd>,
        metadata: [u8; 32],
    },
}
impl TunRole {
    fn metadata(&self) -> Result<[u8; 32], Malformed> {
        match self {
            Self::Bound(bound) => bound.attach_metadata().map_err(|_| Malformed),
            #[cfg(test)]
            Self::Fixture { metadata, .. } => Ok(*metadata),
        }
    }
    fn duplicate(&self) -> Result<OwnedFd, Malformed> {
        match self {
            Self::Bound(bound) => bound.duplicate_for_attach().map_err(|_| Malformed),
            #[cfg(test)]
            Self::Fixture { fd, .. } => {
                rustix::io::fcntl_dupfd_cloexec(fd.as_ref(), 0).map_err(|_| Malformed)
            }
        }
    }
}

impl Session {
    pub(crate) fn from_verified(
        role: crate::helper::native_bootstrap::SessionRole,
    ) -> Result<Self, Unavailable> {
        let (scope, queue, worker) = role.into_parts();
        scope.validate().map_err(|_| Unavailable::Authority)?;
        let lookup = super::broker::VerifiedLookupScope::verify(scope.fork_lookup())?;
        let broker = Broker::from_verified(lookup)?;
        let (nonce, session, generation, invocation, epoch, digest) = scope.context();
        Ok(Self {
            phase: Phase::Hello,
            epoch,
            digest,
            nonce,
            session,
            generation,
            invocation,
            app_required: true,
            roles: Some(Roles {
                tun: TunRole::Bound(queue),
                worker,
                broker: Some(broker),
            }),
            sequence: Sequence::default(),
            scope: Some(scope),
        })
    }

    /// Пока kernel/unit proof не может быть выпущен, raw caller входы
    /// безусловно отвергаются. Этот gate не принимает fd, env или proof bytes.
    pub fn verified_helper_bootstrap() -> Result<Self, Unavailable> {
        Err(Unavailable::Authority)
    }
    pub fn close(&mut self) {
        if let Some(scope) = self.scope.take() {
            scope.revoke();
        }
        self.phase = Phase::Closed;
        self.sequence.retire();
        if let Some(mut roles) = self.roles.take() {
            if let Some(broker) = roles.broker.as_mut() {
                broker.revoke();
            }
            drop(roles);
        }
    }
    /// EOF, timeout и transport error завершают все helper-owned роли.
    pub fn eof(&mut self) {
        self.close();
    }
    fn header(&self, frame: &[u8]) -> Result<Header, Malformed> {
        if let Some(scope) = &self.scope {
            scope.validate().map_err(|_| Malformed)?;
        }
        let header = Header::decode(frame, 0)?;
        if header.epoch != self.epoch || header.digest != self.digest || frame[64..96] != self.nonce
        {
            return Err(Malformed);
        }
        Ok(header)
    }
    fn frame(&self, kind: Kind) -> Result<Vec<u8>, Malformed> {
        if let Some(scope) = &self.scope {
            scope.validate().map_err(|_| Malformed)?;
        }
        let mut bytes = vec![0; kind.fixed_bytes().ok_or(Malformed)?];
        Header {
            kind,
            request_id: 0,
            epoch: self.epoch,
            digest: self.digest,
        }
        .write(&mut bytes)?;
        bytes[64..96].copy_from_slice(&self.nonce);
        Ok(bytes)
    }
    pub fn hello(&mut self) -> Result<Vec<u8>, Malformed> {
        let result = self.hello_inner();
        if result.is_err() {
            self.close();
        }
        result
    }
    fn hello_inner(&mut self) -> Result<Vec<u8>, Malformed> {
        if self.phase != Phase::Hello || self.roles.is_none() {
            return Err(Malformed);
        }
        let mut bytes = self.frame(Kind::Hello)?;
        bytes[96..112].copy_from_slice(&self.session);
        bytes[112..120].copy_from_slice(&self.generation.to_be_bytes());
        bytes[120..136].copy_from_slice(&self.invocation);
        bytes[136..140].copy_from_slice(&(wire::MAX_FRAME as u32).to_be_bytes());
        bytes[140..142].copy_from_slice(&1u16.to_be_bytes());
        bytes[144..152].copy_from_slice(&wire::OWNER_TTL_NS.to_be_bytes());
        bytes[152..160].copy_from_slice(&wire::BOOTSTRAP_NS.to_be_bytes());
        bytes[160..168].copy_from_slice(&wire::FEATURES.to_be_bytes());
        bytes[168..176].copy_from_slice(&u64::from(self.app_required).to_be_bytes());
        Header::decode(&bytes, 0)?;
        self.phase = Phase::Features;
        Ok(bytes)
    }
    /// ATTACH metadata предоставляется только resource owner. Ровно один
    /// duplicate создаётся здесь; при ошибке сессия целиком отзывается.
    pub fn attach(&mut self, features: &[u8]) -> Result<(Vec<u8>, OwnedFd), Malformed> {
        let result = self.attach_inner(features);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn attach_inner(&mut self, features: &[u8]) -> Result<(Vec<u8>, OwnedFd), Malformed> {
        if self.phase != Phase::Features || self.header(features)?.kind != Kind::Features {
            return Err(Malformed);
        }
        wire::selected_features(features, self.app_required)?;
        let mut bytes = self.frame(Kind::Attach)?;
        let roles = self.roles.as_ref().ok_or(Malformed)?;
        bytes[96..128].copy_from_slice(&roles.tun.metadata()?);
        Header::decode(&bytes, 1)?;
        let fd = roles.tun.duplicate()?;
        self.phase = Phase::Ack;
        Ok((bytes, fd))
    }
    pub fn acknowledge(&mut self, bytes: &[u8]) -> Result<(), Malformed> {
        if self.phase != Phase::Ack || self.header(bytes).map(|h| h.kind) != Ok(Kind::AttachAck) {
            self.close();
            return Err(Malformed);
        }
        self.phase = Phase::Active;
        Ok(())
    }
    /// Canonical tuple передаётся существующему app-UID broker, без caller PID.
    pub fn lookup(&mut self, bytes: &[u8]) -> Result<Lookup, Malformed> {
        let result = self.lookup_inner(bytes);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn lookup_inner(&mut self, bytes: &[u8]) -> Result<Lookup, Malformed> {
        if self.phase != Phase::Active {
            return Err(Malformed);
        }
        let header = self.header(bytes)?;
        if header.kind != Kind::Lookup {
            return Err(Malformed);
        }
        let flow = wire::lookup_flow(bytes)?;
        self.sequence.begin(header.request_id)?;
        let result = match self.roles.as_mut().and_then(|r| r.broker.as_mut()) {
            Some(broker) => broker.lookup(flow),
            None => Lookup::MechanismUnavailable(Unavailable::Authority),
        };
        self.sequence.complete(header.request_id)?;
        Ok(result)
    }
    fn lookup_and_project(
        &mut self,
        bytes: &[u8],
    ) -> Result<super::broker::ProjectedLookup, Malformed> {
        let result = (|| {
            if self.phase != Phase::Active {
                return Err(Malformed);
            }
            let header = self.header(bytes)?;
            if header.kind != Kind::Lookup {
                return Err(Malformed);
            }
            let flow = wire::lookup_flow(bytes)?;
            self.sequence.begin(header.request_id)?;
            let result = match self.roles.as_mut().and_then(|r| r.broker.as_mut()) {
                Some(broker) => broker.lookup_and_project(flow, self.epoch),
                None => super::broker::ProjectedLookup::Unavailable(Unavailable::Authority),
            };
            self.sequence.complete(header.request_id)?;
            Ok(result)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn revoke(&mut self, bytes: &[u8]) -> Result<(), Malformed> {
        let valid = self.header(bytes).map(|h| h.kind) == Ok(Kind::Revoke);
        self.close();
        if valid { Ok(()) } else { Err(Malformed) }
    }
}
// Транспорт не создаёт authority: Session по-прежнему выпускает только helper.
mod transport;
#[cfg(test)]
pub(crate) use transport::tests::bound_terminal_controls;
#[cfg(test)]
pub(super) use transport::tests::{cold_roundtrip, known_roundtrip};

impl Drop for Session {
    fn drop(&mut self) {
        self.close();
    }
}
impl Drop for Roles {
    fn drop(&mut self) {
        // shutdown затрагивает также уже выданные transport duplicates.
        let _shutdown = rustix::net::shutdown(&self.worker, rustix::net::Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    pub(super) fn metadata() -> [u8; 32] {
        let mut metadata = [0; 32];
        metadata[..4].copy_from_slice(&1u32.to_be_bytes());
        metadata[4..8].copy_from_slice(&1u32.to_be_bytes());
        metadata[8..12].copy_from_slice(&0x1001u32.to_be_bytes());
        metadata[12..16].copy_from_slice(&1500u32.to_be_bytes());
        metadata[16..20].copy_from_slice(b"tun0");
        metadata
    }
    pub(super) fn fixture() -> (Session, UnixStream) {
        let (worker, peer) = UnixStream::pair().unwrap();
        let tun = std::fs::File::open("/dev/null").unwrap();
        (
            Session {
                phase: Phase::Hello,
                epoch: 1,
                digest: [2; 32],
                nonce: [3; 32],
                session: [4; 16],
                generation: 1,
                invocation: [5; 16],
                app_required: false,
                roles: Some(Roles {
                    tun: TunRole::Fixture {
                        fd: Arc::new(tun.into()),
                        metadata: metadata(),
                    },
                    worker: worker.into(),
                    broker: None,
                }),
                scope: None,
                sequence: Sequence::new(),
            },
            peer,
        )
    }
    #[test]
    fn bootstrap_never_accepts_caller_authority() {
        assert!(matches!(
            Session::verified_helper_bootstrap(),
            Err(Unavailable::Authority)
        ));
    }
    #[test]
    fn closed_fixture_handshake_and_eof() {
        let (mut s, mut peer) = fixture();
        assert_eq!(
            Header::decode(&s.hello().unwrap(), 0).unwrap().kind,
            Kind::Hello
        );
        let mut features = s.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        let (attach, duplicate) = s.attach(&features).unwrap();
        assert_eq!(Header::decode(&attach, 1).unwrap().kind, Kind::Attach);
        drop(duplicate);
        let mut ack = s.frame(Kind::AttachAck).unwrap();
        ack[96..100].copy_from_slice(&1u32.to_be_bytes());
        s.acknowledge(&ack).unwrap();
        s.eof();
        assert!(s.roles.is_none());
        use std::io::Read;
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn attach_duplicate_and_close_preserve_original_owner() {
        use std::os::fd::AsRawFd;
        let (mut session, _) = fixture();
        let original = match &session.roles.as_ref().unwrap().tun {
            TunRole::Fixture { fd, .. } => Arc::clone(fd),
            _ => unreachable!(),
        };
        session.hello().unwrap();
        let mut features = session.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        let (_, duplicate) = session.attach(&features).unwrap();
        assert_ne!(duplicate.as_raw_fd(), original.as_raw_fd());
        assert!(
            rustix::io::fcntl_getfd(&duplicate)
                .unwrap()
                .contains(rustix::io::FdFlags::CLOEXEC)
        );
        session.close();
        assert_eq!(Arc::strong_count(&original), 1);
        assert!(rustix::io::fcntl_getfd(original.as_ref()).is_ok());
        drop(duplicate);
        assert!(rustix::io::fcntl_getfd(original.as_ref()).is_ok());
    }
    #[test]
    fn malformed_owner_metadata_closes_session_before_duplicate() {
        let (mut session, _) = fixture();
        if let TunRole::Fixture { metadata, .. } = &mut session.roles.as_mut().unwrap().tun {
            metadata[8..12].copy_from_slice(&0x5001u32.to_be_bytes());
        }
        session.hello().unwrap();
        let mut features = session.frame(Kind::Features).unwrap();
        features[96..104].copy_from_slice(&wire::FEATURES.to_be_bytes());
        features[104..112].copy_from_slice(&wire::OWNED_TUN.to_be_bytes());
        assert!(session.attach(&features).is_err());
        assert!(session.roles.is_none());
    }
    #[test]
    fn malformed_features_retire_and_release_descriptors() {
        let (mut s, mut peer) = fixture();
        s.hello().unwrap();
        assert!(s.attach(&[]).is_err());
        assert_eq!(s.phase, Phase::Closed);
        assert!(s.roles.is_none());
        use std::io::Read;
        assert_eq!(peer.read(&mut [0]).unwrap(), 0);
    }
    #[test]
    fn lookup_before_ack_and_bad_revoke_close_session() {
        let (mut s, _) = fixture();
        assert!(s.lookup(&[]).is_err());
        assert!(s.roles.is_none());
        let (mut s, _) = fixture();
        assert!(s.revoke(&[]).is_err());
        assert!(s.roles.is_none());
    }
    #[test]
    fn replay_and_foreign_identity_close_roles() {
        for foreign in [false, true] {
            let (mut s, _) = fixture();
            let hello = s.hello().unwrap();
            let mut bytes = hello;
            if foreign {
                bytes[24..32].copy_from_slice(&2u64.to_be_bytes());
            }
            assert!(s.acknowledge(&bytes).is_err());
            assert!(s.roles.is_none());
            assert!(s.hello().is_err());
        }
    }
}

#[cfg(test)]
mod consumer_fixture;
#[cfg(test)]
pub(crate) use consumer_fixture::run as bound_consumer_fixture;
