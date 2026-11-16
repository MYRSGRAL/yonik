//! Закрытый versioned sideband. Decode/manifest — DATA, не runtime authority.

use sha2::{Digest, Sha256};

pub(crate) const FRAME_LIMIT: usize = 65536;
const HEADER: usize = 128;
const NONE: u16 = u16::MAX;
pub(crate) const CONTROL_FD_LOCATOR: &str = "YONIK_PROFILE_CONTROL_FD";
pub(crate) const LAUNCH_FD_LOCATOR: &str = "YONIK_PROFILE_LAUNCH_FD";
pub(crate) const PEER_PIDFD_LOCATOR: &str = "YONIK_PROFILE_PEER_PIDFD";
pub(crate) const ASSET_ROOT_FD_LOCATOR: &str = "YONIK_PROFILE_ASSET_ROOT_FD";

/// DNS_V2 DATA preflight. Проверка bytes не является negotiation/authority.
#[expect(
    dead_code,
    reason = "Закрытый DATA codec API; issuer negotiation остаётся следующим milestone"
)]
pub(crate) mod dns_v2 {
    use super::{Error, Result};
    use sha2::{Digest, Sha256};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u16)]
    pub(crate) enum Operation {
        Reserve = 35,
        Reserved = 36,
        PhysicalAck = 37,
        LogicalBind = 38,
        LogicalAck = 39,
        Publish = 40,
        Published = 41,
        NumericAuthorize = 42,
        Append = 43,
        AppendAck = 44,
        Retire = 45,
        Retired = 46,
        Cancel = 47,
        Canceled = 48,
        PhysicalBind = 52,
        WaiterBind = 53,
        WaiterBound = 54,
        BundleAcquire = 55,
        BundleGranted = 56,
    }
    impl TryFrom<u16> for Operation {
        type Error = Error;
        fn try_from(n: u16) -> Result<Self> {
            Ok(match n {
                35 => Self::Reserve,
                36 => Self::Reserved,
                37 => Self::PhysicalAck,
                38 => Self::LogicalBind,
                39 => Self::LogicalAck,
                40 => Self::Publish,
                41 => Self::Published,
                42 => Self::NumericAuthorize,
                43 => Self::Append,
                44 => Self::AppendAck,
                45 => Self::Retire,
                46 => Self::Retired,
                47 => Self::Cancel,
                48 => Self::Canceled,
                52 => Self::PhysicalBind,
                53 => Self::WaiterBind,
                54 => Self::WaiterBound,
                55 => Self::BundleAcquire,
                56 => Self::BundleGranted,
                _ => return Err(Error::Schema),
            })
        }
    }
    impl Operation {
        pub(crate) fn is_reply(self) -> bool {
            matches!(
                self,
                Self::Reserved
                    | Self::PhysicalAck
                    | Self::LogicalAck
                    | Self::Published
                    | Self::AppendAck
                    | Self::Retired
                    | Self::Canceled
                    | Self::WaiterBound
                    | Self::BundleGranted
            )
        }
        pub(crate) fn rights(self) -> (usize, usize) {
            if self == Self::PhysicalBind {
                (1, 1)
            } else {
                (0, 0)
            }
        }
    }
    macro_rules! ids {
        ($($name:ident),+) => {$ (
            #[derive(Clone,Copy,Debug,PartialEq,Eq)]
            pub(crate) struct $name(std::num::NonZeroU64);
            impl $name {
                fn read(n:u64)->Result<Self> {id(n)?;Ok(Self(std::num::NonZeroU64::new(n).ok_or(Error::Reference)?))}
                pub(crate) fn get(self)->u64 {self.0.get()}
            }
        )+};
    }
    ids!(
        ReservationId,
        PhysicalResourceId,
        DnsBundleId,
        ExchangeId,
        TransportProofId,
        StubBindId,
        ProducerRRsetId,
        WaiterReceiptId,
        SourceObservationId
    );
    ids!(
        QueryId,
        ServiceGrantId,
        SourceFlowId,
        FlowRevision,
        ProofRevision,
        AppendSequence,
        RequestSequenceId
    );
    ids!(BundleRevision);
    macro_rules! view_id {
        ($kind:literal,$method:ident,$id:ident,$at:literal) => {
            impl View<'_, $kind> {
                pub(crate) fn $method(self) -> Result<$id> {
                    $id::read(n64(self.bytes, $at))
                }
            }
        };
    }
    view_id!(35, query, QueryId, 8);
    view_id!(35, bundle, DnsBundleId, 16);
    view_id!(35, grant, ServiceGrantId, 24);
    view_id!(35, source_flow, SourceFlowId, 32);
    view_id!(35, source_revision, FlowRevision, 40);
    view_id!(36, reservation, ReservationId, 8);
    view_id!(36, query, QueryId, 16);
    view_id!(36, bundle, DnsBundleId, 24);
    view_id!(37, reservation, ReservationId, 8);
    view_id!(37, query, QueryId, 24);
    view_id!(37, bundle, DnsBundleId, 32);
    view_id!(38, reservation, ReservationId, 8);
    view_id!(38, query, QueryId, 16);
    view_id!(38, bundle, DnsBundleId, 24);
    view_id!(38, exchange, ExchangeId, 32);
    view_id!(38, stub, StubBindId, 40);
    view_id!(39, exchange, ExchangeId, 8);
    view_id!(39, query, QueryId, 24);
    view_id!(39, bundle, DnsBundleId, 32);
    view_id!(39, revision, ProofRevision, 40);
    view_id!(40, query, QueryId, 12);
    view_id!(40, grant, ServiceGrantId, 20);
    view_id!(40, exchange, ExchangeId, 28);
    view_id!(40, proof, TransportProofId, 120);
    view_id!(40, revision, ProofRevision, 128);
    view_id!(41, exchange, ExchangeId, 16);
    view_id!(43, exchange, ExchangeId, 8);
    view_id!(43, proof, TransportProofId, 16);
    view_id!(43, revision, ProofRevision, 24);
    view_id!(43, sequence, AppendSequence, 32);
    view_id!(44, exchange, ExchangeId, 8);
    view_id!(44, proof, TransportProofId, 16);
    view_id!(44, sequence, AppendSequence, 24);
    view_id!(44, revision, ProofRevision, 32);
    view_id!(52, exchange_reservation, ReservationId, 128);
    view_id!(52, query, QueryId, 136);
    view_id!(52, bundle, DnsBundleId, 144);
    view_id!(52, physical_reservation, ReservationId, 152);
    view_id!(53, grant, ServiceGrantId, 24);
    view_id!(53, query, QueryId, 32);
    view_id!(53, source_flow, SourceFlowId, 40);
    view_id!(53, source_revision, FlowRevision, 48);
    view_id!(54, reservation, ReservationId, 24);
    view_id!(54, query, QueryId, 32);
    view_id!(55, grant, ServiceGrantId, 8);
    view_id!(55, query, QueryId, 16);
    view_id!(56, bundle, DnsBundleId, 8);
    view_id!(56, grant, ServiceGrantId, 16);
    view_id!(56, query, QueryId, 24);
    view_id!(56, revision, BundleRevision, 56);
    impl<'a> View<'a, 55> {
        pub(crate) fn renewal(self) -> Result<Option<(DnsBundleId, BundleRevision)>> {
            if n64(self.bytes, 32) == 0 {
                Ok(None)
            } else {
                Ok(Some((
                    DnsBundleId::read(n64(self.bytes, 32))?,
                    BundleRevision::read(n64(self.bytes, 64))?,
                )))
            }
        }
        pub(crate) fn base(self) -> &'a [u8] {
            &self.bytes[72..72 + usize::from(n16(self.bytes, 48))]
        }
        pub(crate) fn original(self) -> &'a [u8] {
            let start = 72 + usize::from(n16(self.bytes, 48));
            &self.bytes[start..start + usize::from(n16(self.bytes, 58))]
        }
        pub(crate) fn path(self) -> impl Iterator<Item = (u16, u8)> + 'a {
            let start = 72 + usize::from(n16(self.bytes, 48)) + usize::from(n16(self.bytes, 58));
            self.bytes[start..]
                .chunks_exact(4)
                .map(|row| (n16(row, 0), row[2]))
        }
    }
    macro_rules! closed_u8 {
        ($name:ident,$($variant:ident=$n:literal),+) => {
            #[derive(Clone,Copy,Debug,PartialEq,Eq)]
            pub(crate) enum $name {$($variant),+}
            impl TryFrom<u8> for $name {
                type Error=Error;
                fn try_from(n:u8)->Result<Self> {match n {$($n=>Ok(Self::$variant),)+_=>Err(Error::Schema)}}
            }
        };
    }
    closed_u8!(SourceKind, DnsWire = 1, HostsSnapshot = 2);
    closed_u8!(
        Purpose,
        ProviderQuery = 1,
        BootstrapDns = 2,
        BootstrapHosts = 3
    );
    closed_u8!(NumericUse, LogicalDestination = 1, PhysicalFirstHop = 2);
    closed_u8!(ParentClass, User = 1, Probe = 2, Dns = 3);
    closed_u8!(ReservationRole, Exchange = 1, Physical = 2, Waiter = 3);
    impl View<'_, 35> {
        pub(crate) fn role(self) -> Result<ReservationRole> {
            ReservationRole::try_from(self.bytes[2])
        }
        pub(crate) fn purpose(self) -> Result<Purpose> {
            Purpose::try_from(self.bytes[74])
        }
        pub(crate) fn source_kind(self) -> Result<SourceKind> {
            SourceKind::try_from(self.bytes[75])
        }
        pub(crate) fn parent_class(self) -> Result<ParentClass> {
            ParentClass::try_from(self.bytes[77])
        }
    }
    impl View<'_, 40> {
        pub(crate) fn purpose(self) -> Result<Purpose> {
            Purpose::try_from(self.bytes[136])
        }
        pub(crate) fn source_kind(self) -> Result<SourceKind> {
            SourceKind::try_from(self.bytes[137])
        }
    }
    impl View<'_, 42> {
        pub(crate) fn usage(self) -> Result<NumericUse> {
            NumericUse::try_from(self.bytes[14])
        }
        pub(crate) fn parent_class(self) -> Result<ParentClass> {
            ParentClass::try_from(self.bytes[15])
        }
    }
    impl View<'_, 54> {
        pub(crate) fn purpose(self) -> Result<Purpose> {
            Purpose::try_from(self.bytes[59])
        }
        pub(crate) fn source_kind(self) -> Result<SourceKind> {
            SourceKind::try_from(self.bytes[58])
        }
    }
    macro_rules! ack_views {
        ($($k:literal),+) => {$ (
            impl View<'_,$k> {pub(crate) fn status(self)->Result<super::Status> {super::Status::try_from(self.bytes[2])}}
        )+};
    }
    ack_views!(36, 37, 39, 41, 44, 46, 48, 54);
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Retirement {
        Resource(PhysicalResourceId),
        Proof(TransportProofId, ProofRevision),
    }
    impl View<'_, 45> {
        pub(crate) fn reference(self) -> Result<Retirement> {
            match self.bytes[2] {
                3 => Ok(Retirement::Resource(PhysicalResourceId::read(n64(
                    self.bytes, 8,
                ))?)),
                4 => Ok(Retirement::Proof(
                    TransportProofId::read(n64(self.bytes, 8))?,
                    ProofRevision::read(n64(self.bytes, 16))?,
                )),
                _ => Err(Error::Reference),
            }
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Cancellation {
        Request(RequestSequenceId),
        Exchange(ExchangeId),
        Resource(PhysicalResourceId),
        Proof(TransportProofId),
        Producer(ProducerRRsetId),
        Waiter(WaiterReceiptId),
        Reservation(ReservationId),
    }
    impl View<'_, 47> {
        pub(crate) fn reference(self) -> Result<Cancellation> {
            let n = n64(self.bytes, 8);
            Ok(match self.bytes[2] {
                1 => Cancellation::Request(RequestSequenceId::read(n)?),
                2 => Cancellation::Exchange(ExchangeId::read(n)?),
                3 => Cancellation::Resource(PhysicalResourceId::read(n)?),
                4 => Cancellation::Proof(TransportProofId::read(n)?),
                5 => Cancellation::Producer(ProducerRRsetId::read(n)?),
                6 => Cancellation::Waiter(WaiterReceiptId::read(n)?),
                7 => Cancellation::Reservation(ReservationId::read(n)?),
                _ => return Err(Error::Reference),
            })
        }
    }

    /// Immutable borrowed view: поля проверены до materialization, не authority.
    #[derive(Clone, Copy)]
    pub(crate) struct View<'a, const K: u16> {
        bytes: &'a [u8],
    }
    impl<'a, const K: u16> View<'a, K> {
        pub(crate) fn decode(bytes: &'a [u8]) -> Result<Self> {
            preflight(K, bytes)?;
            Ok(Self { bytes })
        }
        pub(crate) fn bytes(self) -> &'a [u8] {
            self.bytes
        }
        pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize> {
            let dst = out.get_mut(..self.bytes.len()).ok_or(Error::Bounds)?;
            dst.copy_from_slice(self.bytes);
            Ok(self.bytes.len())
        }
    }
    impl View<'_, 41> {
        pub(crate) fn producer(self) -> Result<ProducerRRsetId> {
            ProducerRRsetId::read(n64(self.bytes, 8))
        }
    }
    impl View<'_, 53> {
        pub(crate) fn reservation(self) -> Result<ReservationId> {
            ReservationId::read(n64(self.bytes, 8))
        }
        pub(crate) fn producer(self) -> Result<ProducerRRsetId> {
            ProducerRRsetId::read(n64(self.bytes, 16))
        }
    }
    impl View<'_, 54> {
        pub(crate) fn waiter(self) -> Result<WaiterReceiptId> {
            WaiterReceiptId::read(n64(self.bytes, 8))
        }
        pub(crate) fn producer(self) -> Result<ProducerRRsetId> {
            ProducerRRsetId::read(n64(self.bytes, 16))
        }
    }
    impl View<'_, 42> {
        pub(crate) fn waiter(self) -> Result<WaiterReceiptId> {
            WaiterReceiptId::read(n64(self.bytes, 4))
        }
    }
    impl View<'_, 37> {
        pub(crate) fn resource(self) -> Result<PhysicalResourceId> {
            PhysicalResourceId::read(n64(self.bytes, 16))
        }
    }
    impl View<'_, 39> {
        pub(crate) fn proof(self) -> Result<TransportProofId> {
            TransportProofId::read(n64(self.bytes, 16))
        }
    }
    impl<'a> View<'a, 40> {
        pub(crate) fn hosts(self) -> Result<Option<HostsView<'a>>> {
            if self.bytes[137] == 2 {
                Ok(Some(HostsView::decode(&self.bytes[144..])?))
            } else {
                Ok(None)
            }
        }
    }
    impl View<'_, 36> {
        pub(crate) fn observation(self) -> Result<SourceObservationId> {
            if self.bytes[60] != 3 || n64(self.bytes, 24) != 0 {
                return Err(Error::Reference);
            }
            SourceObservationId::read(n64(self.bytes, 32))
        }
        pub(crate) fn exchange(self) -> Result<ExchangeId> {
            if self.bytes[60] != 1 {
                return Err(Error::Reference);
            }
            ExchangeId::read(n64(self.bytes, 32))
        }
        pub(crate) fn parent_exchange_reservation(self) -> Result<ReservationId> {
            if self.bytes[60] != 2 {
                return Err(Error::Reference);
            }
            ReservationId::read(n64(self.bytes, 32))
        }
    }
    impl<'a> View<'a, 38> {
        pub(crate) fn resources(self) -> impl Iterator<Item = Result<PhysicalResourceId>> + 'a {
            self.bytes[64..]
                .chunks_exact(8)
                .map(|p| PhysicalResourceId::read(n64(p, 0)))
        }
    }
    impl<'a> View<'a, 43> {
        pub(crate) fn resources(self) -> impl Iterator<Item = Result<PhysicalResourceId>> + 'a {
            self.bytes[48..]
                .chunks_exact(8)
                .map(|p| PhysicalResourceId::read(n64(p, 0)))
        }
    }
    pub(crate) struct HostsView<'a>(&'a [u8]);
    pub(crate) struct SnapshotRoleView<'a>(&'a [u8]);
    impl<'a> SnapshotRoleView<'a> {
        pub(crate) fn decode(mapping: u16, row: &'a [u8]) -> Result<Self> {
            if mapping != 4 || row.len() != 76 {
                return Err(Error::Schema);
            }
            let flags = u32::from_be_bytes(row[72..76].try_into().map_err(|_| Error::Bounds)?);
            let size = u32::from_be_bytes(row[64..68].try_into().map_err(|_| Error::Bounds)?);
            if flags & !7 != 0
                || flags & 6 == 0
                || !(170..=2097152).contains(&size)
                || row[68..72] != [0, 1, 0, 0]
                || row[..32].iter().all(|b| *b == 0)
                || row[32..64].iter().all(|b| *b == 0)
            {
                return Err(Error::Reference);
            }
            Ok(Self(row))
        }
        pub(crate) fn application(&self) -> bool {
            self.0[75] & 2 != 0
        }
        pub(crate) fn bootstrap(&self) -> bool {
            self.0[75] & 4 != 0
        }
        pub(crate) fn asset_reference(&self) -> super::SnapshotRef {
            let mut source = [0; 32];
            source.copy_from_slice(&self.0[..32]);
            let mut asset = [0; 32];
            asset.copy_from_slice(&self.0[32..64]);
            super::SnapshotRef {
                source,
                asset,
                bytes: u32::from_be_bytes([self.0[64], self.0[65], self.0[66], self.0[67]]),
                flags: u32::from(self.0[75] & 1),
            }
        }
    }
    impl<'a> HostsView<'a> {
        pub(crate) fn decode(b: &'a [u8]) -> Result<Self> {
            hosts(b)?;
            Ok(Self(b))
        }
        pub(crate) fn observation(&self) -> Result<SourceObservationId> {
            SourceObservationId::read(n64(self.0, 88))
        }
        pub(crate) fn lookup_key(&self) -> Result<&'a str> {
            std::str::from_utf8(&self.0[128..128 + usize::from(n16(self.0, 110))])
                .map_err(|_| Error::Schema)
        }
        pub(crate) fn member_indices(&self) -> impl Iterator<Item = u16> + '_ {
            self.0[128 + usize::from(n16(self.0, 110)) + usize::from(n16(self.0, 112))..]
                .chunks_exact(2)
                .map(|b| n16(b, 0))
        }
    }
    #[derive(Clone, Copy)]
    pub(crate) enum Record<'a> {
        Reserve(View<'a, 35>),
        Reserved(View<'a, 36>),
        PhysicalAck(View<'a, 37>),
        LogicalBind(View<'a, 38>),
        LogicalAck(View<'a, 39>),
        Publish(View<'a, 40>),
        Published(View<'a, 41>),
        NumericAuthorize(View<'a, 42>),
        Append(View<'a, 43>),
        AppendAck(View<'a, 44>),
        Retire(View<'a, 45>),
        Retired(View<'a, 46>),
        Cancel(View<'a, 47>),
        Canceled(View<'a, 48>),
        PhysicalBind(View<'a, 52>),
        WaiterBind(View<'a, 53>),
        WaiterBound(View<'a, 54>),
        BundleAcquire(View<'a, 55>),
        BundleGranted(View<'a, 56>),
    }
    impl<'a> Record<'a> {
        pub(crate) fn decode(op: Operation, b: &'a [u8]) -> Result<Self> {
            Ok(match op {
                Operation::Reserve => Self::Reserve(View::decode(b)?),
                Operation::Reserved => Self::Reserved(View::decode(b)?),
                Operation::PhysicalAck => Self::PhysicalAck(View::decode(b)?),
                Operation::LogicalBind => Self::LogicalBind(View::decode(b)?),
                Operation::LogicalAck => Self::LogicalAck(View::decode(b)?),
                Operation::Publish => Self::Publish(View::decode(b)?),
                Operation::Published => Self::Published(View::decode(b)?),
                Operation::NumericAuthorize => Self::NumericAuthorize(View::decode(b)?),
                Operation::Append => Self::Append(View::decode(b)?),
                Operation::AppendAck => Self::AppendAck(View::decode(b)?),
                Operation::Retire => Self::Retire(View::decode(b)?),
                Operation::Retired => Self::Retired(View::decode(b)?),
                Operation::Cancel => Self::Cancel(View::decode(b)?),
                Operation::Canceled => Self::Canceled(View::decode(b)?),
                Operation::PhysicalBind => Self::PhysicalBind(View::decode(b)?),
                Operation::WaiterBind => Self::WaiterBind(View::decode(b)?),
                Operation::WaiterBound => Self::WaiterBound(View::decode(b)?),
                Operation::BundleAcquire => Self::BundleAcquire(View::decode(b)?),
                Operation::BundleGranted => Self::BundleGranted(View::decode(b)?),
            })
        }
        pub(crate) fn operation(self) -> Operation {
            match self {
                Self::Reserve(_) => Operation::Reserve,
                Self::Reserved(_) => Operation::Reserved,
                Self::PhysicalAck(_) => Operation::PhysicalAck,
                Self::LogicalBind(_) => Operation::LogicalBind,
                Self::LogicalAck(_) => Operation::LogicalAck,
                Self::Publish(_) => Operation::Publish,
                Self::Published(_) => Operation::Published,
                Self::NumericAuthorize(_) => Operation::NumericAuthorize,
                Self::Append(_) => Operation::Append,
                Self::AppendAck(_) => Operation::AppendAck,
                Self::Retire(_) => Operation::Retire,
                Self::Retired(_) => Operation::Retired,
                Self::Cancel(_) => Operation::Cancel,
                Self::Canceled(_) => Operation::Canceled,
                Self::PhysicalBind(_) => Operation::PhysicalBind,
                Self::WaiterBind(_) => Operation::WaiterBind,
                Self::WaiterBound(_) => Operation::WaiterBound,
                Self::BundleAcquire(_) => Operation::BundleAcquire,
                Self::BundleGranted(_) => Operation::BundleGranted,
            }
        }
        pub(crate) fn bytes(self) -> &'a [u8] {
            match self {
                Self::Reserve(v) => v.bytes(),
                Self::Reserved(v) => v.bytes(),
                Self::PhysicalAck(v) => v.bytes(),
                Self::LogicalBind(v) => v.bytes(),
                Self::LogicalAck(v) => v.bytes(),
                Self::Publish(v) => v.bytes(),
                Self::Published(v) => v.bytes(),
                Self::NumericAuthorize(v) => v.bytes(),
                Self::Append(v) => v.bytes(),
                Self::AppendAck(v) => v.bytes(),
                Self::Retire(v) => v.bytes(),
                Self::Retired(v) => v.bytes(),
                Self::Cancel(v) => v.bytes(),
                Self::Canceled(v) => v.bytes(),
                Self::PhysicalBind(v) => v.bytes(),
                Self::WaiterBind(v) => v.bytes(),
                Self::WaiterBound(v) => v.bytes(),
                Self::BundleAcquire(v) => v.bytes(),
                Self::BundleGranted(v) => v.bytes(),
            }
        }
        pub(crate) fn encode(self, out: &mut [u8]) -> Result<usize> {
            let b = self.bytes();
            out.get_mut(..b.len())
                .ok_or(Error::Bounds)?
                .copy_from_slice(b);
            Ok(b.len())
        }
        fn source_epoch(self) -> Option<u64> {
            let b = self.bytes();
            let at = match self.operation() {
                Operation::Reserve => 48,
                Operation::Publish => 36,
                Operation::PhysicalBind => 88,
                Operation::Reserved | Operation::PhysicalAck | Operation::WaiterBound
                    if b[2] == 1 =>
                {
                    40
                }
                Operation::Published if b[2] == 1 => 24,
                Operation::BundleAcquire => 24,
                Operation::BundleGranted if b[2] == 1 => 32,
                _ => return None,
            };
            Some(n64(b, at))
        }
    }

    /// Descriptor/ACK matching token — DATA-only, не installed-image proof.
    #[derive(Clone, Copy)]
    pub(crate) struct Negotiated {
        launch: super::LaunchRecord,
    }
    impl Negotiated {
        pub(crate) fn descriptor(launch: super::LaunchRecord) -> Result<[u8; 272]> {
            let mut b = [0; 272];
            b[..8].copy_from_slice(b"DNSNEG02");
            super::put16(&mut b, 8, 2);
            super::put16(&mut b, 10, 272);
            b[16..208].copy_from_slice(&launch.encode()?);
            b[208..240].copy_from_slice(&Sha256::digest(b"YONIK-DNS-V2-CODEC-2\0"));
            for (at, n) in [
                (240, 4),
                (242, 11),
                (248, 64),
                (250, 64),
                (252, 64),
                (254, 256),
                (256, 256),
            ] {
                super::put16(&mut b, at, n);
            }
            super::put32(&mut b, 244, 8388608);
            Ok(b)
        }
        pub(crate) fn ack(descriptor: &[u8]) -> Result<[u8; 40]> {
            if descriptor.len() != 272 {
                return Err(Error::Bounds);
            }
            let mode = match &descriptor[16..24] {
                b"YNKLOC01" => super::Mode::Local,
                b"YNKEXT01" => super::Mode::System,
                _ => return Err(Error::Schema),
            };
            let launch = super::LaunchRecord::decode(&descriptor[16..208], mode)?;
            if Self::descriptor(launch)?.as_slice() != descriptor {
                return Err(Error::Binding);
            }
            super::extension_ack(b"DNSACK02", descriptor)
        }
        pub(crate) fn accept(
            descriptor: &[u8],
            ack: &[u8],
            launch: super::LaunchRecord,
            ancillary: [(usize, usize); 2],
        ) -> Result<Self> {
            if ancillary != [(0, 0); 2]
                || Self::descriptor(launch)?.as_slice() != descriptor
                || Self::ack(descriptor)?.as_slice() != ack
            {
                return Err(Error::Binding);
            }
            Ok(Self { launch })
        }
    }
    #[derive(Clone, Copy)]
    pub(crate) struct Envelope {
        pub sequence: u64,
        pub reply_to: u64,
        pub binding: super::Binding,
    }
    pub(crate) struct DnsFrame<'a> {
        pub header: Envelope,
        pub record: Record<'a>,
    }
    /// SCM packet имеет собственный identity envelope192, без runtime Header128.
    pub(crate) struct PhysicalPacket<'a>(View<'a, 52>);
    impl<'a> PhysicalPacket<'a> {
        pub(crate) fn decode(
            bytes: &'a [u8],
            neg: &Negotiated,
            rights: usize,
            credentials: usize,
        ) -> Result<Self> {
            if (rights, credentials) != (1, 1) {
                return Err(Error::Binding);
            }
            let view = View::decode(bytes)?;
            physical_binding(bytes, neg.launch)?;
            Ok(Self(view))
        }
        pub(crate) fn encode(&self, neg: &Negotiated, out: &mut [u8]) -> Result<usize> {
            physical_binding(self.0.bytes(), neg.launch)?;
            self.0.encode(out)
        }
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum Direction {
        Producer,
        Issuer,
    }
    impl<'a> DnsFrame<'a> {
        pub(crate) fn encode(&self, neg: &Negotiated, out: &mut [u8]) -> Result<usize> {
            let op = self.record.operation();
            if op == Operation::PhysicalBind {
                return Err(Error::Schema);
            }
            let total = 128 + self.record.bytes().len();
            if total > 65536 || out.len() < total {
                return Err(Error::Bounds);
            }
            id(self.header.sequence)?;
            if op.is_reply() {
                id(self.header.reply_to)?;
            }
            if self
                .record
                .source_epoch()
                .is_some_and(|epoch| epoch != neg.launch.binding.epoch)
            {
                return Err(Error::Binding);
            }
            if op == Operation::PhysicalBind {
                physical_binding(self.record.bytes(), neg.launch)?;
            }
            if self.header.binding != neg.launch.binding
                || (self.header.reply_to != 0) != op.is_reply()
            {
                return Err(Error::Binding);
            }
            let mut h = super::Header {
                kind: super::Kind::Hello,
                sequence: self.header.sequence,
                reply_to: self.header.reply_to,
                binding: self.header.binding,
                object_id: 0,
            }
            .encode(total - 128)?;
            super::put16(&mut h, 10, op as u16);
            out[..128].copy_from_slice(&h);
            self.record.encode(&mut out[128..total])?;
            Ok(total)
        }
        pub(crate) fn decode(
            bytes: &'a [u8],
            neg: &Negotiated,
            direction: Direction,
            rights: usize,
            credentials: usize,
            reply: Option<u64>,
        ) -> Result<Self> {
            if !(128..=65536).contains(&bytes.len()) {
                return Err(Error::Bounds);
            }
            let op = Operation::try_from(n16(bytes, 10))?;
            if op == Operation::PhysicalBind {
                return Err(Error::Schema);
            }
            let from_issuer = direction == Direction::Issuer;
            if from_issuer != op.is_reply() || (rights, credentials) != op.rights() {
                return Err(Error::Binding);
            }
            if from_issuer {
                id(reply.ok_or(Error::Binding)?)?;
            }
            let mut raw = [0; 128];
            raw.copy_from_slice(&bytes[..128]);
            super::put16(&mut raw, 10, super::Kind::Hello as u16);
            let h = super::Header::decode(&raw, bytes.len())?;
            if h.binding != neg.launch.binding
                || h.object_id != 0
                || h.sequence == u64::MAX
                || if from_issuer {
                    reply.is_none() || reply != Some(h.reply_to) || h.reply_to == 0
                } else {
                    reply.is_some() || h.reply_to != 0
                }
            {
                return Err(Error::Binding);
            }
            let record = Record::decode(op, &bytes[128..])?;
            if record
                .source_epoch()
                .is_some_and(|epoch| epoch != neg.launch.binding.epoch)
            {
                return Err(Error::Binding);
            }
            if op == Operation::PhysicalBind {
                physical_binding(record.bytes(), neg.launch)?;
            }
            Ok(Self {
                header: Envelope {
                    sequence: h.sequence,
                    reply_to: h.reply_to,
                    binding: h.binding,
                },
                record,
            })
        }
    }

    fn n16(b: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([b[at], b[at + 1]])
    }
    fn n64(b: &[u8], at: usize) -> u64 {
        u64::from_be_bytes([
            b[at],
            b[at + 1],
            b[at + 2],
            b[at + 3],
            b[at + 4],
            b[at + 5],
            b[at + 6],
            b[at + 7],
        ])
    }
    fn zero(b: &[u8]) -> Result<()> {
        if b.iter().any(|v| *v != 0) {
            Err(Error::Schema)
        } else {
            Ok(())
        }
    }
    fn id(n: u64) -> Result<()> {
        if n == 0 || n == u64::MAX {
            Err(Error::Reference)
        } else {
            Ok(())
        }
    }
    fn lease(n: u64) -> Result<()> {
        if n == 0 || n > 1_000_000_000 {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }
    fn source(kind: u8, purpose: u8) -> Result<()> {
        if matches!((kind, purpose), (1, 1 | 2) | (2, 3)) {
            Ok(())
        } else {
            Err(Error::Schema)
        }
    }
    pub(super) fn preflight(kind: u16, b: &[u8]) -> Result<()> {
        Operation::try_from(kind)?;
        if kind == 52 {
            return physical(b);
        }
        if b.len() < 8 || n16(b, 0) != 2 {
            return Err(Error::Schema);
        }
        match kind {
            35 => {
                if !(96..=1024).contains(&b.len()) {
                    return Err(Error::Bounds);
                }
                if !matches!(b[2], 1..=3) {
                    return Err(Error::Schema);
                }
                zero(&b[3..8])?;
                zero(&b[86..88])?;
                if b[2] != 2 {
                    zero(&b[92..96])?;
                }
                id(n64(b, 8))?;
                id(n64(b, 48))?;
                lease(n64(b, 56))?;
                source(b[75], b[74])?;
                if !matches!(b[76], 6 | 17)
                    || !matches!(b[77], 1..=3)
                    || b[79] > 1
                    || n16(b, 66) == super::NONE
                    || n16(b, 70) == super::NONE
                    || !matches!((b[78], b[74]), (1, 1) | (2, 2 | 3))
                {
                    return Err(Error::Reference);
                }
                let flow = n64(b, 32);
                let revision = n64(b, 40);
                if (flow == 0) != (revision == 0)
                    || b[77] == 1 && flow == 0
                    || b[77] == 2 && flow != 0
                {
                    return Err(Error::Reference);
                }
                if flow != 0 {
                    id(flow)?;
                    id(revision)?;
                }
                let original = usize::from(n16(b, 80));
                let query = usize::from(n16(b, 82));
                let base = usize::from(n16(b, 84));
                if !(1..=253).contains(&original)
                    || query > 253
                    || !(1..=1024).contains(&base)
                    || 96 + original + query + base != b.len()
                {
                    return Err(Error::Bounds);
                }
                ascii_name(&b[96..96 + original], false)?;
                if b[75] == 2 {
                    if b[2] != 3 || n16(b, 64) != super::NONE || n16(b, 72) != 0 || query != 0 {
                        return Err(Error::Reference);
                    }
                    zero(&b[16..32])?;
                    zero(&b[88..92])?;
                } else {
                    id(n64(b, 16))?;
                    id(n64(b, 24))?;
                    if n16(b, 64) == super::NONE || !matches!(n16(b, 72), 1 | 28) || query == 0 {
                        return Err(Error::Reference);
                    }
                    ascii_name(&b[96 + original..96 + original + query], true)?;
                    if b[2] == 2 {
                        id(n64(b, 88))?;
                    } else {
                        let flags = n16(b, 88);
                        let payload = n16(b, 90);
                        if flags & !31 != 0
                            || if flags & 8 == 0 {
                                payload != 0 || flags & 4 != 0
                            } else {
                                !(512..=4096).contains(&payload)
                            }
                        {
                            return Err(Error::Schema);
                        }
                    }
                }
                if b[2] != 2 && (b[74] == 1) != (n16(b, 68) == super::NONE) {
                    return Err(Error::Reference);
                }
                canonical_base(b[77], &b[96 + original + query..])
            }
            36 | 37 | 39 | 44 | 48 => {
                let size = match kind {
                    44 => 56,
                    48 => 32,
                    _ => 64,
                };
                if b.len() != size {
                    return Err(Error::Bounds);
                }
                if !matches!(b[2], 1..=3) {
                    return Err(Error::Schema);
                }
                if b[2] != 1 {
                    return zero(&b[3..]);
                }
                zero(&b[3..8])?;
                match kind {
                    36 => {
                        for at in [8, 16, 40] {
                            id(n64(b, at))?;
                        }
                        lease(n64(b, 48))?;
                        let bundle = n64(b, 24);
                        let context = n64(b, 32);
                        if !matches!(b[60], 1..=3)
                            || n16(b, 56) > 64
                            || n16(b, 58) != 1
                            || (b[60] == 2) == (n16(b, 56) == 0)
                        {
                            return Err(Error::Reference);
                        }
                        match b[60] {
                            1 | 2 => {
                                id(bundle)?;
                                id(context)?;
                            }
                            _ if bundle == 0 => {
                                id(context)?;
                                if n16(b, 56) != 0 {
                                    return Err(Error::Reference);
                                }
                            }
                            _ => {
                                id(bundle)?;
                                if context != 0 || n16(b, 56) != 0 {
                                    return Err(Error::Reference);
                                }
                            }
                        }
                        zero(&b[61..64])
                    }
                    37 => {
                        for at in [8, 16, 24, 32, 40] {
                            id(n64(b, at))?;
                        }
                        lease(n64(b, 48))?;
                        zero(&b[56..64])
                    }
                    39 => {
                        for at in [8, 16, 24, 32] {
                            id(n64(b, at))?;
                        }
                        if n64(b, 40) != 1
                            || !(1..=64).contains(&n16(b, 56))
                            || !matches!(b[58], 1 | 2)
                            || b[58] == 1 && n16(b, 56) != 1
                        {
                            return Err(Error::Reference);
                        }
                        lease(n64(b, 48))?;
                        zero(&b[59..64])
                    }
                    44 => {
                        for at in [8, 16, 24, 32] {
                            id(n64(b, at))?;
                        }
                        if n64(b, 32) < 2 || !(1..=64).contains(&n16(b, 48)) {
                            return Err(Error::Reference);
                        }
                        lease(n64(b, 40))?;
                        zero(&b[50..56])
                    }
                    _ => {
                        id(n64(b, 8))?;
                        id(n64(b, 16))?;
                        zero(&b[24..32])
                    }
                }
            }
            38 | 43 => {
                let fixed = if kind == 38 { 64 } else { 48 };
                if b.len() < fixed {
                    return Err(Error::Bounds);
                }
                let count = usize::from(n16(b, 4));
                if !(1..=64).contains(&count) || b.len() != fixed + 8 * count {
                    return Err(Error::Bounds);
                }
                zero(&b[6..8])?;
                if kind == 38 {
                    if !matches!(b[2], 1 | 2) || b[2] == 1 && count != 1 {
                        return Err(Error::Schema);
                    }
                    zero(&b[3..4])?;
                    for at in [8, 16, 24, 32, 48] {
                        id(n64(b, at))?;
                    }
                    lease(n64(b, 56))?;
                    if n64(b, 40) != 0 {
                        id(n64(b, 40))?;
                    }
                } else {
                    zero(&b[2..4])?;
                    for at in [8, 16, 24, 32] {
                        id(n64(b, at))?;
                    }
                    lease(n64(b, 40))?;
                }
                unique_ids(&b[fixed..])
            }
            42 => {
                if !(16..=1063).contains(&b.len()) {
                    return Err(Error::Bounds);
                }
                if n16(b, 2) >= 256 {
                    return Err(Error::Bounds);
                }
                id(n64(b, 4))?;
                let base = usize::from(n16(b, 12));
                if !(1..=1024).contains(&base) || 16 + base > b.len() || !matches!(b[14], 1 | 2) {
                    return Err(Error::Bounds);
                }
                canonical_base(b[15], &b[16..16 + base])?;
                numeric_destination(&b[16 + base..]).map(|_| ())
            }
            45 | 47 => {
                if b.len() != 24 {
                    return Err(Error::Bounds);
                }
                zero(&b[3..8])?;
                id(n64(b, 8))?;
                if kind == 45 {
                    retire_target(b[2], n64(b, 16))
                } else {
                    if !matches!(b[2], 1..=8) {
                        return Err(Error::Schema);
                    }
                    zero(&b[18..24])
                }
            }
            46 => {
                if b.len() != 40 || !matches!(b[2], 1..=3) {
                    return Err(Error::Bounds);
                }
                if b[2] == 2 {
                    return zero(&b[3..]);
                }
                zero(&b[4..8])?;
                zero(&b[29..32])?;
                id(n64(b, 8))?;
                retire_target(b[3], n64(b, 16))?;
                let pending = n16(b, 24);
                let duplicates = n16(b, 26);
                if pending > 64
                    || duplicates > 64
                    || b[28] > 1
                    || b[2] == 1 && (pending != 0 || duplicates != 0 || b[28] != 1)
                {
                    return Err(Error::Reference);
                }
                Ok(())
            }
            55 => {
                if !(72..=2164).contains(&b.len()) {
                    return Err(Error::Bounds);
                }
                zero(&b[2..8])?;
                zero(&b[62..64])?;
                for at in [8, 16, 24] {
                    id(n64(b, at))?;
                }
                lease(n64(b, 40))?;
                if (n64(b, 32) == 0) != (n64(b, 64) == 0) {
                    return Err(Error::Reference);
                }
                if n64(b, 32) != 0 {
                    id(n64(b, 32))?;
                    id(n64(b, 64))?;
                }
                let base = usize::from(n16(b, 48));
                let count = usize::from(n16(b, 50));
                let original = usize::from(n16(b, 58));
                if !(1..=815).contains(&base)
                    || !(1..=256).contains(&count)
                    || !(1..=253).contains(&original)
                    || 72 + base + original + count * 4 != b.len()
                    || !matches!(n16(b, 52), 1 | 28)
                    || n16(b, 60) == super::NONE
                {
                    return Err(Error::Bounds);
                }
                let flags = n16(b, 54);
                let payload = n16(b, 56);
                if flags & !31 != 0
                    || if flags & 8 == 0 {
                        payload != 0 || flags & 4 != 0
                    } else {
                        !(512..=4096).contains(&payload)
                    }
                {
                    return Err(Error::Schema);
                }
                let super::Message::Authorize(a) =
                    super::Message::decode(super::Kind::Authorize, &b[72..72 + base])?
                else {
                    return Err(Error::Reference);
                };
                if a.class != 3 || a.resolver != n16(b, 60) {
                    return Err(Error::Reference);
                }
                ascii_name(&b[72 + base..72 + base + original], false)?;
                for row in b[72 + base + original..].chunks_exact(4) {
                    if n16(row, 0) == super::NONE || row[2] > 1 || row[3] != 0 {
                        return Err(Error::Reference);
                    }
                }
                Ok(())
            }
            56 => {
                if b.len() != 64 || !matches!(b[2], 1..=3) {
                    return Err(Error::Bounds);
                }
                zero(&b[3..8])?;
                if b[2] != 1 {
                    return zero(&b[8..]);
                }
                for at in [8, 16, 24, 32, 56] {
                    id(n64(b, at))?;
                }
                lease(n64(b, 40))?;
                if !(1..=256).contains(&n16(b, 48)) {
                    return Err(Error::Bounds);
                }
                zero(&b[50..56])
            }
            53 => {
                if b.len() != 64 {
                    return Err(Error::Bounds);
                }
                zero(&b[2..8])?;
                for at in [8, 16, 32] {
                    id(n64(b, at))?;
                }
                if (n64(b, 40) == 0) != (n64(b, 48) == 0) {
                    return Err(Error::Reference);
                }
                for at in [24, 40, 48] {
                    if n64(b, at) != 0 {
                        id(n64(b, at))?;
                    }
                }
                lease(n64(b, 56))
            }
            54 | 41 => {
                let size = if kind == 54 { 64 } else { 48 };
                if b.len() != size {
                    return Err(Error::Bounds);
                }
                if !matches!(b[2], 1..=3) {
                    return Err(Error::Schema);
                }
                if b[2] != 1 {
                    return zero(&b[3..]);
                }
                zero(&b[3..8])?;
                id(n64(b, 8))?;
                if kind == 54 {
                    for at in [16, 24, 32, 40] {
                        id(n64(b, at))?;
                    }
                    lease(n64(b, 48))?;
                    if !(1..=256).contains(&n16(b, 56)) {
                        return Err(Error::Bounds);
                    }
                    source(b[58], b[59])?;
                    zero(&b[60..64])
                } else {
                    if n64(b, 16) != 0 {
                        id(n64(b, 16))?;
                    }
                    id(n64(b, 24))?;
                    if n64(b, 32) == 0
                        || n64(b, 32) > u64::from(u32::MAX) * 1_000_000_000
                        || !(1..=256).contains(&n16(b, 40))
                    {
                        return Err(Error::Bounds);
                    }
                    zero(&b[42..48])
                }
            }
            40 => {
                if !(144..=33679).contains(&b.len()) {
                    return Err(Error::Bounds);
                }
                zero(&b[2..4])?;
                zero(&b[116..120])?;
                zero(&b[138..140])?;
                zero(&b[143..144])?;
                id(n64(b, 12))?;
                id(n64(b, 36))?;
                source(b[137], b[136])?;
                if !matches!(b[142], 6 | 17) {
                    return Err(Error::Schema);
                }
                if b[137] == 2 {
                    if n16(b, 4) != u16::MAX || n16(b, 10) != 0 {
                        return Err(Error::Schema);
                    }
                    zero(&b[20..36])?;
                    zero(&b[108..116])?;
                    zero(&b[120..136])?;
                    let tail = &b[144..];
                    hosts(tail)?;
                    for (prefix, offset, length) in [
                        (44, 16, 32),
                        (76, 48, 32),
                        (36, 80, 8),
                        (6, 114, 2),
                        (8, 116, 2),
                        (140, 118, 2),
                        (142, 121, 1),
                    ] {
                        if b[prefix..prefix + length] != tail[offset..offset + length] {
                            return Err(Error::Binding);
                        }
                    }
                    Ok(())
                } else {
                    for at in [20, 28, 120, 128] {
                        id(n64(b, at))?;
                    }
                    if !matches!(n16(b, 10), 1 | 28) {
                        return Err(Error::Schema);
                    }
                    let question = usize::from(n16(b, 108));
                    let request = usize::from(n16(b, 110));
                    let response =
                        u32::from_be_bytes(b[112..116].try_into().map_err(|_| Error::Bounds)?)
                            as usize;
                    if !(1..=255).contains(&question)
                        || !(12..=512).contains(&request)
                        || !(12..=32768).contains(&response)
                        || 144 + question + request + response != b.len()
                    {
                        return Err(Error::Bounds);
                    }
                    if b[144..144 + question].contains(&0) {
                        return Err(Error::Schema);
                    }
                    if b[136] == 1 && (n16(b, 8) != u16::MAX || n16(b, 140) != u16::MAX) {
                        return Err(Error::Reference);
                    }
                    if n16(b, 4) == super::NONE
                        || n16(b, 6) == super::NONE
                        || b[136] == 2 && (n16(b, 8) == super::NONE || n16(b, 140) == super::NONE)
                    {
                        return Err(Error::Reference);
                    }
                    if b[76..108].iter().all(|v| *v == 0) != b[44..76].iter().all(|v| *v == 0) {
                        return Err(Error::Binding);
                    }
                    if b[136] == 2
                        && (b[44..76].iter().all(|v| *v == 0) || b[76..108].iter().all(|v| *v == 0))
                    {
                        return Err(Error::Binding);
                    }
                    // Strict DNS/question/RR validation выполняет issuer после
                    // DATA preflight, до receipt/durable numeric admission.
                    Ok(())
                }
            }
            _ => Err(Error::Schema),
        }
    }
    fn ascii_name(b: &[u8], lower: bool) -> Result<()> {
        let name = std::str::from_utf8(b).map_err(|_| Error::Schema)?;
        super::resolver_name(name, false, lower)
    }
    fn unique_ids(b: &[u8]) -> Result<()> {
        let count = b.len() / 8;
        let mut ids = [0; 64];
        if count > 64 || b.len() % 8 != 0 {
            return Err(Error::Bounds);
        }
        for (i, slot) in ids[..count].iter_mut().enumerate() {
            *slot = n64(b, i * 8);
            id(*slot)?;
        }
        ids[..count].sort_unstable();
        if ids[..count].windows(2).any(|p| p[0] == p[1]) {
            return Err(Error::Reference);
        }
        Ok(())
    }
    fn canonical_base(class: u8, b: &[u8]) -> Result<()> {
        if b.len() == 8 && matches!(class, 2 | 3) {
            if !matches!(super::Message::decode(super::Kind::Probe,b)?,super::Message::Probe{purpose,..} if purpose==if class==2 {1}else{2})
            {
                return Err(Error::Reference);
            }
            Ok(())
        } else {
            if !matches!(class, 1 | 3)
                || !matches!(super::Message::decode(super::Kind::Authorize,b)?,super::Message::Authorize(a) if a.class==class)
            {
                return Err(Error::Reference);
            }
            Ok(())
        }
    }
    fn numeric_destination(b: &[u8]) -> Result<u8> {
        if b.len() < 7 || !matches!(b[1], 6 | 17) || n16(b, 2) == 0 {
            return Err(Error::Schema);
        }
        zero(&b[5..7])?;
        let n = match b[0] {
            4 => 4,
            6 => 16,
            _ => return Err(Error::Schema),
        };
        if usize::from(b[4]) != n || b.len() != 7 + n {
            return Err(Error::Bounds);
        }
        match b[0] {
            4 => {
                let ip = std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(&b[7..]).map_err(|_| Error::Bounds)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                    return Err(Error::Schema);
                }
            }
            _ => {
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&b[7..]).map_err(|_| Error::Bounds)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some() {
                    return Err(Error::Schema);
                }
            }
        }
        Ok(b[1])
    }
    fn retire_target(target: u8, revision: u64) -> Result<()> {
        match target {
            3 if revision == 0 => Ok(()),
            4 => id(revision),
            _ => Err(Error::Reference),
        }
    }
    fn physical(b: &[u8]) -> Result<()> {
        if b.len() != 192 || &b[..8] != b"DNSPHY02" || n16(b, 8) != 2 || n16(b, 10) != 192 {
            return Err(Error::Bounds);
        }
        zero(&b[12..16])?;
        zero(&b[167..168])?;
        for range in [16..48, 48..64, 64..80, 96..128] {
            if b[range].iter().all(|v| *v == 0) {
                return Err(Error::Binding);
            }
        }
        for at in [80, 88, 128, 136, 144, 152] {
            id(n64(b, at))?;
        }
        if n16(b, 160) == super::NONE
            || n16(b, 162) == super::NONE
            || !matches!(b[166], 1 | 2)
            || !matches!((b[164], b[165]), (6, 1) | (17, 2 | 3))
        {
            return Err(Error::Reference);
        }
        let n = match b[168] {
            4 => 11,
            6 => 23,
            _ => return Err(Error::Schema),
        };
        if numeric_destination(&b[168..168 + n])? != b[164] {
            return Err(Error::Binding);
        }
        zero(&b[168 + n..192])
    }
    fn physical_binding(b: &[u8], launch: super::LaunchRecord) -> Result<()> {
        let binding = launch.binding;
        if b[16..48] != binding.digest
            || b[48..64] != binding.session
            || b[64..80] != binding.invocation
            || n64(b, 80) != binding.generation
            || n64(b, 88) != binding.epoch
            || b[96..128] != launch.nonce
            || b[166] != launch.mode as u8
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
    fn hosts(b: &[u8]) -> Result<()> {
        if !(130..=666).contains(&b.len())
            || &b[..8] != b"DNHOST02"
            || n16(b, 8) != 2
            || usize::from(n16(b, 10)) != b.len()
        {
            return Err(Error::Bounds);
        }
        zero(&b[12..16])?;
        if b[16..48].iter().all(|v| *v == 0) || b[48..80].iter().all(|v| *v == 0) {
            return Err(Error::Binding);
        }
        zero(&b[104..106])?;
        zero(&b[124..128])?;
        for at in [80, 88] {
            id(n64(b, at))?;
        }
        lease(n64(b, 96))?;
        let count = usize::from(n16(b, 108));
        let key = usize::from(n16(b, 110));
        let original = usize::from(n16(b, 112));
        if !(1..=16).contains(&count)
            || !(1..=253).contains(&key)
            || !(1..=253).contains(&original)
            || 128 + key + original + 2 * count != b.len()
            || b[120] > 1
            || !matches!(b[121], 6 | 17)
            || n16(b, 122) == 0
        {
            return Err(Error::Bounds);
        }
        for (start, length) in [(128, key), (128 + key, original)] {
            let name = std::str::from_utf8(&b[start..start + length]).map_err(|_| Error::Schema)?;
            super::resolver_name(name, false, start == 128)?;
        }
        let original_bytes = &b[128 + key..128 + key + original];
        let rooted = original_bytes.contains(&b'.') && original_bytes.last() != Some(&b'.');
        if original + usize::from(rooted) != key
            || !original_bytes
                .iter()
                .zip(&b[128..128 + original])
                .all(|(a, c)| a.to_ascii_lowercase() == *c)
            || rooted && b[128 + key - 1] != b'.'
        {
            return Err(Error::Binding);
        }
        let mut previous = None;
        for pair in b[128 + key + original..].chunks_exact(2) {
            let member = u16::from_be_bytes([pair[0], pair[1]]);
            if member >= 16 || previous.is_some_and(|p| p >= member) {
                return Err(Error::Reference);
            }
            previous = Some(member);
        }
        Ok(())
    }
}

/// Private proof v2 DATA codec. Сам по себе не создаёт admission/FlowGrant.
pub(crate) mod udp_v2 {
    use super::{
        Error, LaunchRecord, Reader, Result, Tuple, Writer, boolean, extension_ack, put16, put32,
        put64,
    };
    use sha2::{Digest, Sha256};
    pub(crate) const MAX_DATAGRAM: usize = 65507;
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) struct Packet {
        pub association: u64,
        pub packet: u64,
        pub permit: u64,
        pub cookie: u64,
        pub tuple: Tuple,
        pub bytes: u32,
        pub header: u16,
        pub flags: u16,
        pub fingerprint: [u8; 32],
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum Record {
        Control {
            operation: u64,
            proof: u64,
            ingress: u16,
            tuple: Tuple,
        },
        ControlAck {
            operation: u64,
            control: u64,
            cookie: u64,
            remaining: u64,
        },
        Associate {
            operation: u64,
            control: u64,
            cookie: u64,
        },
        Associated {
            operation: u64,
            control: u64,
            association: u64,
            cookie: u64,
            port: u16,
        },
        Peek {
            association: u64,
            operation: u64,
            control: u64,
        },
        Permit {
            packet: Packet,
            remaining: u64,
        },
        Consumed {
            packet: Packet,
            sequence: u64,
        },
        Matched {
            association: u64,
            packet: u64,
            permit: u64,
            sequence: u64,
            status: u8,
            remaining: u64,
        },
        Close {
            association: u64,
            close: u64,
            control: u64,
            reason: u16,
        },
        Closed {
            association: u64,
            close: u64,
            last_packet: u64,
            pending: u32,
            status: u8,
            joined: bool,
            duplicates: u16,
            cookie: u64,
            retired: u64,
        },
    }
    pub(crate) struct Encoded {
        pub bytes: [u8; 256],
        pub length: usize,
        pub rights: usize,
        pub from_go: bool,
    }
    fn id(n: u64) -> Result<()> {
        if n == 0 || n == u64::MAX {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }
    fn nz(n: u64) -> Result<()> {
        if n == 0 { Err(Error::Bounds) } else { Ok(()) }
    }
    fn lease(n: u64) -> Result<()> {
        if n == 0 || n > 1_000_000_000 {
            Err(Error::Bounds)
        } else {
            Ok(())
        }
    }
    fn u16_at(b: &[u8], p: usize) -> u16 {
        u16::from_be_bytes([b[p], b[p + 1]])
    }
    fn u32_at(b: &[u8], p: usize) -> u32 {
        // Private fixed offsets после exact-size preflight.
        u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]])
    }
    fn u64_at(b: &[u8], p: usize) -> u64 {
        u64::from_be_bytes([
            b[p],
            b[p + 1],
            b[p + 2],
            b[p + 3],
            b[p + 4],
            b[p + 5],
            b[p + 6],
            b[p + 7],
        ])
    }
    pub(crate) fn bootstrap(launch: LaunchRecord) -> Result<[u8; 128]> {
        let raw = launch.encode()?;
        let mut out = [0; 128];
        out[..8].copy_from_slice(b"YNKPF002");
        put16(&mut out, 8, 2);
        put16(&mut out, 10, 128);
        put16(&mut out, 12, 1);
        out[16..].copy_from_slice(&raw[16..128]);
        Ok(out)
    }
    pub(crate) fn bootstrap_ack(launch: LaunchRecord) -> Result<[u8; 40]> {
        extension_ack(b"YNKPFA02", &bootstrap(launch)?)
    }
    impl Packet {
        fn validate(self) -> Result<()> {
            for n in [self.association, self.packet, self.permit] {
                id(n)?;
            }
            nz(self.cookie)?;
            self.tuple.owner_flow()?;
            if self.tuple.protocol != 17
                || self.tuple.family != 4
                || self.tuple.remote[..4] != [127, 0, 0, 1]
                || self.bytes as usize > MAX_DATAGRAM
                || self.header as u32 > self.bytes
                || !(8..=260).contains(&self.header)
                || self.flags != 0
                || self.fingerprint == [0; 32]
            {
                return Err(Error::Schema);
            }
            Ok(())
        }
        fn write(self, out: &mut [u8; 256]) -> Result<()> {
            self.validate()?;
            for (offset, n) in [
                (128, self.association),
                (136, self.packet),
                (144, self.permit),
                (152, self.cookie),
            ] {
                put64(out, offset, n);
            }
            self.tuple.write(&mut Writer {
                bytes: &mut out[160..200],
                position: 0,
            })?;
            put32(out, 200, self.bytes);
            put16(out, 204, self.header);
            put16(out, 206, self.flags);
            out[208..240].copy_from_slice(&self.fingerprint);
            Ok(())
        }
        fn read(b: &[u8]) -> Result<Self> {
            Ok(Self {
                association: u64_at(b, 128),
                packet: u64_at(b, 136),
                permit: u64_at(b, 144),
                cookie: u64_at(b, 152),
                tuple: Tuple::read(&mut Reader::new(&b[160..200]))?,
                bytes: u32_at(b, 200),
                header: u16_at(b, 204),
                flags: u16_at(b, 206),
                fingerprint: b[208..240].try_into().map_err(|_| Error::Bounds)?,
            })
        }
    }
    impl Record {
        pub(crate) fn encode(self, launch: LaunchRecord) -> Result<Encoded> {
            launch.encode()?;
            let (magic, length, rights, from_go) = match self {
                Self::Control { .. } => (b"YNKUCS01", 192, 1, true),
                Self::ControlAck { .. } => (b"YNKUCA01", 160, 0, false),
                Self::Associate { .. } => (b"YNKUAQ01", 160, 0, true),
                Self::Associated { .. } => (b"YNKUAC01", 192, 1, false),
                Self::Peek { .. } => (b"YNKUPQ01", 160, 0, true),
                Self::Permit { .. } => (b"YNKURP01", 256, 0, false),
                Self::Consumed { .. } => (b"YNKUCM01", 256, 0, true),
                Self::Matched { .. } => (b"YNKUMR01", 192, 0, false),
                Self::Close { .. } => (b"YNKUCQ01", 160, 0, false),
                Self::Closed { .. } => (b"YNKUCR01", 192, 0, true),
            };
            let mut out = [0; 256];
            out[..8].copy_from_slice(magic);
            put16(&mut out, 8, 1);
            put16(&mut out, 10, length as u16);
            put16(&mut out, 12, rights as u16);
            let b = launch.binding;
            out[16..48].copy_from_slice(&b.digest);
            out[48..64].copy_from_slice(&b.session);
            out[64..80].copy_from_slice(&b.invocation);
            put64(&mut out, 80, b.generation);
            put64(&mut out, 88, b.epoch);
            out[96..128].copy_from_slice(&launch.nonce);
            match self {
                Self::Control {
                    operation,
                    proof,
                    ingress,
                    tuple,
                } => {
                    id(operation)?;
                    id(proof)?;
                    tuple.owner_flow()?;
                    if ingress >= 4
                        || tuple.protocol != 6
                        || tuple.family != 4
                        || tuple.remote[..4] != [127, 0, 0, 1]
                    {
                        return Err(Error::Schema);
                    }
                    put64(&mut out, 128, operation);
                    put64(&mut out, 136, proof);
                    put16(&mut out, 144, ingress);
                    out[146] = 3;
                    tuple.write(&mut Writer {
                        bytes: &mut out[148..188],
                        position: 0,
                    })?;
                }
                Self::ControlAck {
                    operation,
                    control,
                    cookie,
                    remaining,
                } => {
                    id(operation)?;
                    id(control)?;
                    nz(cookie)?;
                    lease(remaining)?;
                    put64(&mut out, 128, operation);
                    put64(&mut out, 136, control);
                    put64(&mut out, 144, cookie);
                    put64(&mut out, 152, remaining);
                }
                Self::Associate {
                    operation,
                    control,
                    cookie,
                } => {
                    id(operation)?;
                    id(control)?;
                    nz(cookie)?;
                    put64(&mut out, 128, operation);
                    put64(&mut out, 136, control);
                    put64(&mut out, 144, cookie);
                }
                Self::Associated {
                    operation,
                    control,
                    association,
                    cookie,
                    port,
                } => {
                    for n in [operation, control, association] {
                        id(n)?;
                    }
                    nz(cookie)?;
                    if port == 0 {
                        return Err(Error::Bounds);
                    }
                    put64(&mut out, 128, operation);
                    put64(&mut out, 136, control);
                    put64(&mut out, 144, association);
                    put64(&mut out, 152, cookie);
                    out[160] = 4;
                    out[161] = 17;
                    put16(&mut out, 164, port);
                    out[168..172].copy_from_slice(&[127, 0, 0, 1]);
                }
                Self::Peek {
                    association,
                    operation,
                    control,
                } => {
                    for n in [association, operation, control] {
                        id(n)?;
                    }
                    put64(&mut out, 128, association);
                    put64(&mut out, 136, operation);
                    put64(&mut out, 144, control);
                }
                Self::Permit { packet, remaining } => {
                    packet.write(&mut out)?;
                    lease(remaining)?;
                    put64(&mut out, 240, remaining);
                }
                Self::Consumed { packet, sequence } => {
                    packet.write(&mut out)?;
                    id(sequence)?;
                    put64(&mut out, 240, sequence);
                }
                Self::Matched {
                    association,
                    packet,
                    permit,
                    sequence,
                    status,
                    remaining,
                } => {
                    for n in [association, packet, permit, sequence] {
                        id(n)?;
                    }
                    if !(1..=3).contains(&status)
                        || remaining > 1_000_000_000
                        || status == 1 && remaining == 0
                    {
                        return Err(Error::Schema);
                    }
                    put64(&mut out, 128, association);
                    put64(&mut out, 136, packet);
                    put64(&mut out, 144, permit);
                    put64(&mut out, 152, sequence);
                    out[160] = status;
                    put64(&mut out, 168, remaining);
                }
                Self::Close {
                    association,
                    close,
                    control,
                    reason,
                } => {
                    for n in [association, close, control] {
                        id(n)?;
                    }
                    put64(&mut out, 128, association);
                    put64(&mut out, 136, close);
                    put64(&mut out, 144, control);
                    put16(&mut out, 152, reason);
                }
                Self::Closed {
                    association,
                    close,
                    last_packet,
                    pending,
                    status,
                    joined,
                    duplicates,
                    cookie,
                    retired,
                } => {
                    id(association)?;
                    id(close)?;
                    nz(cookie)?;
                    if last_packet == u64::MAX
                        || retired == u64::MAX
                        || pending > 256
                        || duplicates > 1
                        || ![1, 3].contains(&status)
                        || status == 1 && (pending != 0 || !joined || duplicates != 0)
                    {
                        return Err(Error::Schema);
                    }
                    put64(&mut out, 128, association);
                    put64(&mut out, 136, close);
                    put64(&mut out, 144, last_packet);
                    put32(&mut out, 152, pending);
                    out[156] = status;
                    out[157] = u8::from(joined);
                    put16(&mut out, 158, duplicates);
                    put64(&mut out, 160, cookie);
                    put64(&mut out, 168, retired);
                }
            }
            Ok(Encoded {
                bytes: out,
                length,
                rights,
                from_go,
            })
        }
        pub(crate) fn decode(
            bytes: &[u8],
            launch: LaunchRecord,
            from_go: bool,
            rights: usize,
        ) -> Result<Self> {
            // Length/direction/rights preflight перед разбором fields/материализацией.
            if !(128..=256).contains(&bytes.len()) {
                return Err(Error::Bounds);
            }
            let (length, required, toward) = match &bytes[..8] {
                b"YNKUCS01" => (192, 1, true),
                b"YNKUCA01" => (160, 0, false),
                b"YNKUAQ01" => (160, 0, true),
                b"YNKUAC01" => (192, 1, false),
                b"YNKUPQ01" => (160, 0, true),
                b"YNKURP01" => (256, 0, false),
                b"YNKUCM01" => (256, 0, true),
                b"YNKUMR01" => (192, 0, false),
                b"YNKUCQ01" => (160, 0, false),
                b"YNKUCR01" => (192, 0, true),
                _ => return Err(Error::Schema),
            };
            if bytes.len() != length || rights != required || from_go != toward {
                return Err(Error::Bounds);
            }
            let a = u64_at(bytes, 128);
            let b = u64_at(bytes, 136);
            let c = u64_at(bytes, 144);
            let record = match &bytes[..8] {
                b"YNKUCS01" => Self::Control {
                    operation: a,
                    proof: b,
                    ingress: u16_at(bytes, 144),
                    tuple: Tuple::read(&mut Reader::new(&bytes[148..188]))?,
                },
                b"YNKUCA01" => Self::ControlAck {
                    operation: a,
                    control: b,
                    cookie: c,
                    remaining: u64_at(bytes, 152),
                },
                b"YNKUAQ01" => Self::Associate {
                    operation: a,
                    control: b,
                    cookie: c,
                },
                b"YNKUAC01" => Self::Associated {
                    operation: a,
                    control: b,
                    association: c,
                    cookie: u64_at(bytes, 152),
                    port: u16_at(bytes, 164),
                },
                b"YNKUPQ01" => Self::Peek {
                    association: a,
                    operation: b,
                    control: c,
                },
                b"YNKURP01" => Self::Permit {
                    packet: Packet::read(bytes)?,
                    remaining: u64_at(bytes, 240),
                },
                b"YNKUCM01" => Self::Consumed {
                    packet: Packet::read(bytes)?,
                    sequence: u64_at(bytes, 240),
                },
                b"YNKUMR01" => Self::Matched {
                    association: a,
                    packet: b,
                    permit: c,
                    sequence: u64_at(bytes, 152),
                    status: bytes[160],
                    remaining: u64_at(bytes, 168),
                },
                b"YNKUCQ01" => Self::Close {
                    association: a,
                    close: b,
                    control: c,
                    reason: u16_at(bytes, 152),
                },
                b"YNKUCR01" => Self::Closed {
                    association: a,
                    close: b,
                    last_packet: c,
                    pending: u32_at(bytes, 152),
                    status: bytes[156],
                    joined: boolean(bytes[157])?,
                    duplicates: u16_at(bytes, 158),
                    cookie: u64_at(bytes, 160),
                    retired: u64_at(bytes, 168),
                },
                _ => return Err(Error::Schema),
            };
            let encoded = record.encode(launch)?;
            if bytes != &encoded.bytes[..encoded.length] {
                return Err(Error::Binding);
            }
            Ok(record)
        }
    }
    pub(crate) fn fingerprint(
        launch: LaunchRecord,
        packet: Packet,
        payload: &[u8],
    ) -> Result<[u8; 32]> {
        if payload.len() != packet.bytes as usize || payload.len() > MAX_DATAGRAM {
            return Err(Error::Bounds);
        }
        let mut h = Sha256::new();
        h.update(b"YNK-UDP-PACKET-v1\0");
        let b = launch.binding;
        h.update(b.digest);
        h.update(b.session);
        h.update(b.invocation);
        h.update(b.generation.to_be_bytes());
        h.update(b.epoch.to_be_bytes());
        h.update(launch.nonce);
        for n in [
            packet.association,
            packet.packet,
            packet.permit,
            packet.cookie,
        ] {
            h.update(n.to_be_bytes());
        }
        let mut tuple = [0; 40];
        packet.tuple.write(&mut Writer {
            bytes: &mut tuple,
            position: 0,
        })?;
        h.update(tuple);
        h.update(packet.bytes.to_be_bytes());
        h.update(payload);
        Ok(h.finalize().into())
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ExecDelivery {
    pub launch: LaunchRecord,
    pub image: [u8; 32],
    pub image_bytes: u64,
    pub config_bytes: u32,
}
impl ExecDelivery {
    pub(crate) fn encode(self) -> Result<[u8; 256]> {
        if self.launch.mode != Mode::System
            || self.image == [0; 32]
            || self.image_bytes == 0
            || self.image_bytes > 128 * 1024 * 1024
            || self.config_bytes == 0
            || self.config_bytes > 65536
        {
            return Err(Error::Bounds);
        }
        self.launch.encode()?;
        let mut out = [0; 256];
        out[..8].copy_from_slice(b"YNKEXC01");
        put16(&mut out, 8, 1);
        put16(&mut out, 10, 256);
        put16(&mut out, 12, 2);
        out[16..128].copy_from_slice(&self.launch.encode()?[16..128]);
        put32(&mut out, 128, self.launch.child_pid);
        put64(&mut out, 136, self.launch.child_start);
        out[144..176].copy_from_slice(&self.image);
        out[176..208].copy_from_slice(&self.launch.binding.digest);
        out[208..240].copy_from_slice(&self.launch.manifest);
        put64(&mut out, 240, self.image_bytes);
        put32(&mut out, 248, self.config_bytes);
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], launch: LaunchRecord) -> Result<Self> {
        if bytes.len() != 256 {
            return Err(Error::Bounds);
        }
        let value = Self {
            launch,
            image: bytes[144..176].try_into().map_err(|_| Error::Bounds)?,
            image_bytes: u64::from_be_bytes(bytes[240..248].try_into().map_err(|_| Error::Bounds)?),
            config_bytes: u32::from_be_bytes(
                bytes[248..252].try_into().map_err(|_| Error::Bounds)?,
            ),
        };
        if value.encode()?.as_slice() != bytes {
            return Err(Error::Binding);
        }
        Ok(value)
    }
    pub(crate) fn ack(self) -> Result<[u8; 40]> {
        extension_ack(b"YNKEXA01", &self.encode()?)
    }
}
pub(crate) fn proof_bootstrap(launch: LaunchRecord) -> Result<[u8; 128]> {
    if launch.mode != Mode::System {
        return Err(Error::Binding);
    }
    let record = launch.encode()?;
    let mut out = [0; 128];
    out[..8].copy_from_slice(b"YNKPF001");
    put16(&mut out, 8, 1);
    put16(&mut out, 10, 128);
    put16(&mut out, 12, 1);
    out[16..].copy_from_slice(&record[16..128]);
    Ok(out)
}
pub(crate) fn proof_bootstrap_ack(launch: LaunchRecord) -> Result<[u8; 40]> {
    extension_ack(b"YNKPFA01", &proof_bootstrap(launch)?)
}
fn extension_ack(magic: &[u8; 8], record: &[u8]) -> Result<[u8; 40]> {
    let mut out = [0; 40];
    out[..8].copy_from_slice(magic);
    out[8..].copy_from_slice(&Sha256::digest(record));
    Ok(out)
}
#[derive(Clone, Copy)]
pub(crate) struct SocketRecord {
    pub request: u64,
    pub proof: u64,
    pub ingress: u16,
    pub tuple: Tuple,
}
impl SocketRecord {
    pub(crate) fn encode(self, launch: LaunchRecord) -> Result<[u8; 192]> {
        proof_bootstrap(launch)?;
        if [self.request, self.proof]
            .iter()
            .any(|id| *id == 0 || *id == u64::MAX)
            || self.tuple.protocol != 6
            || usize::from(self.ingress) >= TABLE_CAPS[4]
        {
            return Err(Error::Schema);
        }
        self.tuple.owner_flow()?;
        let b = launch.binding;
        let mut out = [0; 192];
        out[..8].copy_from_slice(b"YNKSPF01");
        put16(&mut out, 8, 1);
        put16(&mut out, 10, 192);
        put16(&mut out, 12, 1);
        out[16..48].copy_from_slice(&b.digest);
        out[48..64].copy_from_slice(&b.session);
        out[64..80].copy_from_slice(&b.invocation);
        put64(&mut out, 80, b.generation);
        put64(&mut out, 88, b.epoch);
        out[96..128].copy_from_slice(&launch.nonce);
        put64(&mut out, 128, self.request);
        put64(&mut out, 136, self.proof);
        put16(&mut out, 144, self.ingress);
        out[146] = 2;
        self.tuple.write(&mut Writer {
            bytes: &mut out[148..188],
            position: 0,
        })?;
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], launch: LaunchRecord) -> Result<Self> {
        if bytes.len() != 192 {
            return Err(Error::Bounds);
        }
        let value = Self {
            request: u64::from_be_bytes(bytes[128..136].try_into().map_err(|_| Error::Bounds)?),
            proof: u64::from_be_bytes(bytes[136..144].try_into().map_err(|_| Error::Bounds)?),
            ingress: u16::from_be_bytes(bytes[144..146].try_into().map_err(|_| Error::Bounds)?),
            tuple: Tuple::read(&mut Reader::new(&bytes[148..188]))?,
        };
        if value.encode(launch)?.as_slice() != bytes {
            return Err(Error::Binding);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct PeerIdentity {
    pid: u32,
    uid: u32,
    start: u64,
}
struct AncillaryShape {
    credentials: usize,
    rights: usize,
    truncated: bool,
    seqpacket: bool,
    peer: PeerIdentity,
}
impl AncillaryShape {
    /// Только проверка формы. OS wrapper обязан удерживать и проверять pidfd,
    /// закрывать все unexpected rights и получать observation самостоятельно.
    fn validate(&self, expected: PeerIdentity, expected_rights: usize) -> Result<()> {
        if self.credentials != 1
            || self.rights != expected_rights
            || self.truncated
            || !self.seqpacket
            || self.peer != expected
            || expected.pid == 0
            || expected.start == 0
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Bounds,
    Schema,
    Binding,
    Hash,
    Reference,
    Budget,
}
type Result<T> = std::result::Result<T, Error>;

macro_rules! wire_enum {
    ($name:ident, $ty:ty, $($variant:ident = $value:expr),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr($ty)]
        pub(crate) enum $name { $($variant = $value),+ }
        impl TryFrom<$ty> for $name {
            type Error = Error;
            fn try_from(value: $ty) -> Result<Self> {
                match value { $($value => Ok(Self::$variant),)+ _ => Err(Error::Schema) }
            }
        }
    }
}
wire_enum!(Mode, u8, Local = 1, System = 2);
impl Mode {
    pub(crate) fn required(self) -> bool {
        self == Self::System
    }
}
wire_enum!(
    Kind,
    u16,
    Hello = 1,
    Admit = 2,
    AdmitAck = 3,
    OpenIngress = 16,
    IngressReply = 17,
    Authorize = 18,
    Grant = 19,
    Probe = 20,
    Renew = 21,
    Deny = 22,
    Cancel = 32,
    Revoke = 33,
    CloseAck = 34
);
wire_enum!(Status, u8, Allow = 1, Deny = 2, Unknown = 3);
wire_enum!(CloseStatus, u8, KnownClosed = 1, Unknown = 3);
wire_enum!(
    ReceiptKind,
    u8,
    None = 0,
    FrozenSent = 1,
    SidebandOperation = 2
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub session: [u8; 16],
    pub invocation: [u8; 16],
    pub digest: [u8; 32],
    pub generation: u64,
    pub epoch: u64,
}
impl Binding {
    fn validate(self) -> Result<()> {
        if self.session == [0; 16]
            || self.invocation == [0; 16]
            || self.digest == [0; 32]
            || self.generation == 0
            || self.epoch == 0
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Header {
    pub kind: Kind,
    pub sequence: u64,
    pub reply_to: u64,
    pub binding: Binding,
    pub object_id: u64,
}
impl Header {
    pub(crate) fn encode(self, body_len: usize) -> Result<[u8; HEADER]> {
        self.binding.validate()?;
        let total = HEADER
            .checked_add(body_len)
            .filter(|n| *n <= FRAME_LIMIT)
            .ok_or(Error::Bounds)?;
        if self.sequence == 0 {
            return Err(Error::Schema);
        }
        let mut out = [0; HEADER];
        out[..8].copy_from_slice(b"YNKCAP01");
        put16(&mut out, 8, 1);
        put16(&mut out, 10, self.kind as u16);
        put32(&mut out, 12, total as u32);
        put64(&mut out, 16, self.sequence);
        put64(&mut out, 24, self.reply_to);
        out[32..48].copy_from_slice(&self.binding.session);
        out[48..64].copy_from_slice(&self.binding.invocation);
        out[64..96].copy_from_slice(&self.binding.digest);
        put64(&mut out, 96, self.binding.generation);
        put64(&mut out, 104, self.binding.epoch);
        put64(&mut out, 112, self.object_id);
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], total: usize) -> Result<Self> {
        if bytes.len() != HEADER || !(HEADER..=FRAME_LIMIT).contains(&total) {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)? != b"YNKCAP01" || r.u16()? != 1 {
            return Err(Error::Schema);
        }
        let kind_number = r.u16()?;
        // Legacy Header не выдаёт DNS_V2 negotiation. Новые kinds не могут
        // пройти через старый runtime decoder даже с корректным DATA body.
        if dns_v2::Operation::try_from(kind_number).is_ok() {
            return Err(Error::Schema);
        }
        let kind = Kind::try_from(kind_number)?;
        if r.u32()? as usize != total {
            return Err(Error::Bounds);
        }
        let sequence = r.u64()?;
        let reply_to = r.u64()?;
        let binding = Binding {
            session: r.array()?,
            invocation: r.array()?,
            digest: r.array()?,
            generation: r.u64()?,
            epoch: r.u64()?,
        };
        let object_id = r.u64()?;
        r.zero(8)?;
        r.end()?;
        binding.validate()?;
        if sequence == 0 {
            return Err(Error::Schema);
        }
        Ok(Self {
            kind,
            sequence,
            reply_to,
            binding,
            object_id,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchRecord {
    pub mode: Mode,
    pub nonce: [u8; 32],
    pub binding: Binding,
    pub owner_pid: u32,
    pub child_pid: u32,
    pub owner_start: u64,
    pub child_start: u64,
    pub manifest: [u8; 32],
}
impl LaunchRecord {
    pub(crate) fn encode(self) -> Result<[u8; 192]> {
        self.binding.validate()?;
        if self.nonce == [0; 32]
            || self.manifest == [0; 32]
            || self.owner_pid == 0
            || self.owner_start == 0
            || match self.mode {
                Mode::Local => self.child_pid != 0 || self.child_start != 0,
                Mode::System => self.child_pid == 0 || self.child_start == 0,
            }
        {
            return Err(Error::Binding);
        }
        let mut out = [0; 192];
        out[..8].copy_from_slice(match self.mode {
            Mode::Local => b"YNKLOC01",
            Mode::System => b"YNKEXT01",
        });
        put16(&mut out, 8, 1);
        put16(&mut out, 10, 192);
        put16(&mut out, 12, u16::from(self.mode.required()));
        out[16..48].copy_from_slice(&self.nonce);
        out[48..80].copy_from_slice(&self.binding.digest);
        out[80..96].copy_from_slice(&self.binding.session);
        out[96..112].copy_from_slice(&self.binding.invocation);
        put64(&mut out, 112, self.binding.generation);
        put64(&mut out, 120, self.binding.epoch);
        put32(&mut out, 128, self.owner_pid);
        put32(&mut out, 132, self.child_pid);
        put64(&mut out, 136, self.owner_start);
        put64(&mut out, 144, self.child_start);
        out[152..184].copy_from_slice(&self.manifest);
        Ok(out)
    }
    pub(crate) fn decode(bytes: &[u8], expected: Mode) -> Result<Self> {
        if bytes.len() != 192 {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(bytes);
        if r.take(8)?
            != match expected {
                Mode::Local => b"YNKLOC01",
                Mode::System => b"YNKEXT01",
            }
            || r.u16()? != 1
            || r.u16()? != 192
            || r.u16()? != u16::from(expected.required())
        {
            return Err(Error::Schema);
        }
        r.zero(2)?;
        let nonce = r.array()?;
        let digest = r.array()?;
        let session = r.array()?;
        let invocation = r.array()?;
        let binding = Binding {
            digest,
            session,
            invocation,
            generation: r.u64()?,
            epoch: r.u64()?,
        };
        let record = Self {
            mode: expected,
            nonce,
            binding,
            owner_pid: r.u32()?,
            child_pid: r.u32()?,
            owner_start: r.u64()?,
            child_start: r.u64()?,
            manifest: r.array()?,
        };
        r.zero(8)?;
        r.end()?;
        record.encode()?;
        Ok(record)
    }
    pub(crate) fn ack(self) -> Result<[u8; 40]> {
        let mut ack = [0; 40];
        ack[..8].copy_from_slice(b"YNKEXAK1");
        ack[8..].copy_from_slice(&Sha256::digest(self.encode()?));
        Ok(ack)
    }
    pub(crate) fn verify_ack(self, bytes: &[u8]) -> Result<()> {
        if bytes != self.ack()? {
            return Err(Error::Hash);
        }
        Ok(())
    }
}

fn put16(out: &mut [u8], offset: usize, value: u16) {
    out[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

const TABLE_CAPS: [usize; 11] = [256, 512, 1024, 256, 64, 16, 4, 1, 512, 16, 1];
const MAX_CAPS: [u32; 8] = [4096, 128, 128, 64, 8 * 1024 * 1024, 30000, 4096, 256];

struct MemoryPreflight {
    metadata: usize,
    buffer_bytes: usize,
}
impl MemoryPreflight {
    fn new(caps: [u32; 8], capsule_bytes: usize) -> Result<Self> {
        for (actual, max) in caps.iter().zip(MAX_CAPS) {
            if *actual == 0 || *actual > max {
                return Err(Error::Budget);
            }
        }
        // Payload и fixed scratch учитываются одновременно с будущими ledgers.
        let mut metadata = capsule_bytes
            .checked_add(2 * FRAME_LIMIT)
            .and_then(|n| n.checked_add(std::mem::size_of::<Capsule<'_>>() + 32768))
            .ok_or(Error::Budget)?;
        for (count, width) in [
            (caps[3], 2 * 1024),
            (caps[3], 2048),
            (caps[7], 64),
            (caps[6], 768),
            (caps[0], 576),
            (caps[2], 1024),
            (caps[1], 512),
            (caps[0], 128),
            (1, 512 * 1024 + 64 * 1024 + 384 * 1024),
            (caps[0] * 2, 64),
        ] {
            metadata = metadata
                .checked_add((count as usize).checked_mul(width).ok_or(Error::Budget)?)
                .ok_or(Error::Budget)?;
        }
        let buffer_bytes = (caps[4] as usize)
            .checked_sub(metadata)
            .ok_or(Error::Budget)?;
        Ok(Self {
            metadata,
            buffer_bytes,
        })
    }
}

/// Только reference DATA. Владение asset/source проверяет отдельный issuer.
#[derive(Clone, Copy)]
pub(crate) struct SnapshotRef {
    pub source: [u8; 32],
    pub asset: [u8; 32],
    pub bytes: u32,
    pub flags: u32,
}
pub(crate) type AssetReference = (u8, [u8; 32], u64, [u8; 32], u32);
pub(crate) struct ResolverHost {
    pub alias: String,
    pub addresses: Vec<std::net::IpAddr>,
}
/// Только canonical DATA. Source FDs и env/image proofs удерживает producer.
pub(crate) struct ResolverData {
    pub source: [u8; 32],
    pub source_flags: u32,
    pub nss_hash: [u8; 32],
    pub hosts_hash: [u8; 32],
    pub resolv_hash: [u8; 32],
    pub order: u8,
    pub ndots: u8,
    pub attempts: u8,
    pub timeout_ms: u32,
    pub flags: u16,
    pub hostname: String,
    pub search: Vec<String>,
    pub peers: Vec<std::net::SocketAddr>,
    pub hosts: Vec<ResolverHost>,
    pub _memory: crate::helper::memory::ByteLease,
}
impl ResolverData {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.search.len() > 6
            || !(1..=3).contains(&self.peers.len())
            || self.hosts.len() > 4096
            || self.source_flags & !1 != 0
            || self.source_flags == 1 && !self.hosts.is_empty()
        {
            return Err(Error::Budget);
        }
        resolver_name(&self.hostname, false, false)?;
        for search in &self.search {
            resolver_name(search, true, false)?;
        }
        for host in &self.hosts {
            resolver_name(&host.alias, host.alias.contains('.'), true)?;
            if !(1..=16).contains(&host.addresses.len()) {
                return Err(Error::Budget);
            }
        }
        // Worst-case encoded size bounded до reserve: не realloc после overflow.
        let mut size = 170 + self.hostname.len();
        for search in &self.search {
            size = size.checked_add(2 + search.len()).ok_or(Error::Budget)?;
        }
        for peer in &self.peers {
            size = size
                .checked_add(if peer.is_ipv4() { 8 } else { 20 })
                .ok_or(Error::Budget)?;
        }
        for host in &self.hosts {
            size = size
                .checked_add(4 + host.alias.len())
                .ok_or(Error::Budget)?;
            for ip in &host.addresses {
                size = size
                    .checked_add(if ip.is_ipv4() { 5 } else { 17 })
                    .ok_or(Error::Budget)?;
            }
        }
        if size > 2 * 1024 * 1024 {
            return Err(Error::Budget);
        }
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(b"YNKDNS01");
        out.extend_from_slice(&[0, 1, 0, 120]);
        out.extend_from_slice(&(size as u32).to_be_bytes());
        out.extend_from_slice(&self.source);
        out.extend_from_slice(&self.nss_hash);
        out.extend_from_slice(&self.hosts_hash);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&self.resolv_hash);
        out.extend_from_slice(&[self.order, self.ndots, self.attempts, 0]);
        out.extend_from_slice(&self.timeout_ms.to_be_bytes());
        out.extend_from_slice(&self.flags.to_be_bytes());
        string(&mut out, &self.hostname, 253)?;
        out.extend_from_slice(&(self.search.len() as u16).to_be_bytes());
        for search in &self.search {
            string(&mut out, search, 253)?;
        }
        out.extend_from_slice(&(self.peers.len() as u16).to_be_bytes());
        for peer in &self.peers {
            out.extend_from_slice(&[if peer.is_ipv4() { 4 } else { 6 }, 0]);
            out.extend_from_slice(&peer.port().to_be_bytes());
            resolver_ip_write(&mut out, peer.ip());
        }
        out.extend_from_slice(&(self.hosts.len() as u16).to_be_bytes());
        for host in &self.hosts {
            string(&mut out, &host.alias, 253)?;
            out.extend_from_slice(&(host.addresses.len() as u16).to_be_bytes());
            for ip in &host.addresses {
                out.push(if ip.is_ipv4() { 4 } else { 6 });
                resolver_ip_write(&mut out, *ip);
            }
        }
        if out.len() != size {
            return Err(Error::Bounds);
        }
        validate_resolver_asset(&out, self.source, self.source_flags)?;
        Ok(out)
    }
}
fn resolver_ip_write(out: &mut Vec<u8>, ip: std::net::IpAddr) {
    match ip {
        std::net::IpAddr::V4(ip) => out.extend_from_slice(&ip.octets()),
        std::net::IpAddr::V6(ip) => out.extend_from_slice(&ip.octets()),
    }
}
fn resolver_ip_read(r: &mut Reader<'_>, family: u8) -> Result<std::net::IpAddr> {
    match family {
        4 => Ok(std::net::Ipv4Addr::from(r.array::<4>()?).into()),
        6 => {
            let ip = std::net::Ipv6Addr::from(r.array::<16>()?);
            if ip.to_ipv4_mapped().is_some() {
                return Err(Error::Schema);
            }
            Ok(ip.into())
        }
        _ => Err(Error::Schema),
    }
}
pub(crate) fn resolver_name(name: &str, rooted: bool, lowercase: bool) -> Result<()> {
    if name.len() > 253
        || name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || [b'.', b'-', b'_'].contains(&b))
        || rooted && !name.ends_with('.')
        || lowercase && name.bytes().any(|b| b.is_ascii_uppercase())
    {
        return Err(Error::Schema);
    }
    if name != "."
        && name
            .strip_suffix('.')
            .unwrap_or(name)
            .split('.')
            .any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
            })
    {
        return Err(Error::Schema);
    }
    Ok(())
}
/// Zero-allocation readback; source/hash provenance остаётся отдельным proof.
pub(crate) fn verify_resolver_asset(bytes: &[u8], reference: SnapshotRef) -> Result<()> {
    if bytes.len() != reference.bytes as usize
        || bytes.len() > 2 * 1024 * 1024
        || <[u8; 32]>::from(Sha256::digest(bytes)) != reference.asset
    {
        return Err(Error::Hash);
    }
    validate_resolver_asset(bytes, reference.source, reference.flags)
}
pub(crate) fn validate_resolver_asset(
    bytes: &[u8],
    source: [u8; 32],
    source_flags: u32,
) -> Result<()> {
    if !(170..=2 * 1024 * 1024).contains(&bytes.len())
        || source == [0; 32]
        || source_flags & !1 != 0
    {
        return Err(Error::Bounds);
    }
    let mut r = Reader::new(bytes);
    if r.take(8)? != b"YNKDNS01"
        || r.u16()? != 1
        || r.u16()? != 120
        || r.u32()? as usize != bytes.len()
        || r.array::<32>()? != source
    {
        return Err(Error::Schema);
    }
    let nss = r.array::<32>()?;
    let hosts = r.array::<32>()?;
    if nss == [0; 32]
        || hosts == [0; 32]
        || source_flags == 1 && hosts != <[u8; 32]>::from(Sha256::digest([]))
    {
        return Err(Error::Hash);
    }
    r.zero(8)?;
    if r.array::<32>()? == [0; 32] {
        return Err(Error::Hash);
    }
    if !(1..=4).contains(&r.u8()?) || r.u8()? > 15 || !(1..=5).contains(&r.u8()?) {
        return Err(Error::Schema);
    }
    r.zero(1)?;
    if !(1..=30000).contains(&r.u32()?) || r.u16()? & !31 != 0 {
        return Err(Error::Schema);
    }
    resolver_name(r.string(253)?, false, false)?;
    let searches = r.u16()?;
    if searches > 6 {
        return Err(Error::Budget);
    }
    for _ in 0..searches {
        resolver_name(r.string(253)?, true, false)?;
    }
    let peers = r.u16()?;
    if !(1..=3).contains(&peers) {
        return Err(Error::Budget);
    }
    for _ in 0..peers {
        let family = r.u8()?;
        r.zero(1)?;
        if r.u16()? != 53 {
            return Err(Error::Schema);
        }
        let ip = resolver_ip_read(&mut r, family)?;
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip, std::net::IpAddr::V4(ip) if ip.is_broadcast())
            || matches!(ip, std::net::IpAddr::V6(ip) if ip.is_unicast_link_local())
        {
            return Err(Error::Schema);
        }
    }
    let count = r.u16()? as usize;
    if count > 4096 || source_flags == 1 && count != 0 {
        return Err(Error::Budget);
    }
    // Fixed scratch, не heap; сортировка не меняет порядок rows самого asset.
    let mut aliases = [""; 4096];
    for alias in &mut aliases[..count] {
        *alias = r.string(253)?;
        resolver_name(alias, alias.contains('.'), true)?;
        let addresses = r.u16()?;
        if !(1..=16).contains(&addresses) {
            return Err(Error::Budget);
        }
        for _ in 0..addresses {
            let family = r.u8()?;
            resolver_ip_read(&mut r, family)?;
        }
    }
    aliases[..count].sort_unstable();
    if aliases[..count].windows(2).any(|p| p[0] == p[1]) {
        return Err(Error::Reference);
    }
    r.end()
}
pub(crate) struct OwnedCapsule {
    bytes: Vec<u8>,
    _memory: crate::helper::memory::ByteLease,
}
struct Tables {
    rows: [Vec<Vec<u8>>; 11],
    size: usize,
}
impl Tables {
    fn new() -> Self {
        Self {
            rows: std::array::from_fn(|_| Vec::new()),
            size: 128 + 11 * 8,
        }
    }
    fn push(&mut self, table: usize, row: Vec<u8>) -> Result<u16> {
        let rows = &mut self.rows[table];
        if rows.len() >= TABLE_CAPS[table] || row.len() > u16::MAX as usize {
            return Err(Error::Budget);
        }
        self.size = self
            .size
            .checked_add(4 + row.len())
            .filter(|n| *n <= FRAME_LIMIT - HEADER)
            .ok_or(Error::Budget)?;
        let index = rows.len() as u16;
        rows.push(row);
        Ok(index)
    }
    fn endpoint(&mut self, host: &str, port: u16, protocol: u8) -> Result<u16> {
        let mut row = destination_bytes(host, port, protocol)?;
        row.extend_from_slice(&[0; 4]);
        if let Some(index) = self.rows[1].iter().position(|previous| *previous == row) {
            return Ok(index as u16);
        }
        self.push(1, row)
    }
}
fn string(out: &mut Vec<u8>, value: &str, max: usize) -> Result<()> {
    if value.len() > max || value.len() > u16::MAX as usize {
        return Err(Error::Bounds);
    }
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}
fn destination_bytes(host: &str, port: u16, protocol: u8) -> Result<Vec<u8>> {
    network(protocol)?;
    canonical_host(host)?;
    if port == 0 {
        return Err(Error::Schema);
    }
    let mut row = Vec::with_capacity(8 + host.len().max(16));
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            row.extend_from_slice(&[4, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&[0, 4, 0, 0]);
            row.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            row.extend_from_slice(&[6, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&[0, 16, 0, 0]);
            row.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            row.extend_from_slice(&[3, protocol]);
            row.extend_from_slice(&port.to_be_bytes());
            row.extend_from_slice(&(host.len() as u16).to_be_bytes());
            row.extend_from_slice(&[0, 0]);
            row.extend_from_slice(host.as_bytes());
        }
    }
    let mut r = Reader::new(&row);
    Destination::read(&mut r)?;
    r.end()?;
    Ok(row)
}
struct HashWriter(Sha256);
struct BranchDeriver<'a> {
    intent: &'a yonik_engine::native_profile::ProfileIntent,
    names: &'a [String],
    indices: &'a std::collections::BTreeMap<&'a str, u16>,
    remotes:
        &'a std::collections::BTreeMap<&'a str, &'a yonik_engine::native_profile::PhysicalEndpoint>,
    cache: [[[u8; 3]; 2]; 256],
}
impl BranchDeriver<'_> {
    fn mask(
        &mut self,
        subject: u16,
        input: yonik_engine::native_profile::WireNetwork,
        port: Option<u16>,
        depth: usize,
    ) -> Result<u8> {
        use yonik_engine::native_profile::WireNetwork;
        if depth > 256 {
            return Err(Error::Reference);
        }
        let i = usize::from(input == WireNetwork::Udp);
        let p = match port {
            None => 0,
            Some(443) => 1,
            Some(_) => 2,
        };
        let cached = self.cache[subject as usize][i][p];
        if cached == 254 {
            return Err(Error::Reference);
        }
        if cached != 255 {
            return Ok(cached);
        }
        self.cache[subject as usize][i][p] = 254;
        let name = &self.names[subject as usize];
        let mut mask = self
            .intent
            .branch_mask(name, input, port)
            .map_err(|_| Error::Schema)?;
        for b in 0..2 {
            if mask & (1 << b) == 0 {
                continue;
            }
            let projection = self
                .intent
                .project_branch(name, input, b == 1)
                .map_err(|_| Error::Schema)?;
            if let Some(next) = projection.next_subject() {
                let next = *self.indices.get(next).ok_or(Error::Reference)?;
                let port = self
                    .remotes
                    .get(name.as_str())
                    .ok_or(Error::Reference)?
                    .port();
                let carrier = projection.carrier().ok_or(Error::Reference)?;
                if self.mask(next, carrier, Some(port), depth + 1)? == 0 {
                    mask &= !(1 << b);
                }
            }
        }
        self.cache[subject as usize][i][p] = mask;
        Ok(mask)
    }
}
impl std::io::Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl OwnedCapsule {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn build(
        intent: &yonik_engine::native_profile::ProfileIntent,
        plan: &yonik_engine::native_profile::OwnedRuntimePlan,
        snapshot: Option<SnapshotRef>,
        digest: [u8; 32],
        policy_revision: u64,
        admission_id: u64,
    ) -> Result<Self> {
        use yonik_engine::native_profile::{OwnedIngress, ProviderIngressProtocol, WireNetwork};
        // До validate/typed graph/container allocation: один aggregate credit.
        let mut memory = crate::helper::memory::config_budget()
            .reserve(8 * 1024 * 1024)
            .map_err(|_| Error::Budget)?;
        if digest == [0; 32] || policy_revision == 0 || admission_id == 0 {
            return Err(Error::Binding);
        }
        let graph = intent.validate().map_err(|_| Error::Schema)?;
        intent
            .validate_ingress_mapping(plan)
            .map_err(|_| Error::Reference)?;
        let mode = if plan.is_system() {
            Mode::System
        } else {
            Mode::Local
        };
        let names = graph.subjects();
        for endpoint in graph.egress().physical() {
            if (endpoint.host().eq_ignore_ascii_case("localhost")
                || endpoint
                    .host()
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()))
                && [plan.local_port().get(), plan.probe_port().get()].contains(&endpoint.port())
            {
                return Err(Error::Reference);
            }
        }
        let mut t = Tables::new();
        let indices: std::collections::BTreeMap<&str, u16> = names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.as_str(), i as u16))
            .collect();
        let remotes: std::collections::BTreeMap<
            &str,
            &yonik_engine::native_profile::PhysicalEndpoint,
        > = graph
            .egress()
            .subject_endpoints()
            .iter()
            .map(|(n, e)| (n.as_str(), e))
            .collect();
        let mut deriver = BranchDeriver {
            intent,
            names,
            indices: &indices,
            remotes: &remotes,
            cache: [[[255; 3]; 2]; 256],
        };
        for (i, name) in names.iter().enumerate() {
            let (kind, security) = intent.transport_kind(name).map_err(|_| Error::Schema)?;
            let mut hash = HashWriter(Sha256::new());
            hash.0.update(b"YNKCAP-TRANSPORT-v1\0");
            intent
                .write_transport_sensitive(name, &mut hash)
                .map_err(|_| Error::Bounds)?;
            let mut transport = vec![kind as u8, security as u8, 0, 0];
            transport.extend_from_slice(&hash.0.finalize());
            t.push(3, transport)?;
            let mut row = Vec::new();
            string(&mut row, name, 160)?;
            row.extend_from_slice(&[intent.proxy_kind(name).map_err(|_| Error::Schema)?, 0]);
            for index in [i as u16, 2 * i as u16, 2 * i as u16 + 1] {
                row.extend_from_slice(&index.to_be_bytes());
            }
            t.push(0, row)?;
            for input in [WireNetwork::Tcp, WireNetwork::Udp] {
                let mask = deriver.mask(i as u16, input, None, 0)?;
                let mut branches = [Branch::ABSENT; 2];
                for (b, branch) in branches.iter_mut().enumerate() {
                    if mask & (1 << b) == 0 {
                        continue;
                    }
                    let projection = intent
                        .project_branch(name, input, b == 1)
                        .map_err(|_| Error::Schema)?;
                    branch.action = projection.action() as u8;
                    if branch.action == 4 {
                        *branch = Branch::NO_DIAL;
                        continue;
                    }
                    branch.dial = projection.dial().ok_or(Error::Reference)? as u8;
                    branch.carrier = projection.carrier().ok_or(Error::Reference)? as u8;
                    branch.stream = if projection.active_stream() {
                        i as u16
                    } else {
                        NONE
                    };
                    if branch.action == 3 {
                        continue;
                    }
                    let remote = remotes.get(name.as_str()).ok_or(Error::Reference)?;
                    branch.endpoint = t.endpoint(remote.host(), remote.port(), branch.carrier)?;
                    if let Some(next) = projection.next_subject() {
                        let next_subject = *indices.get(next).ok_or(Error::Reference)?;
                        let next_input = projection.carrier().ok_or(Error::Reference)?;
                        let next_scope =
                            2 * next_subject + u16::from(next_input == WireNetwork::Udp);
                        let next_mask =
                            deriver.mask(next_subject, next_input, Some(remote.port()), 0)?;
                        if next_mask == 0 {
                            return Err(Error::Reference);
                        }
                        let mut chain = Vec::new();
                        chain.extend_from_slice(&(t.rows[8].len() as u16).to_be_bytes());
                        chain.extend_from_slice(&next_scope.to_be_bytes());
                        chain.extend_from_slice(&[b as u8, next_mask, 0, 0]);
                        branch.chain = t.push(2, chain)?;
                    } else if !graph.egress().physical().iter().any(|leaf| {
                        leaf.host() == remote.host()
                            && leaf.port() == remote.port()
                            && protocol(leaf.protocol()) == branch.carrier
                    }) {
                        return Err(Error::Reference);
                    }
                }
                let mut row = vec![];
                row.extend_from_slice(&(i as u16).to_be_bytes());
                row.extend_from_slice(&[input as u8, mask]);
                for branch in branches {
                    row.extend_from_slice(&[branch.dial, branch.carrier]);
                }
                for branch in branches {
                    row.extend_from_slice(&branch.endpoint.to_be_bytes());
                }
                for branch in branches {
                    row.extend_from_slice(&branch.stream.to_be_bytes());
                }
                for branch in branches {
                    row.extend_from_slice(&branch.chain.to_be_bytes());
                }
                for branch in branches {
                    row.push(branch.action);
                }
                row.extend_from_slice(&[0, 0]);
                t.push(8, row)?;
            }
        }
        let subject_index = |name: Option<&str>| -> Result<u16> {
            name.map_or(Ok(NONE), |n| {
                indices.get(n).copied().ok_or(Error::Reference)
            })
        };
        for resolver in graph.egress().resolvers() {
            let endpoint = resolver.endpoint();
            let p = protocol(endpoint.protocol());
            let mut row = vec![1, p];
            row.extend_from_slice(&subject_index(resolver.subject())?.to_be_bytes());
            row.extend_from_slice(&[0; 32]);
            row.extend_from_slice(&destination_bytes(endpoint.host(), endpoint.port(), p)?);
            t.push(4, row)?;
        }
        if !graph.egress().system_resolvers().is_empty() {
            let reference = snapshot.ok_or(Error::Reference)?;
            let binding = plan.system_resolver_binding().ok_or(Error::Reference)?;
            if reference.source != *binding.snapshot_digest() {
                return Err(Error::Reference);
            }
            for resolver in graph.egress().system_resolvers() {
                for peer in binding.servers() {
                    for p in [6, 17] {
                        let mut row = vec![2, p];
                        row.extend_from_slice(&subject_index(resolver.subject())?.to_be_bytes());
                        row.extend_from_slice(&reference.source);
                        row.extend_from_slice(&destination_bytes(
                            &peer.ip().to_string(),
                            peer.port(),
                            p,
                        )?);
                        t.push(4, row)?;
                    }
                }
            }
            let mut row = Vec::new();
            row.extend_from_slice(&reference.source);
            row.extend_from_slice(&reference.asset);
            row.extend_from_slice(&reference.bytes.to_be_bytes());
            row.extend_from_slice(&[0, 1, 0, 0]);
            row.extend_from_slice(&reference.flags.to_be_bytes());
            t.push(10, row)?;
        } else if snapshot.is_some() {
            return Err(Error::Reference);
        }
        if plan.resource_bindings().len() != graph.resources().len() {
            return Err(Error::Reference);
        }
        for requirement in graph.resources() {
            let (_, reference) = plan
                .resource_bindings()
                .iter()
                .find(|(r, _)| r == requirement)
                .ok_or(Error::Reference)?;
            reference.validate().map_err(|_| Error::Schema)?;
            if reference.engine != yonik_engine::Engine::Xray
                || reference.kind != requirement.kind()
            {
                return Err(Error::Reference);
            }
            let kind = match requirement.kind() {
                yonik_engine::resource_bundle::ResourceKind::Cidrs => 1,
                yonik_engine::resource_bundle::ResourceKind::Domains => 2,
            };
            let mut row = vec![kind, 0];
            string(&mut row, requirement.category(), 160)?;
            row.extend_from_slice(&reference.digest);
            row.extend_from_slice(&reference.bytes.to_be_bytes());
            t.push(5, row)?;
        }
        for (kind, mask, port, name) in [
            (2, 3, plan.local_port().get(), "yonik-owned-local"),
            (4, 1, plan.probe_port().get(), "yonik-owned-probe"),
        ] {
            let mut row = vec![kind, mask];
            row.extend_from_slice(&port.to_be_bytes());
            string(&mut row, name, 160)?;
            t.push(6, row)?;
        }
        if mode == Mode::System {
            let mut row = vec![1, 3, 0, 0];
            string(&mut row, "system-tun", 160)?;
            t.push(6, row)?;
        }
        for ingress in graph.ingresses() {
            let owned = plan
                .ingress_mappings()
                .find(|(tag, _)| *tag == ingress.tag())
                .map(|(_, o)| o)
                .ok_or(Error::Reference)?;
            let mut row = vec![];
            string(&mut row, ingress.tag(), 128)?;
            row.extend_from_slice(
                &(if owned == OwnedIngress::System {
                    2u16
                } else {
                    0u16
                })
                .to_be_bytes(),
            );
            row.extend_from_slice(&[
                match ingress.protocol() {
                    ProviderIngressProtocol::Socks => 1,
                    ProviderIngressProtocol::Http => 2,
                },
                0,
            ]);
            t.push(9, row)?;
        }
        if let Some(probe) = graph.probe() {
            let url = reqwest::Url::parse(probe.url()).map_err(|_| Error::Schema)?;
            if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
                return Err(Error::Schema);
            }
            let scheme = match url.scheme() {
                "http" => 1,
                "https" => 2,
                _ => return Err(Error::Schema),
            };
            let port = url.port_or_known_default().ok_or(Error::Schema)?;
            let host = url
                .host_str()
                .ok_or(Error::Schema)?
                .trim_matches(['[', ']']);
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            let mut row = vec![scheme, 0];
            row.extend_from_slice(&port.to_be_bytes());
            string(&mut row, host, 253)?;
            string(&mut row, &path, 2048)?;
            row.extend_from_slice(&(probe.subjects().len() as u16).to_be_bytes());
            for name in probe.subjects() {
                row.extend_from_slice(&subject_index(Some(name))?.to_be_bytes());
            }
            t.push(7, row)?;
        }
        let mut bytes = vec![0; 128];
        put64(&mut bytes, 64, admission_id);
        put32(&mut bytes, 72, 60000);
        bytes[76] = mode as u8;
        bytes[77] = u8::from(mode.required());
        put16(&mut bytes, 78, 3);
        put64(&mut bytes, 80, policy_revision);
        for (i, cap) in MAX_CAPS.iter().enumerate() {
            put32(&mut bytes, 88 + 4 * i, *cap);
        }
        put16(&mut bytes, 120, 11);
        bytes
            .try_reserve_exact(t.size - 128)
            .map_err(|_| Error::Budget)?;
        for (i, rows) in t.rows.iter().enumerate() {
            bytes.extend_from_slice(&((i + 1) as u16).to_be_bytes());
            bytes.extend_from_slice(&(rows.len() as u16).to_be_bytes());
            let size = rows.iter().map(|r| r.len() + 4).sum::<usize>();
            bytes.extend_from_slice(&(size as u32).to_be_bytes());
            for row in rows {
                bytes.extend_from_slice(&(row.len() as u16).to_be_bytes());
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(row);
            }
        }
        let mut hash = Sha256::new();
        hash.update(b"YNKCAP-MANIFEST-v1\0");
        hash.update(digest);
        hash.update(&bytes[76..78]);
        hash.update(&bytes[80..120]);
        hash.update(&bytes[128..]);
        bytes[..32].copy_from_slice(&hash.finalize());
        Capsule::decode(&bytes, &digest)?;
        drop(t);
        drop(remotes);
        drop(indices);
        drop(graph);
        memory
            .resize(bytes.capacity() + std::mem::size_of::<Self>())
            .map_err(|_| Error::Budget)?;
        Ok(Self {
            bytes,
            _memory: memory,
        })
    }
}
fn protocol(value: yonik_engine::native_profile::TransportProtocol) -> u8 {
    match value {
        yonik_engine::native_profile::TransportProtocol::Tcp => 6,
        yonik_engine::native_profile::TransportProtocol::Udp => 17,
    }
}

struct Table<'a> {
    bytes: &'a [u8],
    count: u16,
    offsets: [u16; 1024],
}
impl<'a> Table<'a> {
    fn rows(&self) -> Rows<'a> {
        Rows(self.bytes)
    }
    fn row(&self, index: u16) -> Result<&'a [u8]> {
        if index >= self.count {
            return Err(Error::Reference);
        }
        let start = self.offsets[index as usize] as usize;
        let mut r = Reader::new(self.bytes.get(start..).ok_or(Error::Reference)?);
        let n = r.u16()? as usize;
        r.zero(2)?;
        r.take(n)
    }
}
struct Rows<'a>(&'a [u8]);
impl<'a> Iterator for Rows<'a> {
    type Item = &'a [u8];
    fn next(&mut self) -> Option<Self::Item> {
        let prefix = self.0.get(..4)?;
        let n = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
        let row = self.0.get(4..4 + n)?;
        self.0 = self.0.get(4 + n..)?;
        Some(row)
    }
}

/// Zero-copy view: даже malformed caps не вызывают allocations.
pub(crate) struct Capsule<'a> {
    body: &'a [u8],
    tables: [Table<'a>; 11],
    pub mode: Mode,
    pub manifest: [u8; 32],
    pub admission_id: u64,
    pub lease_ms: u32,
    pub policy_revision: u64,
}
pub(crate) struct DialScope<'a> {
    pub input: u8,
    pub action: u8,
    pub endpoint: Option<Destination<'a>>,
    pub endpoint_index: u16,
    pub next: Option<(u16, u8)>,
}
/// Manifest DATA; служебную authority создаёт только trusted runtime issuer.
pub(crate) struct ProbeScope<'a> {
    pub scheme: u8,
    pub port: u16,
    pub host: &'a str,
    pub path: &'a str,
    pub scope: u16,
    pub branches: u8,
}
pub(crate) struct ResolverScope<'a> {
    pub subject: u16,
    pub source: [u8; 32],
    pub peer: Destination<'a>,
    pub scope: Option<(u16, u8)>,
}
impl<'a> Capsule<'a> {
    pub(crate) fn validate_udp_control(&self, index: u16, tuple: Tuple) -> Result<()> {
        let row = self.tables[6].row(index)?;
        if row[0] != 2
            || row[1] & 1 == 0
            || tuple.protocol != 6
            || tuple.family != 4
            || tuple.remote[..4] != [127, 0, 0, 1]
            || tuple.remote_port != u16::from_be_bytes([row[2], row[3]])
        {
            return Err(Error::Reference);
        }
        tuple.owner_flow()?;
        Ok(())
    }
    pub(crate) fn subject_scope(&self, index: u16, protocol: u8) -> Result<(u16, u8)> {
        let subject = subject(self.tables[0].row(index)?)?;
        let index = match protocol {
            6 => subject.tcp,
            17 => subject.udp,
            _ => return Err(Error::Schema),
        };
        let scope = scope_from(&self.tables, index)?;
        Ok((index, scope.mask))
    }
    pub(crate) fn probe_scope(&self, index: u16, subject: u16) -> Result<ProbeScope<'_>> {
        self.validate_request(&Message::Probe {
            purpose: 1,
            index,
            subject,
            resolver: NONE,
        })?;
        let mut r = Reader::new(self.tables[7].row(index)?);
        let scheme = r.u8()?;
        r.zero(1)?;
        let port = r.u16()?;
        let host = r.string(253)?;
        let path = r.string(2048)?;
        let (scope, branches) = self.subject_scope(subject, 6)?;
        Ok(ProbeScope {
            scheme,
            port,
            host,
            path,
            scope,
            branches,
        })
    }
    pub(crate) fn resolver_scope(&self, index: u16) -> Result<ResolverScope<'_>> {
        let mut r = Reader::new(self.tables[4].row(index)?);
        r.u8()?;
        let protocol = r.u8()?;
        let subject = r.u16()?;
        let source = r.array()?;
        let peer = Destination::read(&mut r)?;
        r.end()?;
        let scope = if subject == NONE {
            None
        } else {
            Some(self.subject_scope(subject, protocol)?)
        };
        Ok(ResolverScope {
            subject,
            source,
            peer,
            scope,
        })
    }
    pub(crate) fn bootstrap_query(
        &self,
        index: u16,
        subject: u16,
        resolver: u16,
    ) -> Result<Destination<'_>> {
        self.validate_request(&Message::Probe {
            purpose: 2,
            index,
            subject,
            resolver,
        })?;
        // Row reference не разрешает hostname другого subject/chain frontier.
        let mut owned = false;
        for protocol in [6, 17] {
            let (scope, mask) = self.subject_scope(subject, protocol)?;
            for branch in 0..2 {
                if mask & (1 << branch) != 0
                    && self.dial_scope(scope, branch)?.endpoint_index == index
                {
                    owned = true;
                }
            }
        }
        if !owned {
            return Err(Error::Reference);
        }
        self.endpoint(index)
    }
    pub(crate) fn limits(&self) -> [u32; 8] {
        std::array::from_fn(|i| {
            let p = 88 + i * 4;
            u32::from_be_bytes([
                self.body[p],
                self.body[p + 1],
                self.body[p + 2],
                self.body[p + 3],
            ])
        })
    }
    pub(crate) fn buffer_credit(&self) -> Result<usize> {
        Ok(MemoryPreflight::new(self.limits(), self.body.len())?.buffer_bytes)
    }
    pub(crate) fn dial_scope(&self, index: u16, branch: u8) -> Result<DialScope<'_>> {
        if branch > 1 {
            return Err(Error::Reference);
        }
        let scope = scope_from(&self.tables, index)?;
        if scope.mask & (1 << branch) == 0 {
            return Err(Error::Reference);
        }
        let b = scope.branches[branch as usize];
        let endpoint = if b.endpoint == NONE {
            None
        } else {
            Some(Destination::read(&mut Reader::new(
                self.tables[1].row(b.endpoint)?,
            ))?)
        };
        let next = if b.chain == NONE {
            None
        } else {
            let c = chain(self.tables[2].row(b.chain)?)?;
            Some((c.next, c.mask))
        };
        Ok(DialScope {
            input: scope.input,
            action: b.action,
            endpoint,
            endpoint_index: b.endpoint,
            next,
        })
    }
    pub(crate) fn endpoint(&self, index: u16) -> Result<Destination<'_>> {
        Destination::read(&mut Reader::new(self.tables[1].row(index)?))
    }
    pub(crate) fn resolver_peer(&self, index: u16) -> Result<Destination<'_>> {
        let mut r = Reader::new(self.tables[4].row(index)?);
        r.take(36)?;
        Destination::read(&mut r)
    }
    pub(crate) fn decode(body: &'a [u8], digest: &[u8; 32]) -> Result<Self> {
        if body.len() < 128 || body.len() > FRAME_LIMIT - HEADER {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(body);
        let manifest = r.array()?;
        let _previous: [u8; 32] = r.array()?;
        let admission_id = r.u64()?;
        let lease_ms = r.u32()?;
        let mode = Mode::try_from(r.u8()?)?;
        if r.u8()? != u8::from(mode.required()) || r.u16()? != 3 {
            return Err(Error::Schema);
        }
        let policy_revision = r.u64()?;
        let mut caps = [0; 8];
        for cap in &mut caps {
            *cap = r.u32()?;
        }
        MemoryPreflight::new(caps, body.len())?;
        if r.u16()? != 11 {
            return Err(Error::Schema);
        }
        r.zero(6)?;
        if admission_id == 0 || lease_ms == 0 || lease_ms > 60000 || policy_revision == 0 {
            return Err(Error::Schema);
        }
        let mut tables = std::array::from_fn(|_| Table {
            bytes: &[][..],
            count: 0,
            offsets: [0; 1024],
        });
        for (i, table) in tables.iter_mut().enumerate() {
            if r.u16()? != (i + 1) as u16 {
                return Err(Error::Schema);
            }
            let count = r.u16()?;
            let len = r.u32()? as usize;
            if count as usize > TABLE_CAPS[i] {
                return Err(Error::Budget);
            }
            let bytes = r.take(len)?;
            let mut rows = Reader::new(bytes);
            for i in 0..count {
                table.offsets[i as usize] = rows.position as u16;
                let n = rows.u16()? as usize;
                rows.zero(2)?;
                rows.take(n)?;
            }
            rows.end()?;
            table.bytes = bytes;
            table.count = count;
        }
        r.end()?;
        let mut h = Sha256::new();
        h.update(b"YNKCAP-MANIFEST-v1\0");
        h.update(digest);
        h.update(&body[76..78]);
        h.update(&body[80..120]);
        h.update(&body[128..]);
        if <[u8; 32]>::from(h.finalize()) != manifest {
            return Err(Error::Hash);
        }
        let out = Self {
            body,
            tables,
            mode,
            manifest,
            admission_id,
            lease_ms,
            policy_revision,
        };
        out.validate()?;
        Ok(out)
    }
    fn validate(&self) -> Result<()> {
        let t = &self.tables;
        if t[0].count == 0
            || t[0].count != t[3].count
            || usize::from(t[8].count) != usize::from(t[0].count) * 2
            || t[6].count == 0
        {
            return Err(Error::Reference);
        }
        let mut names = [""; 256];
        for (i, row) in t[0].rows().enumerate() {
            let s = subject(row)?;
            names[i] = s.name;
            if s.stream != i as u16 || s.tcp != 2 * i as u16 || s.udp != 2 * i as u16 + 1 {
                return Err(Error::Reference);
            }
        }
        names[..t[0].count as usize].sort_unstable();
        if names[..t[0].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        for row in t[1].rows() {
            let mut r = Reader::new(row);
            Destination::read(&mut r)?;
            r.zero(4)?;
            r.end()?;
        }
        for row in t[3].rows() {
            let mut r = Reader::new(row);
            if !(1..=4).contains(&r.u8()?) || r.u8()? > 2 {
                return Err(Error::Schema);
            }
            r.zero(2)?;
            let hash: [u8; 32] = r.array()?;
            if hash == [0; 32] {
                return Err(Error::Hash);
            }
            r.end()?;
        }
        let mut chain_seen = [false; 1024];
        for (i, row) in t[8].rows().enumerate() {
            let scope = scope(row)?;
            if scope.subject != i as u16 / 2 || scope.input != if i % 2 == 0 { 6 } else { 17 } {
                return Err(Error::Reference);
            }
            for (b, branch) in scope.branches.iter().enumerate() {
                if scope.mask & (1 << b) == 0 {
                    if *branch != Branch::ABSENT {
                        return Err(Error::Reference);
                    }
                    continue;
                }
                let kind = subject(t[0].row(scope.subject)?)?.kind;
                if branch.action == 4 {
                    if *branch != Branch::NO_DIAL || kind != 6 && kind != 7 {
                        return Err(Error::Reference);
                    }
                    continue;
                }
                network(branch.dial)?;
                network(branch.carrier)?;
                if kind == 6
                    || kind == 7
                    || matches!(kind, 1 | 4) && branch.dial != 6
                    || matches!(kind, 2 | 3 | 5)
                        && branch.dial != if b == 1 { 6 } else { scope.input }
                    || kind == 4 && branch.carrier != 17
                {
                    return Err(Error::Reference);
                }
                if branch.dial == 17 && (branch.carrier != 17 || branch.stream != NONE)
                    || branch.dial == 6 && branch.stream != scope.subject
                {
                    return Err(Error::Reference);
                }
                if branch.action == 3 {
                    if branch.endpoint != NONE
                        || branch.chain != NONE
                        || subject(t[0].row(scope.subject)?)?.kind != 5
                    {
                        return Err(Error::Reference);
                    }
                } else {
                    let mut r = Reader::new(t[1].row(branch.endpoint)?);
                    let endpoint = Destination::read(&mut r)?;
                    if endpoint.protocol != branch.carrier {
                        return Err(Error::Reference);
                    }
                    match branch.action {
                        1 => {
                            if branch.chain != NONE {
                                return Err(Error::Reference);
                            }
                        }
                        2 => {
                            let c = chain(t[2].row(branch.chain)?)?;
                            if c.source != i as u16
                                || c.branch != b as u8
                                || c.mask == 0
                                || c.mask & !3 != 0
                            {
                                return Err(Error::Reference);
                            }
                            let next = scope_from(t, c.next)?;
                            if next.input != branch.carrier || c.mask & !next.mask != 0 {
                                return Err(Error::Reference);
                            }
                            if chain_seen[branch.chain as usize] {
                                return Err(Error::Reference);
                            }
                            chain_seen[branch.chain as usize] = true;
                        }
                        _ => return Err(Error::Schema),
                    }
                }
            }
        }
        if chain_seen[..t[2].count as usize].iter().any(|seen| !*seen) {
            return Err(Error::Reference);
        }
        // Acyclic проверяется по subject graph, независимо от input/branch.
        let mut edges = [NONE; 256];
        for row in t[2].rows() {
            let c = chain(row)?;
            let source = (c.source / 2) as usize;
            let next = c.next / 2;
            if edges[source] != NONE && edges[source] != next {
                return Err(Error::Reference);
            }
            edges[source] = next;
        }
        let n = t[0].count as usize;
        let mut indegree = [0u16; 256];
        for next in &edges[..n] {
            if *next != NONE {
                indegree[*next as usize] += 1;
            }
        }
        let mut queue = [0usize; 256];
        let mut end = 0;
        let mut completed = 0;
        for (i, degree) in indegree[..n].iter().enumerate() {
            if *degree == 0 {
                queue[end] = i;
                end += 1;
            }
        }
        while completed < end {
            let next = edges[queue[completed]];
            completed += 1;
            if next != NONE {
                let i = next as usize;
                indegree[i] -= 1;
                if indegree[i] == 0 {
                    queue[end] = i;
                    end += 1;
                }
            }
        }
        if completed != n {
            return Err(Error::Reference);
        }
        self.validate_auxiliary()
    }
}

fn network(n: u8) -> Result<()> {
    if n != 6 && n != 17 {
        return Err(Error::Schema);
    }
    Ok(())
}
impl Capsule<'_> {
    /// Отдельная authority boundary: динамический UDP port принимается лишь
    /// вместе с retained actual child socket proof; metadata assertion не proof.
    pub(crate) fn validate_associated_request(
        &self,
        message: &Message<'_>,
        proof: &crate::helper::native_profile_channel::SocketProof,
    ) -> Result<()> {
        let Message::OpenIngress {
            ingress,
            provenance,
            tuple,
            original,
        } = message
        else {
            return Err(Error::Reference);
        };
        let row = self.tables[6].row(*ingress)?;
        if row[0] != 2
            || row[1] & 2 == 0
            || *provenance != 3
            || tuple.protocol != 17
            || original.protocol != 17
        {
            return Err(Error::Reference);
        }
        proof
            .validate_association(*tuple, *original)
            .map_err(|_| Error::Binding)
    }
    pub(crate) fn validate_asset_refs(&self, assets: &[AssetReference]) -> Result<()> {
        if assets.len() > 16 {
            return Err(Error::Budget);
        }
        let mut used = [false; 16];
        for row in self.tables[5].rows() {
            let mut r = Reader::new(row);
            let kind = r.u8()?;
            r.zero(1)?;
            r.string(160)?;
            let digest = r.array::<32>()?;
            let bytes = r.u64()?;
            let index = assets
                .iter()
                .position(|a| *a == (kind, digest, bytes, [0; 32], 0))
                .ok_or(Error::Reference)?;
            used[index] = true;
        }
        for row in self.tables[10].rows() {
            let mut r = Reader::new(row);
            let source = r.array::<32>()?;
            let asset = r.array::<32>()?;
            let bytes = u64::from(r.u32()?);
            r.take(4)?;
            let flags = r.u32()?;
            let index = assets
                .iter()
                .position(|a| *a == (3, asset, bytes, source, flags))
                .ok_or(Error::Reference)?;
            used[index] = true;
        }
        if used[..assets.len()].iter().any(|used| !used) {
            return Err(Error::Reference);
        }
        Ok(())
    }
    /// Проверяет DATA scope запроса. Peer/ingress/owner authority выдаёт issuer.
    pub(crate) fn validate_request(&self, message: &Message<'_>) -> Result<()> {
        let t = &self.tables;
        match message {
            Message::OpenIngress {
                ingress,
                provenance,
                tuple,
                original,
            } => {
                let row = t[6].row(*ingress)?;
                let kind = row[0];
                let mask = row[1];
                let port = u16::from_be_bytes([row[2], row[3]]);
                let bit = if tuple.protocol == 6 { 1 } else { 2 };
                if mask & bit == 0
                    || kind == 4
                    || (kind == 1) != (*provenance == 1)
                    || *provenance == 2 && tuple.remote_port != port
                    || kind!=1 && (tuple.family!=4 || tuple.remote[..4]!=[127,0,0,1] || original.protocol!=tuple.protocol)
                    // UDP association требует отдельного retained socket proof.
                    // OPEN_INGRESS assertion и TCP attribution его не заменяют.
                    || *provenance == 3
                    || kind == 3 && *provenance != 2
                {
                    return Err(Error::Reference);
                }
                if kind == 1
                    && (original.protocol != tuple.protocol
                        || original.port != tuple.remote_port
                        || original.family != tuple.family
                        || original.bytes
                            != &tuple.remote[..if tuple.family == 4 { 4 } else { 16 }])
                {
                    return Err(Error::Reference);
                }
            }
            Message::Authorize(a) => {
                if a.branch > 1 || a.class != 1 && a.class != 3 {
                    return Err(Error::Schema);
                }
                if self.mode == Mode::Local && a.receipt.kind != ReceiptKind::None {
                    return Err(Error::Binding);
                }
                if a.class == 1 {
                    let scope = scope_from(t, a.scope)?;
                    if scope.subject != a.subject || scope.mask & (1 << a.branch) == 0 {
                        return Err(Error::Reference);
                    }
                    let branch = scope.branches[a.branch as usize];
                    if branch.action == 4 || branch.stream != a.transport || branch.chain != a.chain
                    {
                        return Err(Error::Reference);
                    }
                } else {
                    if a.receipt.kind != ReceiptKind::None
                        || a.receipt.id != 0
                        || a.source_flow == 0
                        || [a.subject, a.chain, a.transport, a.scope] != [NONE; 4]
                        || a.branch != 0
                    {
                        return Err(Error::Reference);
                    }
                    hostname(a.query)?;
                    if a.query.bytes().any(|b| b.is_ascii_uppercase()) {
                        return Err(Error::Schema);
                    }
                    let destination = self.resolver_peer(a.resolver)?;
                    if destination != a.effective {
                        return Err(Error::Reference);
                    }
                }
            }
            Message::Probe {
                purpose,
                index,
                subject,
                resolver,
            } => {
                if *purpose == 1 {
                    if *resolver != NONE {
                        return Err(Error::Reference);
                    }
                    let mut r = Reader::new(t[7].row(*index)?);
                    r.take(4)?;
                    r.string(253)?;
                    r.string(2048)?;
                    let count = r.u16()?;
                    let mut found = false;
                    for _ in 0..count {
                        found |= r.u16()? == *subject;
                    }
                    if !found {
                        return Err(Error::Reference);
                    }
                } else if *purpose == 2 {
                    let mut r = Reader::new(t[1].row(*index)?);
                    let endpoint = Destination::read(&mut r)?;
                    if endpoint.family != 3 {
                        return Err(Error::Reference);
                    }
                    t[4].row(*resolver)?;
                    if *subject != NONE {
                        t[0].row(*subject)?;
                    }
                } else {
                    return Err(Error::Schema);
                }
            }
            _ => return Err(Error::Schema),
        }
        Ok(())
    }
    fn validate_auxiliary(&self) -> Result<()> {
        let t = &self.tables;
        let mut snapshot = None;
        let mut asset_bytes = 0u64;
        let mut assets = [([0u8; 32], 0u64, 0u8); 16];
        let mut unique = 0usize;
        if t[10].count == 1 {
            let mut r = Reader::new(t[10].row(0)?);
            let source: [u8; 32] = r.array()?;
            let asset: [u8; 32] = r.array()?;
            let bytes = r.u32()?;
            if source == [0; 32]
                || asset == [0; 32]
                || !(120..=2 * 1024 * 1024).contains(&bytes)
                || r.u16()? != 1
            {
                return Err(Error::Schema);
            }
            r.zero(2)?;
            if r.u32()? & !1 != 0 {
                return Err(Error::Schema);
            }
            r.end()?;
            snapshot = Some(source);
            assets[0] = (asset, bytes as u64, 0);
            unique = 1;
            asset_bytes = bytes as u64;
        }
        let mut system_rows = 0;
        for row in t[4].rows() {
            let mut r = Reader::new(row);
            let backend = r.u8()?;
            let protocol = r.u8()?;
            network(protocol)?;
            let s = r.u16()?;
            if s != NONE {
                t[0].row(s)?;
            }
            let hash: [u8; 32] = r.array()?;
            let dest = Destination::read(&mut r)?;
            r.end()?;
            if dest.protocol != protocol {
                return Err(Error::Reference);
            }
            match backend {
                1 => {
                    if hash != [0; 32] {
                        return Err(Error::Reference);
                    }
                }
                2 => {
                    if snapshot != Some(hash) {
                        return Err(Error::Reference);
                    }
                    system_rows += 1;
                }
                _ => return Err(Error::Schema),
            }
        }
        if snapshot.is_some() != (system_rows > 0) {
            return Err(Error::Reference);
        }
        let mut resource_keys = [(0u8, ""); 16];
        for (i, row) in t[5].rows().enumerate() {
            let mut r = Reader::new(row);
            let kind = r.u8()?;
            if kind != 1 && kind != 2 {
                return Err(Error::Schema);
            }
            r.zero(1)?;
            let category = r.string(160)?;
            if category.is_empty()
                || !category.is_ascii()
                || category.bytes().any(|b| b.is_ascii_control())
            {
                return Err(Error::Schema);
            }
            resource_keys[i] = (kind, category);
            let hash: [u8; 32] = r.array()?;
            let bytes = r.u64()?;
            r.end()?;
            if hash == [0; 32] || bytes == 0 || bytes > 64 * 1024 * 1024 {
                return Err(Error::Budget);
            }
            if let Some((_, existing, existing_kind)) =
                assets[..unique].iter().find(|(h, _, _)| *h == hash)
            {
                if *existing != bytes || *existing_kind != kind {
                    return Err(Error::Reference);
                }
            } else {
                if unique == 16 {
                    return Err(Error::Budget);
                }
                assets[unique] = (hash, bytes, kind);
                unique += 1;
                asset_bytes = asset_bytes
                    .checked_add(bytes)
                    .filter(|n| *n <= 64 * 1024 * 1024)
                    .ok_or(Error::Budget)?;
            }
        }
        resource_keys[..t[5].count as usize].sort_unstable();
        if resource_keys[..t[5].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        let mut ingress_names = [""; 4];
        let mut has_tun = false;
        for (i, row) in t[6].rows().enumerate() {
            let mut r = Reader::new(row);
            let kind = r.u8()?;
            let mask = r.u8()?;
            let port = r.u16()?;
            let name = r.string(160)?;
            r.end()?;
            if !(1..=4).contains(&kind)
                || mask == 0
                || mask & !3 != 0
                || name.is_empty()
                || name.chars().any(char::is_control)
            {
                return Err(Error::Schema);
            }
            if kind == 1 {
                if has_tun || self.mode != Mode::System || mask != 3 || port != 0 {
                    return Err(Error::Reference);
                }
                has_tun = true;
            } else if port == 0 || (kind == 3 || kind == 4) && mask != 1 {
                return Err(Error::Reference);
            }
            ingress_names[i] = name;
        }
        if self.mode.required() != has_tun {
            return Err(Error::Reference);
        }
        ingress_names[..t[6].count as usize].sort_unstable();
        if ingress_names[..t[6].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        let mut aliases = [""; 16];
        for (i, row) in t[9].rows().enumerate() {
            let mut r = Reader::new(row);
            let tag = r.string(128)?;
            let ingress = r.u16()?;
            let protocol = r.u8()?;
            r.zero(1)?;
            r.end()?;
            if tag.is_empty() || tag.chars().any(char::is_control) || protocol != 1 && protocol != 2
            {
                return Err(Error::Schema);
            }
            let owned = t[6].row(ingress)?;
            if owned[0] != 1 && owned[0] != 2 && owned[0] != 3 {
                return Err(Error::Reference);
            }
            aliases[i] = tag;
        }
        aliases[..t[9].count as usize].sort_unstable();
        if aliases[..t[9].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        for row in t[7].rows() {
            let mut r = Reader::new(row);
            let scheme = r.u8()?;
            if scheme != 1 && scheme != 2 {
                return Err(Error::Schema);
            }
            r.zero(1)?;
            if r.u16()? == 0 {
                return Err(Error::Schema);
            }
            let host = r.string(253)?;
            canonical_host(host)?;
            let path = r.string(2048)?;
            if !path.starts_with('/')
                || path.bytes().any(|b| b.is_ascii_control())
                || path.contains('#')
            {
                return Err(Error::Schema);
            }
            let count = r.u16()?;
            if count == 0 || count > t[0].count {
                return Err(Error::Budget);
            }
            let mut seen = [false; 256];
            for _ in 0..count {
                let i = r.u16()?;
                t[0].row(i)?;
                if seen[i as usize] {
                    return Err(Error::Reference);
                }
                seen[i as usize] = true;
            }
            r.end()?;
        }
        let mut physical = [false; 512];
        for row in t[8].rows() {
            for b in scope(row)?.branches {
                if b.action == 1 {
                    physical[b.endpoint as usize] = true;
                }
            }
        }
        if physical.iter().filter(|b| **b).count() > 128 {
            return Err(Error::Budget);
        }
        // Row bytes уже bounded; sorted borrowed refs не копируют payload.
        let mut endpoints = [&[][..]; 512];
        for (i, row) in t[1].rows().enumerate() {
            endpoints[i] = row;
        }
        endpoints[..t[1].count as usize].sort_unstable();
        if endpoints[..t[1].count as usize]
            .windows(2)
            .any(|w| w[0] == w[1])
        {
            return Err(Error::Reference);
        }
        Ok(())
    }
}
fn canonical_host(host: &str) -> Result<()> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if ip.is_unspecified()
            || ip.is_multicast()
            || matches!(ip,std::net::IpAddr::V6(v) if v.to_ipv4_mapped().is_some())
        {
            return Err(Error::Schema);
        }
        Ok(())
    } else {
        hostname(host)
    }
}
fn hostname(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 253
        || !name.is_ascii()
        || name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(Error::Schema);
    }
    Ok(())
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Destination<'a> {
    pub protocol: u8,
    pub port: u16,
    pub family: u8,
    pub bytes: &'a [u8],
}
impl<'a> Destination<'a> {
    fn read(r: &mut Reader<'a>) -> Result<Self> {
        let family = r.u8()?;
        let protocol = r.u8()?;
        network(protocol)?;
        let port = r.u16()?;
        let n = r.u16()? as usize;
        r.zero(2)?;
        if port == 0 || n > 253 {
            return Err(Error::Schema);
        }
        let bytes = r.take(n)?;
        let destination = Self {
            protocol,
            port,
            family,
            bytes,
        };
        destination.validate_original()?;
        Ok(destination)
    }
    pub(crate) fn validate_original(self) -> Result<()> {
        let Self {
            protocol,
            port,
            family,
            bytes,
        } = self;
        network(protocol)?;
        let n = bytes.len();
        if port == 0 || n > 253 {
            return Err(Error::Schema);
        }
        match family {
            3 => {
                let host = std::str::from_utf8(bytes).map_err(|_| Error::Schema)?;
                if host.parse::<std::net::IpAddr>().is_ok() {
                    return Err(Error::Schema);
                }
                hostname(host)?;
            }
            4 if n == 4 => {
                let ip = std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(bytes).map_err(|_| Error::Schema)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
                    return Err(Error::Schema);
                }
            }
            6 if n == 16 => {
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(bytes).map_err(|_| Error::Schema)?,
                );
                if ip.is_unspecified() || ip.is_multicast() || ip.to_ipv4_mapped().is_some() {
                    return Err(Error::Schema);
                }
            }
            _ => return Err(Error::Schema),
        }
        Ok(())
    }
}
struct Subject<'a> {
    name: &'a str,
    kind: u8,
    stream: u16,
    tcp: u16,
    udp: u16,
}
fn subject(row: &[u8]) -> Result<Subject<'_>> {
    let mut r = Reader::new(row);
    let name = r.string(160)?;
    if name.is_empty() || name.chars().any(char::is_control) {
        return Err(Error::Schema);
    }
    let kind = r.u8()?;
    if !(1..=7).contains(&kind) {
        return Err(Error::Schema);
    }
    r.zero(1)?;
    let out = Subject {
        name,
        kind,
        stream: r.u16()?,
        tcp: r.u16()?,
        udp: r.u16()?,
    };
    r.end()?;
    Ok(out)
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct Branch {
    dial: u8,
    carrier: u8,
    endpoint: u16,
    stream: u16,
    chain: u16,
    action: u8,
}
impl Branch {
    const ABSENT: Self = Self {
        dial: 0,
        carrier: 0,
        endpoint: NONE,
        stream: NONE,
        chain: NONE,
        action: 0,
    };
    const NO_DIAL: Self = Self {
        action: 4,
        ..Self::ABSENT
    };
}
struct Scope {
    subject: u16,
    input: u8,
    mask: u8,
    branches: [Branch; 2],
}
fn scope(row: &[u8]) -> Result<Scope> {
    let mut r = Reader::new(row);
    let subject = r.u16()?;
    let input = r.u8()?;
    network(input)?;
    let mask = r.u8()?;
    if mask & !3 != 0 {
        return Err(Error::Schema);
    }
    let mut branches = [Branch::ABSENT; 2];
    for b in &mut branches {
        b.dial = r.u8()?;
        b.carrier = r.u8()?;
    }
    for b in &mut branches {
        b.endpoint = r.u16()?;
    }
    for b in &mut branches {
        b.stream = r.u16()?;
    }
    for b in &mut branches {
        b.chain = r.u16()?;
    }
    for b in &mut branches {
        b.action = r.u8()?;
    }
    r.zero(2)?;
    r.end()?;
    Ok(Scope {
        subject,
        input,
        mask,
        branches,
    })
}
fn scope_from(t: &[Table<'_>; 11], index: u16) -> Result<Scope> {
    scope(t[8].row(index)?)
}
struct Chain {
    source: u16,
    next: u16,
    branch: u8,
    mask: u8,
}
fn chain(row: &[u8]) -> Result<Chain> {
    let mut r = Reader::new(row);
    let out = Chain {
        source: r.u16()?,
        next: r.u16()?,
        branch: r.u8()?,
        mask: r.u8()?,
    };
    r.zero(2)?;
    r.end()?;
    if out.branch > 1 {
        return Err(Error::Schema);
    }
    Ok(out)
}
fn put32(out: &mut [u8], offset: usize, value: u32) {
    out[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
fn put64(out: &mut [u8], offset: usize, value: u64) {
    out[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(n)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(Error::Bounds)?;
        let out = &self.bytes[self.position..end];
        self.position = end;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Error::Bounds)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.array::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    fn zero(&mut self, n: usize) -> Result<()> {
        if self.take(n)?.iter().any(|b| *b != 0) {
            return Err(Error::Schema);
        }
        Ok(())
    }
    fn end(self) -> Result<()> {
        if self.position != self.bytes.len() {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    fn string(&mut self, max: usize) -> Result<&'a str> {
        let n = self.u16()? as usize;
        if n > max {
            return Err(Error::Bounds);
        }
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::Schema)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Receipt {
    pub kind: ReceiptKind,
    pub id: u64,
}
impl Receipt {
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let kind = ReceiptKind::try_from(r.u8()?)?;
        r.zero(7)?;
        let id = r.u64()?;
        if (kind == ReceiptKind::None) != (id == 0) {
            return Err(Error::Schema);
        }
        Ok(Self { kind, id })
    }
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.u8(self.kind as u8)?;
        w.take(&[0; 7])?;
        w.u64(self.id)
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Tuple {
    pub protocol: u8,
    pub family: u8,
    pub local_port: u16,
    pub remote_port: u16,
    pub local: [u8; 16],
    pub remote: [u8; 16],
}
impl Tuple {
    /// Wire уже initiator→ingress. Меняется только family namespace для broker;
    /// перестановка endpoints атрибутировала бы accepted socket самого Xray.
    pub(crate) fn owner_flow(self) -> Result<crate::attribution::broker::Flow> {
        network(self.protocol)?;
        let family = match self.family {
            4 => 2,
            6 => 10,
            _ => return Err(Error::Schema),
        };
        if self.local_port == 0
            || self.remote_port == 0
            || self.family == 4
                && (self.local[4..].iter().any(|b| *b != 0)
                    || self.remote[4..].iter().any(|b| *b != 0))
        {
            return Err(Error::Schema);
        }
        Ok(crate::attribution::broker::Flow {
            family,
            protocol: self.protocol,
            local_port: self.local_port,
            remote_port: self.remote_port,
            local: self.local,
            remote: self.remote,
            cookie: None,
        })
    }
    fn read(r: &mut Reader<'_>) -> Result<Self> {
        let protocol = r.u8()?;
        network(protocol)?;
        let family = r.u8()?;
        r.zero(2)?;
        let out = Self {
            protocol,
            family,
            local_port: r.u16()?,
            remote_port: r.u16()?,
            local: r.array()?,
            remote: r.array()?,
        };
        if out.local_port == 0 || out.remote_port == 0 {
            return Err(Error::Schema);
        }
        for address in [&out.local, &out.remote] {
            let n = match family {
                4 => {
                    if address[4..].iter().any(|b| *b != 0) {
                        return Err(Error::Schema);
                    }
                    4
                }
                6 => 16,
                _ => return Err(Error::Schema),
            };
            let mut bytes = [0u8; 24];
            bytes[..2].copy_from_slice(&[family, protocol]);
            put16(&mut bytes, 2, 1);
            put16(&mut bytes, 4, n as u16);
            bytes[8..8 + n].copy_from_slice(&address[..n]);
            Destination::read(&mut Reader::new(&bytes[..8 + n]))?;
        }
        Ok(out)
    }
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.take(&[self.protocol, self.family, 0, 0])?;
        w.u16(self.local_port)?;
        w.u16(self.remote_port)?;
        w.take(&self.local)?;
        w.take(&self.remote)
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Authorize<'a> {
    pub source_flow: u64,
    pub class: u8,
    pub subject: u16,
    pub chain: u16,
    pub transport: u16,
    pub scope: u16,
    pub branch: u8,
    pub original: Destination<'a>,
    pub effective: Destination<'a>,
    pub resolver: u16,
    pub query: &'a str,
    pub receipt: Receipt,
}
pub(crate) enum Message<'a> {
    Hello {
        nonce: [u8; 32],
        mode: Mode,
    },
    Admit(&'a [u8]),
    AdmitAck {
        manifest: [u8; 32],
        admission: u64,
        status: Status,
    },
    OpenIngress {
        ingress: u16,
        provenance: u8,
        tuple: Tuple,
        original: Destination<'a>,
    },
    IngressReply {
        status: Status,
        required: bool,
        flow: u64,
        revision: u64,
    },
    Authorize(Authorize<'a>),
    Grant {
        status: Status,
        class: u8,
        required: bool,
        grant: u64,
        flow: u64,
        lease: u32,
        revision: u64,
        fresh: u64,
        receipt: Receipt,
    },
    Probe {
        purpose: u16,
        index: u16,
        subject: u16,
        resolver: u16,
    },
    Renew {
        admission: u64,
        manifest: [u8; 32],
    },
    Deny {
        status: Status,
        reason: u8,
    },
    Cancel {
        target: u8,
        reason: u8,
        id: u64,
    },
    Revoke {
        reason: u16,
    },
    CloseAck {
        target: u8,
        status: CloseStatus,
        id: u64,
    },
}
impl<'a> Message<'a> {
    fn decode(kind: Kind, body: &'a [u8]) -> Result<Self> {
        if kind != Kind::Admit && body.len() > 1024 {
            return Err(Error::Bounds);
        }
        let mut r = Reader::new(body);
        let out = match kind {
            Kind::Hello => {
                let nonce = r.array()?;
                let mode = Mode::try_from(r.u8()?)?;
                r.zero(7)?;
                if nonce == [0; 32] {
                    return Err(Error::Binding);
                }
                Self::Hello { nonce, mode }
            }
            Kind::Admit => {
                if body.len() < 128 || body.len() > FRAME_LIMIT - HEADER {
                    return Err(Error::Bounds);
                }
                r.take(body.len())?;
                Self::Admit(body)
            }
            Kind::AdmitAck => {
                let manifest = r.array()?;
                let admission = r.u64()?;
                let status = Status::try_from(r.u8()?)?;
                r.zero(7)?;
                if manifest == [0; 32] || admission == 0 {
                    return Err(Error::Schema);
                }
                Self::AdmitAck {
                    manifest,
                    admission,
                    status,
                }
            }
            Kind::OpenIngress => {
                let ingress = r.u16()?;
                let provenance = r.u8()?;
                r.zero(1)?;
                if !(1..=3).contains(&provenance) {
                    return Err(Error::Schema);
                }
                let tuple = Tuple::read(&mut r)?;
                let original = Destination::read(&mut r)?;
                if tuple.protocol != original.protocol
                    || provenance == 2 && tuple.protocol != 6
                    || provenance == 3 && tuple.protocol != 17
                {
                    return Err(Error::Reference);
                }
                Self::OpenIngress {
                    ingress,
                    provenance,
                    tuple,
                    original,
                }
            }
            Kind::IngressReply => {
                let status = Status::try_from(r.u8()?)?;
                let required = boolean(r.u8()?)?;
                r.zero(2)?;
                let flow = r.u64()?;
                if r.u32()? != 0 {
                    return Err(Error::Schema);
                }
                let revision = r.u64()?;
                if (status == Status::Allow) != (flow != 0)
                    || status == Status::Allow && revision == 0
                {
                    return Err(Error::Schema);
                }
                Self::IngressReply {
                    status,
                    required,
                    flow,
                    revision,
                }
            }
            Kind::Authorize => {
                let source_flow = r.u64()?;
                let class = r.u8()?;
                r.zero(1)?;
                let subject = r.u16()?;
                let chain = r.u16()?;
                let transport = r.u16()?;
                let scope = r.u16()?;
                let branch = r.u8()?;
                r.zero(1)?;
                let original = Destination::read(&mut r)?;
                let effective = Destination::read(&mut r)?;
                let resolver = r.u16()?;
                let query = r.string(253)?;
                let receipt = Receipt::read(&mut r)?;
                if source_flow == 0 || branch > 1 {
                    return Err(Error::Schema);
                }
                match class {
                    1 => {
                        if subject == NONE || scope == NONE || resolver != NONE || !query.is_empty()
                        {
                            return Err(Error::Reference);
                        }
                    }
                    3 => {
                        if [subject, chain, transport, scope] != [NONE; 4]
                            || branch != 0
                            || resolver == NONE
                        {
                            return Err(Error::Reference);
                        }
                        hostname(query)?;
                    }
                    _ => return Err(Error::Schema),
                }
                Self::Authorize(Authorize {
                    source_flow,
                    class,
                    subject,
                    chain,
                    transport,
                    scope,
                    branch,
                    original,
                    effective,
                    resolver,
                    query,
                    receipt,
                })
            }
            Kind::Grant => {
                let status = Status::try_from(r.u8()?)?;
                let class = r.u8()?;
                let required = boolean(r.u8()?)?;
                r.zero(1)?;
                let grant = r.u64()?;
                let flow = r.u64()?;
                let lease = r.u32()?;
                let revision = r.u64()?;
                let fresh = r.u64()?;
                let receipt = Receipt::read(&mut r)?;
                if !(1..=3).contains(&class)
                    || fresh > 20_000_000
                    || lease > 1000
                    || status == Status::Allow && (grant == 0 || lease == 0 || revision == 0)
                    || status == Status::Allow && class == 1 && flow == 0
                    || flow == 0 && (required || fresh != 0 || receipt.kind != ReceiptKind::None)
                    || status != Status::Allow && (grant != 0 || lease != 0)
                    || class == 2
                        && (flow != 0
                            || required
                            || fresh != 0
                            || receipt.kind != ReceiptKind::None)
                    || !required && (fresh != 0 || receipt.kind != ReceiptKind::None)
                    || required
                        && status == Status::Allow
                        && (fresh == 0 || receipt.kind == ReceiptKind::None)
                {
                    return Err(Error::Schema);
                }
                Self::Grant {
                    status,
                    class,
                    required,
                    grant,
                    flow,
                    lease,
                    revision,
                    fresh,
                    receipt,
                }
            }
            Kind::Probe => {
                let purpose = r.u16()?;
                let index = r.u16()?;
                let subject = r.u16()?;
                let resolver = r.u16()?;
                if purpose != 1 && purpose != 2
                    || purpose == 1 && resolver != NONE
                    || purpose == 2 && resolver == NONE
                {
                    return Err(Error::Schema);
                }
                Self::Probe {
                    purpose,
                    index,
                    subject,
                    resolver,
                }
            }
            Kind::Renew => {
                let admission = r.u64()?;
                let manifest = r.array()?;
                if admission == 0 || manifest == [0; 32] {
                    return Err(Error::Schema);
                }
                Self::Renew {
                    admission,
                    manifest,
                }
            }
            Kind::Deny => {
                let status = Status::try_from(r.u8()?)?;
                let reason = r.u8()?;
                r.zero(6)?;
                if status == Status::Allow {
                    return Err(Error::Schema);
                }
                Self::Deny { status, reason }
            }
            Kind::Cancel => {
                let target = r.u8()?;
                let reason = r.u8()?;
                r.zero(2)?;
                let id = r.u64()?;
                target_id(target, id)?;
                Self::Cancel { target, reason, id }
            }
            Kind::Revoke => {
                let reason = r.u16()?;
                r.zero(6)?;
                Self::Revoke { reason }
            }
            Kind::CloseAck => {
                let target = r.u8()?;
                let status = CloseStatus::try_from(r.u8()?)?;
                r.zero(2)?;
                let id = r.u64()?;
                target_id(target, id)?;
                Self::CloseAck { target, status, id }
            }
        };
        r.end()?;
        Ok(out)
    }
    fn encode(&self, out: &mut [u8]) -> Result<usize> {
        let mut w = Writer {
            bytes: out,
            position: 0,
        };
        match self {
            Self::Hello { nonce, mode } => {
                w.take(nonce)?;
                w.u8(*mode as u8)?;
                w.take(&[0; 7])?;
            }
            Self::Admit(bytes) => w.take(bytes)?,
            Self::AdmitAck {
                manifest,
                admission,
                status,
            } => {
                w.take(manifest)?;
                w.u64(*admission)?;
                w.u8(*status as u8)?;
                w.take(&[0; 7])?;
            }
            Self::OpenIngress {
                ingress,
                provenance,
                tuple,
                original,
            } => {
                w.u16(*ingress)?;
                w.take(&[*provenance, 0])?;
                tuple.write(&mut w)?;
                original.write(&mut w)?;
            }
            Self::IngressReply {
                status,
                required,
                flow,
                revision,
            } => {
                w.take(&[*status as u8, u8::from(*required), 0, 0])?;
                w.u64(*flow)?;
                w.u32(0)?;
                w.u64(*revision)?;
            }
            Self::Authorize(a) => {
                w.u64(a.source_flow)?;
                w.take(&[a.class, 0])?;
                for i in [a.subject, a.chain, a.transport, a.scope] {
                    w.u16(i)?;
                }
                w.take(&[a.branch, 0])?;
                a.original.write(&mut w)?;
                a.effective.write(&mut w)?;
                w.u16(a.resolver)?;
                w.string(a.query, 253)?;
                a.receipt.write(&mut w)?;
            }
            Self::Grant {
                status,
                class,
                required,
                grant,
                flow,
                lease,
                revision,
                fresh,
                receipt,
            } => {
                w.take(&[*status as u8, *class, u8::from(*required), 0])?;
                w.u64(*grant)?;
                w.u64(*flow)?;
                w.u32(*lease)?;
                w.u64(*revision)?;
                w.u64(*fresh)?;
                receipt.write(&mut w)?;
            }
            Self::Probe {
                purpose,
                index,
                subject,
                resolver,
            } => {
                for i in [purpose, index, subject, resolver] {
                    w.u16(*i)?;
                }
            }
            Self::Renew {
                admission,
                manifest,
            } => {
                w.u64(*admission)?;
                w.take(manifest)?;
            }
            Self::Deny { status, reason } => {
                w.take(&[*status as u8, *reason])?;
                w.take(&[0; 6])?;
            }
            Self::Cancel { target, reason, id } => {
                w.take(&[*target, *reason, 0, 0])?;
                w.u64(*id)?;
            }
            Self::Revoke { reason } => {
                w.u16(*reason)?;
                w.take(&[0; 6])?;
            }
            Self::CloseAck { target, status, id } => {
                w.take(&[*target, *status as u8, 0, 0])?;
                w.u64(*id)?;
            }
        }
        let n = w.position;
        Message::decode(self.kind(), &out[..n])?;
        Ok(n)
    }
    fn kind(&self) -> Kind {
        match self {
            Self::Hello { .. } => Kind::Hello,
            Self::Admit(_) => Kind::Admit,
            Self::AdmitAck { .. } => Kind::AdmitAck,
            Self::OpenIngress { .. } => Kind::OpenIngress,
            Self::IngressReply { .. } => Kind::IngressReply,
            Self::Authorize(_) => Kind::Authorize,
            Self::Grant { .. } => Kind::Grant,
            Self::Probe { .. } => Kind::Probe,
            Self::Renew { .. } => Kind::Renew,
            Self::Deny { .. } => Kind::Deny,
            Self::Cancel { .. } => Kind::Cancel,
            Self::Revoke { .. } => Kind::Revoke,
            Self::CloseAck { .. } => Kind::CloseAck,
        }
    }
}
fn boolean(n: u8) -> Result<bool> {
    match n {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::Schema),
    }
}
fn target_id(target: u8, id: u64) -> Result<()> {
    if !(1..=4).contains(&target) || (target == 4) != (id == 0) {
        return Err(Error::Schema);
    }
    Ok(())
}
impl Destination<'_> {
    fn write(self, w: &mut Writer<'_>) -> Result<()> {
        w.take(&[self.family, self.protocol])?;
        w.u16(self.port)?;
        w.u16(self.bytes.len() as u16)?;
        w.u16(0)?;
        w.take(self.bytes)
    }
}
struct Writer<'a> {
    bytes: &'a mut [u8],
    position: usize,
}
impl Writer<'_> {
    fn take(&mut self, bytes: &[u8]) -> Result<()> {
        let end = self
            .position
            .checked_add(bytes.len())
            .filter(|n| *n <= self.bytes.len())
            .ok_or(Error::Bounds)?;
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
        Ok(())
    }
    fn u8(&mut self, n: u8) -> Result<()> {
        self.take(&[n])
    }
    fn u16(&mut self, n: u16) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn u32(&mut self, n: u32) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn u64(&mut self, n: u64) -> Result<()> {
        self.take(&n.to_be_bytes())
    }
    fn string(&mut self, value: &str, max: usize) -> Result<()> {
        if value.len() > max {
            return Err(Error::Bounds);
        }
        self.u16(value.len() as u16)?;
        self.take(value.as_bytes())
    }
}

pub(crate) struct Frame<'a> {
    pub header: Header,
    pub message: Message<'a>,
}
impl<'a> Frame<'a> {
    pub(crate) fn encode(header: Header, message: &Message<'_>, out: &mut [u8]) -> Result<usize> {
        if header.kind != message.kind() {
            return Err(Error::Schema);
        }
        let limit = FRAME_LIMIT.min(out.len());
        let body = out.get_mut(HEADER..limit).ok_or(Error::Bounds)?;
        let n = message.encode(body)?;
        let wire = header.encode(n)?;
        out[..HEADER].copy_from_slice(&wire);
        Ok(HEADER + n)
    }
    pub(crate) fn decode(
        bytes: &'a [u8],
        binding: Binding,
        mode: Mode,
        from_host: bool,
    ) -> Result<Self> {
        if bytes.len() >= HEADER {
            let kind = u16::from_be_bytes([bytes[10], bytes[11]]);
            if dns_v2::Operation::try_from(kind).is_ok() {
                dns_v2::preflight(kind, &bytes[HEADER..])?;
                return Err(Error::Schema);
            }
        }
        let header = Header::decode(bytes.get(..HEADER).ok_or(Error::Bounds)?, bytes.len())?;
        if header.binding != binding {
            return Err(Error::Binding);
        }
        let message = Message::decode(header.kind, &bytes[HEADER..])?;
        let host_kind = matches!(
            header.kind,
            Kind::Admit | Kind::IngressReply | Kind::Grant | Kind::Deny | Kind::Revoke
        );
        if !matches!(header.kind, Kind::Cancel | Kind::CloseAck) && host_kind != from_host {
            return Err(Error::Schema);
        }
        match &message {
            Message::Hello { mode: actual, .. } => {
                if *actual != mode || header.reply_to != 0 || header.object_id != 0 {
                    return Err(Error::Binding);
                }
            }
            Message::Admit(body) => {
                if Capsule::decode(body, &binding.digest)?.mode != mode
                    || header.object_id != 0
                    || header.reply_to == 0
                {
                    return Err(Error::Binding);
                }
            }
            Message::Grant {
                status,
                required,
                grant,
                flow,
                ..
            } => {
                if header.object_id != *grant
                    || header.reply_to == 0
                    || mode == Mode::Local && *required
                    || mode == Mode::System && *flow != 0 && *status == Status::Allow && !required
                {
                    return Err(Error::Binding);
                }
            }
            Message::IngressReply { required, .. } => {
                if *required != mode.required() || header.object_id != 0 || header.reply_to == 0 {
                    return Err(Error::Binding);
                }
            }
            Message::Authorize(a) => {
                if header.reply_to != 0
                    || mode == Mode::Local && a.receipt.kind != ReceiptKind::None
                {
                    return Err(Error::Binding);
                }
            }
            Message::AdmitAck { .. } | Message::Deny { .. } | Message::CloseAck { .. } => {
                if header.reply_to == 0 || header.object_id != 0 {
                    return Err(Error::Schema);
                }
            }
            Message::Probe { .. } => {
                if header.reply_to != 0 {
                    return Err(Error::Schema);
                }
            }
            Message::OpenIngress { .. }
            | Message::Renew { .. }
            | Message::Cancel { .. }
            | Message::Revoke { .. } => {
                if header.object_id != 0 || header.reply_to != 0 {
                    return Err(Error::Schema);
                }
            }
        }
        Ok(Self { header, message })
    }
}

/// Отдельно от object/request IDs. Ошибка навсегда закрывает decoder direction.
pub(crate) struct Sequence {
    next: u64,
    revoked: bool,
}
impl Sequence {
    pub(crate) fn new() -> Self {
        Self {
            next: 1,
            revoked: false,
        }
    }
    pub(crate) fn accept(&mut self, sequence: u64) -> Result<()> {
        if self.revoked || sequence != self.next || sequence == u64::MAX {
            self.revoked = true;
            return Err(Error::Binding);
        }
        self.next += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    fn dns_v2_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn dns_v2_fields(out: &mut [u8], fields: &serde_json::Value) {
        for f in fields.as_array().unwrap() {
            let at = f[0].as_u64().unwrap() as usize;
            let bytes = match f[1].as_str().unwrap() {
                "hex" => dns_v2_hex(f[2].as_str().unwrap()),
                "fill" => vec![f[2][0].as_u64().unwrap() as u8; f[2][1].as_u64().unwrap() as usize],
                "u8" => vec![f[2].as_u64().unwrap() as u8],
                "u16" => (f[2].as_u64().unwrap() as u16).to_be_bytes().to_vec(),
                "u32" => (f[2].as_u64().unwrap() as u32).to_be_bytes().to_vec(),
                "u64" => f[2].as_u64().unwrap().to_be_bytes().to_vec(),
                _ => panic!("Неизвестный fixture field type"),
            };
            out[at..at + bytes.len()].copy_from_slice(&bytes);
        }
    }
    fn dns_v2_corpus() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/dns-v2-canonical.json"
        ))
        .unwrap()
    }
    #[test]
    fn dns_v2_canonical_all_operations_roundtrip_stdlib_goldens() {
        use super::dns_v2::{
            Direction, DnsFrame, Envelope, Negotiated, Operation, PhysicalPacket, Record,
        };
        let corpus = dns_v2_corpus();
        for (i, v) in corpus["vectors"].as_array().unwrap().iter().enumerate() {
            let name = v["name"].as_str().unwrap();
            let kind = v["kind"].as_u64().unwrap() as u16;
            let op = Operation::try_from(kind).unwrap();
            let mut body = vec![0; v["size"].as_u64().unwrap() as usize];
            dns_v2_fields(&mut body, &v["fields"]);
            if let Some(hex) = v["bodyHex"].as_str() {
                assert_eq!(body, dns_v2_hex(hex), "{name}");
            }
            assert_eq!(
                super::Sha256::digest(&body).as_slice(),
                dns_v2_hex(v["bodySha256"].as_str().unwrap()),
                "{name}"
            );
            let record = Record::decode(op, &body).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            let mut output = vec![0xaa; body.len() + 8];
            assert_eq!(record.encode(&mut output).unwrap(), body.len());
            assert_eq!(&output[..body.len()], body.as_slice());
            assert_eq!(&output[body.len()..], &[0xaa; 8]);
            assert!(record.encode(&mut output[..body.len() - 1]).is_err());
            for len in 0..body.len() {
                assert!(
                    Record::decode(op, &body[..len]).is_err(),
                    "{name} trunc {len}"
                );
            }
            let mut trailing = body.clone();
            trailing.push(0);
            assert!(Record::decode(op, &trailing).is_err(), "{name} trailing");
            let mode = super::Mode::try_from(v["mode"].as_u64().unwrap() as u8).unwrap();
            let n = &corpus["negotiations"][v["mode"].as_u64().unwrap() as usize - 1];
            let launch =
                super::LaunchRecord::decode(&dns_v2_hex(n["launchHex"].as_str().unwrap()), mode)
                    .unwrap();
            let descriptor = dns_v2_hex(n["descriptorHex"].as_str().unwrap());
            let ack = dns_v2_hex(n["ackHex"].as_str().unwrap());
            let neg = Negotiated::accept(&descriptor, &ack, launch, [(0, 0); 2]).unwrap();
            if kind == 52 {
                let proof = PhysicalPacket::decode(&body, &neg, 1, 1).unwrap();
                let mut packet = vec![0; 192];
                assert_eq!(proof.encode(&neg, &mut packet).unwrap(), 192);
                assert_eq!(packet, dns_v2_hex(v["frameHex"].as_str().unwrap()));
                assert_eq!(
                    super::Sha256::digest(&packet).as_slice(),
                    dns_v2_hex(v["frameSha256"].as_str().unwrap())
                );
                assert!(PhysicalPacket::decode(&packet, &neg, 0, 0).is_err());
                assert!(PhysicalPacket::decode(&packet, &neg, 2, 1).is_err());
                assert!(PhysicalPacket::decode(&packet, &neg, 1, 2).is_err());
                for len in 0..192 {
                    assert!(PhysicalPacket::decode(&packet[..len], &neg, 1, 1).is_err());
                }
                assert!(super::Frame::decode(&packet, launch.binding, mode, false).is_err());
                assert!(
                    DnsFrame {
                        header: Envelope {
                            sequence: 1,
                            reply_to: 0,
                            binding: launch.binding
                        },
                        record
                    }
                    .encode(&neg, &mut vec![0; 320])
                    .is_err()
                );
                continue;
            }
            let issuer = op.is_reply();
            let reply = issuer.then_some(9);
            let frame = DnsFrame {
                header: Envelope {
                    sequence: 100 + i as u64,
                    reply_to: reply.unwrap_or(0),
                    binding: launch.binding,
                },
                record,
            };
            let mut packet = vec![0; 128 + body.len()];
            frame.encode(&neg, &mut packet).unwrap();
            if let Some(hex) = v["frameHex"].as_str() {
                assert_eq!(packet, dns_v2_hex(hex), "{name}");
            }
            assert_eq!(
                super::Sha256::digest(&packet).as_slice(),
                dns_v2_hex(v["frameSha256"].as_str().unwrap()),
                "{name}"
            );
            let direction = if issuer {
                Direction::Issuer
            } else {
                Direction::Producer
            };
            let (rights, credentials) = op.rights();
            let decoded =
                DnsFrame::decode(&packet, &neg, direction, rights, credentials, reply).unwrap();
            assert_eq!(decoded.record.operation(), op);
            assert_eq!(decoded.record.bytes(), body);
            assert!(
                super::Frame::decode(&packet, launch.binding, mode, issuer).is_err(),
                "legacy {name}"
            );
            for (at, value) in [
                (0, 0),
                (8, 1),
                (12, 255),
                (16, 0),
                (32, 255),
                (112, 1),
                (120, 1),
            ] {
                let mut bad = packet.clone();
                bad[at] = value;
                if bad != packet {
                    assert!(
                        DnsFrame::decode(&bad, &neg, direction, rights, credentials, reply)
                            .is_err(),
                        "{name} header {at}"
                    );
                }
            }
            assert!(
                DnsFrame::decode(&packet, &neg, direction, rights + 1, credentials, reply).is_err()
            );
            assert!(
                DnsFrame::decode(&packet, &neg, direction, rights, credentials + 1, reply).is_err()
            );
            if issuer {
                assert!(
                    DnsFrame::decode(&packet, &neg, direction, rights, credentials, Some(10))
                        .is_err()
                );
            }
            if kind == 52 {
                assert!(DnsFrame::decode(&packet, &neg, direction, 0, 0, reply).is_err());
            }
        }
    }
    #[test]
    fn dns_v2_descriptor_exact_binding_ack_rights_and_no_downgrade() {
        use super::dns_v2::Negotiated;
        let corpus = dns_v2_corpus();
        for n in corpus["negotiations"].as_array().unwrap() {
            let mode = super::Mode::try_from(n["mode"].as_u64().unwrap() as u8).unwrap();
            let launch =
                super::LaunchRecord::decode(&dns_v2_hex(n["launchHex"].as_str().unwrap()), mode)
                    .unwrap();
            let d = dns_v2_hex(n["descriptorHex"].as_str().unwrap());
            let ack = dns_v2_hex(n["ackHex"].as_str().unwrap());
            assert_eq!(Negotiated::descriptor(launch).unwrap().as_slice(), d);
            assert_eq!(Negotiated::ack(&d).unwrap().as_slice(), ack);
            let mut old = d.clone();
            old[208..240].copy_from_slice(&sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-1\0"));
            let mut old_ack = [0; 40];
            old_ack[..8].copy_from_slice(b"DNSACK02");
            old_ack[8..].copy_from_slice(&sha2::Sha256::digest(&old));
            assert!(Negotiated::accept(&old, &old_ack, launch, [(0, 0); 2]).is_err());
            for len in 0..d.len() {
                assert!(Negotiated::ack(&d[..len]).is_err());
            }
            for at in [
                0, 8, 10, 12, 16, 208, 240, 242, 244, 248, 250, 252, 254, 256, 258, 271,
            ] {
                let mut bad = d.clone();
                bad[at] ^= 1;
                assert!(
                    Negotiated::accept(&bad, &ack, launch, [(0, 0); 2]).is_err(),
                    "descriptor {at}"
                );
            }
            for at in 0..40 {
                let mut bad = ack.clone();
                bad[at] ^= 1;
                assert!(Negotiated::accept(&d, &bad, launch, [(0, 0); 2]).is_err());
            }
            for a in [
                [(1, 0), (0, 0)],
                [(0, 1), (0, 0)],
                [(0, 0), (1, 0)],
                [(0, 0), (0, 1)],
            ] {
                assert!(Negotiated::accept(&d, &ack, launch, a).is_err());
            }
            let mut other = launch;
            other.manifest[0] ^= 1;
            assert!(Negotiated::accept(&d, &ack, other, [(0, 0); 2]).is_err());
            assert!(super::Frame::decode(&d, launch.binding, mode, true).is_err());
        }
    }
    #[test]
    fn dns_v2_bundle_views_preserve_actual_choices_and_renewal_identity() {
        use super::dns_v2::View;
        let corpus = dns_v2_corpus();
        for (name, renewal, count) in [
            ("bundle-acquire-initial", false, 1),
            ("bundle-acquire-renew", true, 2),
            ("bundle-acquire-max", false, 256),
        ] {
            let case = corpus["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == name)
                .unwrap();
            let mut body = vec![0; case["size"].as_u64().unwrap() as usize];
            dns_v2_fields(&mut body, &case["fields"]);
            let view = View::<55>::decode(&body).unwrap();
            assert_eq!(view.query().unwrap().get(), 11);
            assert_eq!(view.grant().unwrap().get(), 13);
            assert_eq!(view.renewal().unwrap().is_some(), renewal);
            if let Some((bundle, revision)) = view.renewal().unwrap() {
                assert_eq!((bundle.get(), revision.get()), (12, 1));
            }
            assert_eq!(
                view.base().len(),
                usize::from(u16::from_be_bytes([body[48], body[49]]))
            );
            assert!(!view.original().is_empty());
            assert_eq!(
                view.path().collect::<Vec<_>>(),
                (0..count).map(|i| (i, (i % 2) as u8)).collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn dns_v2_negative_corpus_bounds_reserved_counts_and_typed_namespaces() {
        use super::dns_v2::{Operation, Record, SnapshotRoleView, View};
        let corpus = dns_v2_corpus();
        for rejected in corpus["rejectedBodies"].as_array().unwrap() {
            let case = corpus["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == rejected["case"])
                .unwrap();
            let mut body = vec![0; case["size"].as_u64().unwrap() as usize];
            dns_v2_fields(&mut body, &case["fields"]);
            dns_v2_fields(&mut body, &rejected["patches"]);
            body.resize(
                body.len() + rejected["appendZeroBytes"].as_u64().unwrap() as usize,
                0,
            );
            assert!(
                Record::decode(
                    Operation::try_from(case["kind"].as_u64().unwrap() as u16).unwrap(),
                    &body
                )
                .is_err(),
                "{rejected}"
            );
        }
        for row in corpus["snapshotRows"].as_array().unwrap() {
            let bytes = dns_v2_hex(row["hex"].as_str().unwrap());
            let view = SnapshotRoleView::decode(4, &bytes).unwrap();
            let flags = row["flags"].as_u64().unwrap();
            assert_eq!(view.application(), flags & 2 != 0);
            assert_eq!(view.bootstrap(), flags & 4 != 0);
            assert_eq!(view.asset_reference().flags, u32::from(flags & 1 != 0));
            assert!(SnapshotRoleView::decode(3, &bytes).is_err());
            for f in [0, 1, 8, 255] {
                let mut bad = bytes.clone();
                bad[75] = f;
                assert!(SnapshotRoleView::decode(4, &bad).is_err());
            }
        }
        for n in [0, 1, 34, 49, 50, 51, 57, 65535] {
            assert!(Operation::try_from(n).is_err());
        }
        let mut waiter = [0; 64];
        waiter[1] = 2;
        for (at, value) in [(8, 72u64), (16, 71), (32, 73), (56, 1000)] {
            waiter[at..at + 8].copy_from_slice(&value.to_be_bytes());
        }
        let producer = View::<53>::decode(&waiter).unwrap().producer().unwrap();
        assert_eq!(producer.get(), 71);
        // ProducerRRsetId не имеет implicit conversion в WaiterReceiptId;
        // отдельный getter выдаёт только typed id из WaiterBound/Numeric.
        let numeric = corpus["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "numeric-class-1-use-1")
            .unwrap();
        let body = dns_v2_hex(numeric["bodyHex"].as_str().unwrap());
        assert_eq!(
            View::<42>::decode(&body).unwrap().waiter().unwrap().get(),
            74
        );
    }
    #[test]
    fn dns_v2_negative_frames_exact_pending_launch_epoch_and_ancillary() {
        use super::dns_v2::{Direction, DnsFrame, Negotiated, Operation, PhysicalPacket};
        let corpus = dns_v2_corpus();
        let n = &corpus["negotiations"][0];
        let launch = super::LaunchRecord::decode(
            &dns_v2_hex(n["launchHex"].as_str().unwrap()),
            super::Mode::Local,
        )
        .unwrap();
        let neg = Negotiated::accept(
            &dns_v2_hex(n["descriptorHex"].as_str().unwrap()),
            &dns_v2_hex(n["ackHex"].as_str().unwrap()),
            launch,
            [(0, 0); 2],
        )
        .unwrap();
        for rejected in corpus["rejectedFrames"].as_array().unwrap() {
            let v = corpus["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .find(|v| v["name"] == rejected["case"])
                .unwrap();
            let mut frame = dns_v2_hex(v["frameHex"].as_str().unwrap());
            dns_v2_fields(&mut frame, &rejected["patches"]);
            let op = Operation::try_from(v["kind"].as_u64().unwrap() as u16).unwrap();
            let (r, c) = op.rights();
            let r = rejected["rights"].as_u64().map_or(r, |n| n as usize);
            let c = rejected["credentials"].as_u64().map_or(c, |n| n as usize);
            if op == Operation::PhysicalBind {
                assert!(
                    PhysicalPacket::decode(&frame, &neg, r, c).is_err(),
                    "{rejected}"
                );
                continue;
            }
            assert!(
                DnsFrame::decode(
                    &frame,
                    &neg,
                    if op.is_reply() {
                        Direction::Issuer
                    } else {
                        Direction::Producer
                    },
                    r,
                    c,
                    op.is_reply().then_some(9)
                )
                .is_err(),
                "{rejected}"
            );
        }
    }
    #[test]
    fn dns_v2_hosts_requires_nonzero_snapshot_identity() {
        let mut b = vec![0; 144 + 138];
        b[1] = 2;
        b[4..6].fill(255);
        b[19] = 1;
        b[43] = 1;
        b[136] = 3;
        b[137] = 2;
        b[142] = 6;
        let t = &mut b[144..];
        t[..8].copy_from_slice(b"DNHOST02");
        t[9] = 2;
        t[11] = 138;
        t[87] = 1;
        t[95] = 1;
        t[103] = 1;
        t[109] = 1;
        t[111] = 4;
        t[113] = 4;
        t[121] = 6;
        t[123] = 80;
        t[128..132].copy_from_slice(b"host");
        t[132..136].copy_from_slice(b"Host");
        assert!(super::dns_v2::preflight(40, &b).is_err());
        b[44..76].fill(1);
        b[76..108].fill(2);
        b[160..192].fill(1);
        b[192..224].fill(2);
        super::dns_v2::preflight(40, &b).unwrap();
        for len in 0..b.len() {
            assert!(super::dns_v2::preflight(40, &b[..len]).is_err());
        }
        for at in [144 + 104, 144 + 124, 144 + 137, 20, 108, 128] {
            let mut bad = b.clone();
            bad[at] = 255;
            assert!(super::dns_v2::preflight(40, &bad).is_err());
        }
    }
    #[test]
    fn dns_v2_waiter_independent_wire_and_no_legacy_downgrade() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/dns-v2-waiter.json"
        ))
        .unwrap();
        let body: Vec<u8> = fixture["bodyHex"]
            .as_str()
            .unwrap()
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        super::dns_v2::preflight(53, &body).unwrap();
        for len in 0..64 {
            assert!(super::dns_v2::preflight(53, &body[..len]).is_err());
        }
        for at in [0, 2, 4, 56] {
            let mut bad = body.clone();
            bad[at] = 255;
            assert!(super::dns_v2::preflight(53, &bad).is_err());
        }
        let mut mixed = body.clone();
        mixed[48..56].fill(0);
        assert!(super::dns_v2::preflight(53, &mixed).is_err());
        let mut old = body.clone();
        old[1] = 1;
        assert!(super::dns_v2::preflight(53, &old).is_err());
        let mut header = [0; 128];
        header[..8].copy_from_slice(b"YNKCAP01");
        header[9] = 1;
        header[11] = 53;
        assert!(super::Header::decode(&header, 192).is_err());
    }
    use super::*;
    #[test]
    fn udp_v2_independent_exact_vectors_and_preflight() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/udp-proof-v2.json"
        ))
        .unwrap();
        let launch =
            LaunchRecord::decode(&unhex(f["launch_hex"].as_str().unwrap()), Mode::System).unwrap();
        assert_eq!(
            udp_v2::bootstrap(launch).unwrap().as_slice(),
            unhex(f["bootstrap_hex"].as_str().unwrap())
        );
        assert_eq!(
            udp_v2::bootstrap_ack(launch).unwrap().as_slice(),
            unhex(f["ack_hex"].as_str().unwrap())
        );
        assert_ne!(
            udp_v2::bootstrap_ack(launch).unwrap(),
            proof_bootstrap_ack(launch).unwrap()
        );
        for vector in f["vectors"].as_array().unwrap() {
            let raw = unhex(vector["hex"].as_str().unwrap());
            let rights = vector["rights"].as_u64().unwrap() as usize;
            let from_go = vector["from_go"].as_bool().unwrap();
            let record = udp_v2::Record::decode(&raw, launch, from_go, rights).unwrap();
            let encoded = record.encode(launch).unwrap();
            assert_eq!(&encoded.bytes[..encoded.length], raw);
            assert_eq!(encoded.rights, rights);
            assert_eq!(encoded.from_go, from_go);
            for n in 0..raw.len() {
                assert!(udp_v2::Record::decode(&raw[..n], launch, from_go, rights).is_err());
            }
            for offset in [8, 10, 12, 14, 16, 48, 64, 80, 88, 96] {
                let mut bad = raw.clone();
                bad[offset] ^= 128;
                assert!(udp_v2::Record::decode(&bad, launch, from_go, rights).is_err());
            }
            assert!(udp_v2::Record::decode(&raw, launch, !from_go, rights).is_err());
            assert!(udp_v2::Record::decode(&raw, launch, from_go, rights + 1).is_err());
            if let udp_v2::Record::Permit { packet, .. } = record {
                let payload = unhex(f["payload_hex"].as_str().unwrap());
                assert_eq!(
                    udp_v2::fingerprint(launch, packet, &payload).unwrap(),
                    packet.fingerprint
                );
                let mut changed = payload.clone();
                changed[10] ^= 1;
                assert_ne!(
                    udp_v2::fingerprint(launch, packet, &changed).unwrap(),
                    packet.fingerprint
                );
                assert!(
                    udp_v2::fingerprint(launch, packet, &payload[..payload.len() - 1]).is_err()
                );
            }
        }
    }
    #[test]
    fn r14_system_user_dns_grant_preserves_attribution_and_exact_pending_vectors() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-user-dns-grant-r14.json"
        ))
        .unwrap();
        let bytes = |key: &str| unhex(f[key].as_str().unwrap());
        // Только consistency vectors для Go pending matcher; не новый Rust
        // consumer и не authority из DTO. Actual producer проверяется driver test.
        let pending = |frame: &Frame<'_>, reply| {
            matches!(
                frame.message,
                Message::Grant {
                    grant: 11,
                    flow: 7,
                    revision: 23,
                    ..
                }
            ) && frame.header.reply_to == reply
                && frame.header.object_id == 11
        };
        for (key, reply, kind, id, fresh) in [
            (
                "system_user_dns_grant_frame_hex",
                20,
                ReceiptKind::SidebandOperation,
                9,
                15_000_000,
            ),
            (
                "system_user_dns_frozen_refresh_frame_hex",
                21,
                ReceiptKind::FrozenSent,
                10,
                5_000_000,
            ),
        ] {
            let wire = bytes(key);
            let frame = Frame::decode(&wire, binding(), Mode::System, true).unwrap();
            assert!(pending(&frame, reply));
            let Message::Grant {
                class: 3,
                required: true,
                receipt,
                fresh: actual,
                ..
            } = frame.message
            else {
                panic!("System user DNS потерял attribution")
            };
            assert_eq!((receipt.kind, receipt.id, actual), (kind, id, fresh));
            assert!(actual <= 20_000_000);
            let mut encoded = [0; 184];
            let length = Frame::encode(frame.header, &frame.message, &mut encoded).unwrap();
            assert_eq!(&encoded[..length], wire);
            assert!(Frame::decode(&wire, binding(), Mode::Local, true).is_err());
        }
        for (key, sequence, object) in [
            ("authorize_frame_hex", 20, 0),
            ("authorize_refresh_frame_hex", 21, 11),
        ] {
            let wire = bytes(key);
            let frame = Frame::decode(&wire, binding(), Mode::System, false).unwrap();
            assert_eq!(
                (frame.header.sequence, frame.header.object_id),
                (sequence, object)
            );
            let Message::Authorize(a) = frame.message else {
                unreachable!()
            };
            assert_eq!((a.source_flow, a.class, a.query), (7, 3, "query.invalid"));
            assert_eq!((a.receipt.kind, a.receipt.id), (ReceiptKind::None, 0));
        }
        for case in f["negative"].as_array().unwrap() {
            let wire = unhex(case["frame_hex"].as_str().unwrap());
            let decoded = Frame::decode(&wire, binding(), Mode::System, true);
            assert_eq!(
                decoded.is_ok(),
                case["system_codec_valid"].as_bool().unwrap(),
                "{}",
                case["name"]
            );
            if let Ok(frame) = decoded {
                assert!(
                    !pending(&frame, case["expected_reply"].as_u64().unwrap_or(20)),
                    "{}",
                    case["name"]
                );
            }
        }
        for key in [
            "service_probe_zero_tail_frame_hex",
            "service_dns_zero_tail_frame_hex",
        ] {
            let wire = bytes(key);
            let frame = Frame::decode(&wire, binding(), Mode::System, true).unwrap();
            assert!(matches!(
                frame.message,
                Message::Grant {
                    required: false,
                    flow: 0,
                    fresh: 0,
                    receipt: Receipt {
                        kind: ReceiptKind::None,
                        id: 0
                    },
                    ..
                }
            ));
        }
        let local = bytes("local_user_dns_zero_tail_frame_hex");
        assert!(Frame::decode(&local, binding(), Mode::Local, true).is_ok());
        assert!(Frame::decode(&local, binding(), Mode::System, true).is_err());
    }
    #[test]
    fn r14_proof_bootstrap_ack_is_exact_and_bound_to_record() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json"
        ))
        .unwrap();
        let launch =
            LaunchRecord::decode(&unhex(f["launch_hex"].as_str().unwrap()), Mode::System).unwrap();
        let record = proof_bootstrap(launch).unwrap();
        let ack = proof_bootstrap_ack(launch).unwrap();
        assert_eq!(record.len(), 128);
        assert_eq!(&record[8..16], &[0, 1, 0, 128, 0, 1, 0, 0]);
        assert_eq!(ack.len(), 40);
        assert_eq!(&ack[..8], b"YNKPFA01");
        assert_eq!(&ack[8..], &Sha256::digest(record)[..]);
        for offset in [16, 48, 80, 96, 112, 120] {
            let mut changed = record;
            changed[offset] ^= 1;
            assert_ne!(&ack[8..], &Sha256::digest(changed)[..]);
        }
        assert_ne!(ack.as_slice(), &ack[..39]);
        let mut extended = ack.to_vec();
        extended.push(0);
        assert_ne!(ack.as_slice(), extended);
        assert_eq!(
            ack.as_slice(),
            unhex(f["bootstrap_ack_hex"].as_str().unwrap())
        );
    }
    #[test]
    fn exact_c75a8e9_service_wire_vectors_and_live_probe_refresh() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/go-c75a8e9-service-grants.json"
        ))
        .unwrap();
        for (name, kind) in [
            ("probeBodyHex", Kind::Probe),
            ("bootstrapBodyHex", Kind::Probe),
            ("dnsAuthorizeBodyHex", Kind::Authorize),
            ("dnsGrantBodyHex", Kind::Grant),
            ("probeGrantBodyHex", Kind::Grant),
        ] {
            let bytes = unhex(f[name].as_str().unwrap());
            let message = Message::decode(kind, &bytes).unwrap();
            let mut out = [0; 1153];
            let length = Frame::encode(
                Header {
                    kind,
                    sequence: 3,
                    reply_to: if kind == Kind::Grant { 2 } else { 0 },
                    binding: binding(),
                    object_id: match &message {
                        Message::Grant { grant, .. } => *grant,
                        _ => 0,
                    },
                },
                &message,
                &mut out,
            )
            .unwrap();
            assert_eq!(&out[128..length], bytes);
            Frame::decode(&out[..length], binding(), Mode::Local, kind == Kind::Grant).unwrap();
            if name == "probeGrantBodyHex" {
                let mut bad = bytes.clone();
                bad[12..20].copy_from_slice(&1u64.to_be_bytes());
                assert!(Message::decode(kind, &bad).is_err());
            }
            if name == "dnsGrantBodyHex" {
                let mut bad = bytes.clone();
                bad[12..20].fill(0);
                bad[2] = 1;
                bad[32..40].copy_from_slice(&1u64.to_be_bytes());
                bad[40] = 2;
                bad[48..56].copy_from_slice(&1u64.to_be_bytes());
                assert!(Message::decode(kind, &bad).is_err());
            }
            if kind == Kind::Probe {
                out[112..120].copy_from_slice(&17u64.to_be_bytes());
                assert!(Frame::decode(&out[..length], binding(), Mode::System, false).is_ok());
            }
        }
    }
    #[test]
    fn socket_record_constructor_rejects_invalid_tuple_and_ingress() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json"
        ))
        .unwrap();
        let launch = LaunchRecord::decode(
            &unhex(fixture["launch_hex"].as_str().unwrap()),
            Mode::System,
        )
        .unwrap();
        let socket =
            SocketRecord::decode(&unhex(fixture["socket_hex"].as_str().unwrap()), launch).unwrap();
        for tuple in [
            Tuple {
                local_port: 0,
                ..socket.tuple
            },
            Tuple {
                remote_port: 0,
                ..socket.tuple
            },
            Tuple {
                family: 0,
                ..socket.tuple
            },
        ] {
            assert!(SocketRecord { tuple, ..socket }.encode(launch).is_err());
        }
        for ingress in [64, u16::MAX] {
            assert!(SocketRecord { ingress, ..socket }.encode(launch).is_err());
        }
    }
    #[test]
    fn independent_system_proof_extension_wire_and_hashes() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-proof-extension-v1.json"
        ))
        .unwrap();
        let bytes = |key: &str| unhex(fixture[key].as_str().unwrap());
        let launch = LaunchRecord::decode(&bytes("launch_hex"), Mode::System).unwrap();
        let delivery = ExecDelivery::decode(&bytes("exec_hex"), launch).unwrap();
        assert_eq!(delivery.image, [12; 32]);
        assert_eq!((delivery.image_bytes, delivery.config_bytes), (4096, 64));
        assert_eq!(delivery.ack().unwrap().as_slice(), bytes("exec_ack_hex"));
        assert_eq!(
            proof_bootstrap(launch).unwrap().as_slice(),
            bytes("bootstrap_hex")
        );
        assert_eq!(
            proof_bootstrap_ack(launch).unwrap().as_slice(),
            bytes("bootstrap_ack_hex")
        );
        let socket = SocketRecord::decode(&bytes("socket_hex"), launch).unwrap();
        assert_eq!((socket.request, socket.proof, socket.ingress), (3, 1, 0));
        assert_eq!(
            (socket.tuple.local_port, socket.tuple.remote_port),
            (32001, 1080)
        );
        for key in ["exec_hex", "socket_hex"] {
            let wire = bytes(key);
            for length in 0..wire.len() {
                assert!(if key == "exec_hex" {
                    ExecDelivery::decode(&wire[..length], launch).is_err()
                } else {
                    SocketRecord::decode(&wire[..length], launch).is_err()
                });
            }
            for offset in if key == "exec_hex" {
                vec![
                    0, 8, 10, 12, 14, 16, 48, 80, 96, 112, 120, 128, 132, 136, 176, 208, 252,
                ]
            } else {
                vec![0, 8, 10, 12, 14, 16, 48, 64, 80, 88, 96, 146, 147, 188]
            } {
                let mut bad = wire.clone();
                bad[offset] ^= 1;
                assert!(
                    if key == "exec_hex" {
                        ExecDelivery::decode(&bad, launch).is_err()
                    } else {
                        SocketRecord::decode(&bad, launch).is_err()
                    },
                    "{key} offset {offset}"
                );
            }
        }
        for id in [0, u64::MAX] {
            assert!(
                SocketRecord {
                    request: id,
                    ..socket
                }
                .encode(launch)
                .is_err()
            );
            assert!(
                SocketRecord {
                    proof: id,
                    ..socket
                }
                .encode(launch)
                .is_err()
            );
        }
        assert!(
            SocketRecord {
                tuple: Tuple {
                    protocol: 17,
                    ..socket.tuple
                },
                ..socket
            }
            .encode(launch)
            .is_err()
        );
        let local = LaunchRecord {
            mode: Mode::Local,
            child_pid: 0,
            child_start: 0,
            ..launch
        };
        assert!(proof_bootstrap(local).is_err());
        assert!(ExecDelivery::decode(&bytes("exec_hex"), local).is_err());
    }
    #[test]
    fn initiator_tuple_r8_matches_independent_open_ingress_vectors() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/initiator-ingress-r8.json"
        ))
        .unwrap();
        let capsule = golden_build(false);
        let capsule = Capsule::decode(capsule.bytes(), &binding().digest).unwrap();
        for case in f["cases"].as_array().unwrap() {
            let bytes = unhex(case["frame_hex"].as_str().unwrap());
            let frame = Frame::decode(&bytes, binding(), Mode::Local, false).unwrap();
            let Message::OpenIngress { tuple, .. } = &frame.message else {
                panic!("OPEN_INGRESS expected")
            };
            let tuple_bytes = unhex(case["tuple_hex"].as_str().unwrap());
            assert_eq!(&bytes[132..172], tuple_bytes);
            assert_eq!(tuple.local_port, 32001);
            assert_eq!(
                tuple.remote_port,
                case["expected_owner_remote_port"].as_u64().unwrap() as u16
            );
            let owner = tuple.owner_flow().unwrap();
            assert_eq!(
                owner.family,
                case["expected_owner_family"].as_u64().unwrap() as u8
            );
            assert_eq!(owner.local_port, 32001);
            assert_eq!(owner.remote_port, tuple.remote_port);
            assert_eq!((owner.local, owner.remote), (tuple.local, tuple.remote));
            let allowed = capsule.validate_request(&frame.message).is_ok();
            assert_eq!(allowed, case["name"] == "tcp", "{}", case["name"]);
        }
    }
    #[test]
    fn exact_go_a004e92_launch_admission_golden_has_identical_layout() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/go-a004e92-launch-admission.json"
        ))
        .unwrap();
        let config = unhex(f["config_hex"].as_str().unwrap());
        let record = unhex(f["local_record_hex"].as_str().unwrap());
        let launch = LaunchRecord::decode(&record, Mode::Local).unwrap();
        assert_eq!(launch.encode().unwrap().as_slice(), record);
        assert_eq!(
            launch.binding.digest,
            <[u8; 32]>::from(Sha256::digest(&config))
        );
        let body = unhex(f["admit_body_hex"].as_str().unwrap());
        let capsule = Capsule::decode(&body, &launch.binding.digest).unwrap();
        assert_eq!(capsule.manifest, launch.manifest);
        assert_eq!(
            capsule.manifest.to_vec(),
            unhex(f["manifest_sha256"].as_str().unwrap())
        );
        assert!(!capsule.mode.required());
        // Golden проверяет wire grammar, не production construction или config proof.
        assert!(
            yonik_engine::native_profile::ProfileIntent::decode(
                std::str::from_utf8(&config).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn ancillary_shapes_deny_mixed_rights_wrong_peer_and_truncation() {
        let peer = PeerIdentity {
            pid: 12,
            uid: 1000,
            start: 13,
        };
        for credentials in [0, 1, 2] {
            for rights in [0, 1, 2] {
                let observation = AncillaryShape {
                    credentials,
                    rights,
                    truncated: false,
                    seqpacket: true,
                    peer,
                };
                assert_eq!(
                    observation.validate(peer, 1).is_ok(),
                    credentials == 1 && rights == 1
                );
                assert_eq!(
                    observation.validate(peer, 0).is_ok(),
                    credentials == 1 && rights == 0
                );
            }
        }
        for peer in [
            PeerIdentity { pid: 13, ..peer },
            PeerIdentity { uid: 0, ..peer },
            PeerIdentity { start: 14, ..peer },
        ] {
            let observation = AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: false,
                seqpacket: true,
                peer,
            };
            assert!(
                observation
                    .validate(
                        PeerIdentity {
                            pid: 12,
                            uid: 1000,
                            start: 13
                        },
                        0
                    )
                    .is_err()
            );
        }
        assert!(
            AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: true,
                seqpacket: true,
                peer
            }
            .validate(peer, 0)
            .is_err()
        );
        assert!(
            AncillaryShape {
                credentials: 1,
                rights: 0,
                truncated: false,
                seqpacket: false,
                peer
            }
            .validate(peer, 0)
            .is_err()
        );
        assert_eq!(
            [
                CONTROL_FD_LOCATOR,
                LAUNCH_FD_LOCATOR,
                PEER_PIDFD_LOCATOR,
                ASSET_ROOT_FD_LOCATOR
            ]
            .len(),
            4
        );
    }
    #[test]
    fn chain_udp443_default_rejection_does_not_remove_valid_tcp_path() {
        use yonik_engine::native_profile::{OwnedIngress, OwnedRuntimePlan, ProfileIntent};
        let mut f = fixture(true);
        f["profile"]["graph"]["outbounds"][1]["mux"]
            .as_object_mut()
            .unwrap()
            .remove("xudpProxyUDP443");
        let intent = ProfileIntent::decode(&f["profile"].to_string()).unwrap();
        let tun = yonik_engine::SystemTun::new(
            1,
            1500,
            42,
            vec![yonik_engine::SystemTunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap()],
        )
        .unwrap();
        let plan = OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap())
            .unwrap()
            .with_system(tun)
            .map_ingress("provider", OwnedIngress::System)
            .unwrap()
            .bind_system_resolver(&FakeResolver)
            .unwrap();
        let built = OwnedCapsule::build(
            &intent,
            &plan,
            Some(SnapshotRef {
                source: [8; 32],
                asset: [9; 32],
                bytes: 120,
                flags: 0,
            }),
            [3; 32],
            1,
            1,
        )
        .unwrap();
        let capsule = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert_eq!(scope(capsule.tables[8].row(0).unwrap()).unwrap().mask, 1);
        assert_eq!(scope(capsule.tables[8].row(1).unwrap()).unwrap().mask, 0);
        assert_eq!(capsule.tables[2].count, 1);
        assert_eq!(capsule.tables[1].count, 2);
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/system-chain-default-reject.json"
        ))
        .unwrap();
        assert_eq!(
            built.bytes(),
            unhex(golden["capsule_hex"].as_str().unwrap())
        );
        assert_eq!(f["profile"], golden["profile"]);
    }
    #[test]
    fn request_scope_indices_and_actual_branch_must_match_capsule() {
        let built = golden_build(true);
        let capsule = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert!(capsule.mode.required());
        let destination = destination_bytes("example.test", 443, 6).unwrap();
        let mut r = Reader::new(&destination);
        let destination = Destination::read(&mut r).unwrap();
        let mut a = Authorize {
            source_flow: 1,
            class: 1,
            subject: 0,
            chain: 0,
            transport: 0,
            scope: 0,
            branch: 0,
            original: destination,
            effective: destination,
            resolver: NONE,
            query: "",
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        assert!(capsule.validate_request(&Message::Authorize(a)).is_ok());
        a.scope = 2;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        a.subject = 1;
        a.chain = NONE;
        a.transport = 1;
        a.branch = 0;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        a.branch = 1;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_ok());
        a.branch = 255;
        assert!(capsule.validate_request(&Message::Authorize(a)).is_err());
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 1,
                    index: 0,
                    subject: 0,
                    resolver: NONE
                })
                .is_ok()
        );
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 1,
                    index: 0,
                    subject: 2,
                    resolver: NONE
                })
                .is_err()
        );
        assert!(
            capsule
                .validate_request(&Message::Probe {
                    purpose: 2,
                    index: 0,
                    subject: 0,
                    resolver: 0
                })
                .is_err()
        );
    }
    #[test]
    fn every_message_and_launch_matches_independent_wire_vectors() {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/xray-profile-channel-v3/messages-and-launch.json"
        ))
        .unwrap();
        for vector in f["frames"].as_array().unwrap() {
            let wire = unhex(vector["frame_hex"].as_str().unwrap());
            let host = vector["from_host"].as_bool().unwrap();
            let frame = Frame::decode(&wire, binding(), Mode::Local, host).unwrap();
            assert_eq!(
                frame.header.kind as u16,
                vector["kind"].as_u64().unwrap() as u16
            );
            let mut encoded = [0; 1024];
            let n = frame.message.encode(&mut encoded).unwrap();
            assert_eq!(&encoded[..n], &wire[128..]);
            assert_eq!(frame.header.encode(n).unwrap().as_slice(), &wire[..128]);
            let mut encoded_frame = [0; 2048];
            let n = Frame::encode(frame.header, &frame.message, &mut encoded_frame).unwrap();
            assert_eq!(&encoded_frame[..n], wire);
            for end in 0..wire.len() {
                assert!(Frame::decode(&wire[..end], binding(), Mode::Local, host).is_err());
            }
            let mut bad = wire.clone();
            bad[120] = 1;
            assert!(Frame::decode(&bad, binding(), Mode::Local, host).is_err());
            let mut bad = wire;
            bad[10..12].copy_from_slice(&65535u16.to_be_bytes());
            assert!(Frame::decode(&bad, binding(), Mode::Local, host).is_err());
        }
        for vector in f["launch"].as_array().unwrap() {
            let mode = if vector["system"].as_bool().unwrap() {
                Mode::System
            } else {
                Mode::Local
            };
            let bytes = unhex(vector["record_hex"].as_str().unwrap());
            let record = LaunchRecord::decode(&bytes, mode).unwrap();
            assert_eq!(record.encode().unwrap().as_slice(), bytes);
            record
                .verify_ack(&unhex(vector["ack_hex"].as_str().unwrap()))
                .unwrap();
            let mut bad = bytes.clone();
            bad[184] = 1;
            assert!(LaunchRecord::decode(&bad, mode).is_err());
            for end in 0..bytes.len() {
                assert!(LaunchRecord::decode(&bytes[..end], mode).is_err());
            }
        }
        let budget = MemoryPreflight::new(MAX_CAPS, 65536).unwrap();
        assert_eq!(budget.metadata + budget.buffer_bytes, 8 * 1024 * 1024);
        let mut small = MAX_CAPS;
        small[4] = 1;
        assert!(MemoryPreflight::new(small, 128).is_err());
    }
    fn unhex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn fixture(system: bool) -> serde_json::Value {
        serde_json::from_str(if system {
            include_str!("../../../tests/fixtures/xray-profile-channel-v3/system-chain-probe.json")
        } else {
            include_str!("../../../tests/fixtures/xray-profile-channel-v3/local-minimal.json")
        })
        .unwrap()
    }
    fn binding() -> Binding {
        Binding {
            session: [1; 16],
            invocation: [2; 16],
            digest: [3; 32],
            generation: 4,
            epoch: 5,
        }
    }
    struct FakeResolver;
    impl yonik_engine::native_profile::VerifiedSystemResolver for FakeResolver {
        fn snapshot_digest(&self) -> [u8; 32] {
            [8; 32]
        }
        fn servers(&self) -> Vec<std::net::SocketAddr> {
            vec!["127.0.0.53:53".parse().unwrap()]
        }
    }
    fn golden_build(system: bool) -> OwnedCapsule {
        use yonik_engine::native_profile::{OwnedIngress, OwnedRuntimePlan, ProfileIntent};
        let f = fixture(system);
        let intent = ProfileIntent::decode(&f["profile"].to_string()).unwrap();
        let graph = intent.validate().unwrap();
        for (i, name) in graph.subjects().iter().enumerate() {
            let mut bytes = Vec::new();
            intent.write_transport_sensitive(name, &mut bytes).unwrap();
            assert_eq!(
                bytes,
                unhex(f["transport_preimages_hex"][i].as_str().unwrap()),
                "independent P5STRM01 {name}"
            );
        }
        let mut plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        if system {
            let tun = yonik_engine::SystemTun::new(
                1,
                1500,
                42,
                vec![
                    yonik_engine::SystemTunAddress::new("198.18.0.1".parse().unwrap(), 30).unwrap(),
                ],
            )
            .unwrap();
            plan = plan
                .with_system(tun)
                .map_ingress("provider", OwnedIngress::System)
                .unwrap()
                .bind_system_resolver(&FakeResolver)
                .unwrap();
        }
        OwnedCapsule::build(
            &intent,
            &plan,
            system.then_some(SnapshotRef {
                source: [8; 32],
                asset: [9; 32],
                bytes: 120,
                flags: 0,
            }),
            [3; 32],
            1,
            1,
        )
        .unwrap()
    }
    #[test]
    fn independent_capsule_and_full_frame_vectors_match() {
        for system in [false, true] {
            let f = fixture(system);
            let built = golden_build(system);
            let expected = unhex(f["capsule_hex"].as_str().unwrap());
            assert_eq!(built.bytes(), expected);
            let capsule = Capsule::decode(&expected, &[3; 32]).unwrap();
            assert_eq!(capsule.body, expected);
            assert_eq!(capsule.admission_id, 1);
            assert_eq!(capsule.lease_ms, 60000);
            assert_eq!(capsule.policy_revision, 1);
            assert_eq!(
                capsule.manifest.to_vec(),
                unhex(f["manifest_sha256"].as_str().unwrap())
            );
            let full = unhex(f["admit_frame_hex"].as_str().unwrap());
            let mode = if system { Mode::System } else { Mode::Local };
            let frame = Frame::decode(&full, binding(), mode, true).unwrap();
            assert_eq!(frame.header.sequence, 1);
            assert!(matches!(frame.message, Message::Admit(_)));
            assert!(
                Frame::decode(
                    &full,
                    binding(),
                    if system { Mode::Local } else { Mode::System },
                    true
                )
                .is_err()
            );
            assert!(Frame::decode(&full, binding(), mode, false).is_err());
        }
    }
    fn rehash(bytes: &mut [u8]) {
        let mut hash = Sha256::new();
        hash.update(b"YNKCAP-MANIFEST-v1\0");
        hash.update([3; 32]);
        hash.update(&bytes[76..78]);
        hash.update(&bytes[80..120]);
        hash.update(&bytes[128..]);
        bytes[..32].copy_from_slice(&hash.finalize());
    }
    fn table_start(bytes: &[u8], table: u16) -> usize {
        let mut r = Reader::new(bytes);
        r.take(128).unwrap();
        for _ in 1..table {
            r.u16().unwrap();
            r.u16().unwrap();
            let n = r.u32().unwrap();
            r.take(n as usize).unwrap();
        }
        r.position
    }
    #[test]
    fn malformed_caps_and_rehashed_reference_mutations_fail_without_materialization() {
        let bytes = golden_build(true).bytes().to_vec();
        for n in 0..bytes.len() {
            assert!(Capsule::decode(&bytes[..n], &[3; 32]).is_err());
        }
        for table in 1..=11 {
            let mut bad = bytes.clone();
            let offset = table_start(&bad, table);
            put16(&mut bad, offset + 2, u16::MAX);
            assert!(matches!(
                Capsule::decode(&bad, &[3; 32]),
                Err(Error::Budget)
            ));
        }
        let scope_start = table_start(&bytes, 9) + 8 + 4;
        for (relative, value) in [(0, 255), (3, 4), (4, 17), (8, 255), (16, 255), (22, 1)] {
            let mut bad = bytes.clone();
            bad[scope_start + relative] = value;
            rehash(&mut bad);
            assert!(Capsule::decode(&bad, &[3; 32]).is_err());
        }
        let mut bad = bytes.clone();
        let offset = table_start(&bad, 11) + 8 + 4;
        bad[offset] ^= 1;
        rehash(&mut bad);
        assert!(matches!(
            Capsule::decode(&bad, &[3; 32]),
            Err(Error::Reference)
        ));
        let mut bad = bytes;
        bad[79] = 2;
        assert!(matches!(
            Capsule::decode(&bad, &[3; 32]),
            Err(Error::Schema)
        ));
    }
    #[test]
    fn missing_owner_proof_and_mixed_modes_never_decode_as_allow() {
        let mut body = [0; 128];
        let missing = Message::Grant {
            status: Status::Allow,
            class: 1,
            required: true,
            grant: 1,
            flow: 1,
            lease: 1,
            revision: 1,
            fresh: 0,
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        assert!(missing.encode(&mut body).is_err());
        let local = Message::Grant {
            status: Status::Allow,
            class: 1,
            required: false,
            grant: 1,
            flow: 1,
            lease: 1,
            revision: 1,
            fresh: 0,
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        };
        let n = local.encode(&mut body).unwrap();
        let header = Header {
            kind: Kind::Grant,
            sequence: 1,
            reply_to: 1,
            binding: binding(),
            object_id: 1,
        }
        .encode(n)
        .unwrap();
        let wire = [header.as_slice(), &body[..n]].concat();
        assert!(Frame::decode(&wire, binding(), Mode::Local, true).is_ok());
        assert!(Frame::decode(&wire, binding(), Mode::System, true).is_err());
        let mut seq = Sequence::new();
        assert!(seq.accept(1).is_ok());
        assert!(seq.accept(3).is_err());
        assert!(seq.accept(2).is_err());
    }
    #[test]
    fn capsule_builder_roundtrips_all_eleven_tables_and_rejects_mutation() {
        use yonik_engine::native_profile::{OwnedRuntimePlan, ProfileIntent};
        let intent=ProfileIntent::decode(r#"{"version":1,"graph":{"outbounds":[{"tag":"direct","protocol":"freedom"}],"dns":{"servers":["192.0.2.53"]}}}"#).unwrap();
        let plan =
            OwnedRuntimePlan::new(1080.try_into().unwrap(), 1081.try_into().unwrap()).unwrap();
        let built = OwnedCapsule::build(&intent, &plan, None, [3; 32], 1, 1).unwrap();
        let decoded = Capsule::decode(built.bytes(), &[3; 32]).unwrap();
        assert_eq!(decoded.tables.len(), 11);
        assert_eq!(decoded.tables[8].count, 2);
        assert_eq!(decoded.mode, Mode::Local);
        assert!(!decoded.mode.required());
        for n in 0..built.bytes().len() {
            assert!(Capsule::decode(&built.bytes()[..n], &[3; 32]).is_err());
        }
        let mut bad = built.bytes().to_vec();
        bad[77] = 1;
        assert!(Capsule::decode(&bad, &[3; 32]).is_err());
        assert!(Capsule::decode(built.bytes(), &[4; 32]).is_err());
    }
    #[test]
    fn header_and_launch_are_exact_and_mode_separated() {
        let binding = Binding {
            session: [1; 16],
            invocation: [2; 16],
            digest: [3; 32],
            generation: 4,
            epoch: 5,
        };
        let h = Header {
            kind: Kind::Hello,
            sequence: 1,
            reply_to: 0,
            binding,
            object_id: 0,
        };
        let bytes = h.encode(40).unwrap();
        assert_eq!(&bytes[..8], b"YNKCAP01");
        assert_eq!(&bytes[12..16], &168u32.to_be_bytes());
        assert_eq!(Header::decode(&bytes, 168).unwrap(), h);
        let local = LaunchRecord {
            mode: Mode::Local,
            nonce: [6; 32],
            binding,
            owner_pid: 12,
            child_pid: 0,
            owner_start: 13,
            child_start: 0,
            manifest: [7; 32],
        };
        let record = local.encode().unwrap();
        assert_eq!(&record[..8], b"YNKLOC01");
        assert_eq!(LaunchRecord::decode(&record, Mode::Local).unwrap(), local);
        assert!(LaunchRecord::decode(&record, Mode::System).is_err());
        assert!(LaunchRecord::decode(&record[..191], Mode::Local).is_err());
        assert_eq!(&local.ack().unwrap()[..8], b"YNKEXAK1");
    }
    #[test]
    fn messages_reject_unknown_receipts_and_preserve_scope_bytes() {
        let original = destination_bytes("example.test", 443, 6).unwrap();
        let mut r = Reader::new(&original);
        let destination = Destination::read(&mut r).unwrap();
        let message = Message::Authorize(Authorize {
            source_flow: 1,
            class: 1,
            subject: 2,
            chain: NONE,
            transport: 2,
            scope: 4,
            branch: 0,
            original: destination,
            effective: destination,
            resolver: NONE,
            query: "",
            receipt: Receipt {
                kind: ReceiptKind::None,
                id: 0,
            },
        });
        let mut out = [0u8; 1024];
        let n = message.encode(&mut out).unwrap();
        assert_eq!(&out[16..20], &[0, 4, 0, 0]);
        assert!(matches!(
            Message::decode(Kind::Authorize, &out[..n]).unwrap(),
            Message::Authorize(Authorize { scope: 4, .. })
        ));
        for end in 0..n {
            assert!(Message::decode(Kind::Authorize, &out[..end]).is_err());
        }
        out[n - 16] = 3;
        assert!(Message::decode(Kind::Authorize, &out[..n]).is_err());
    }
}
