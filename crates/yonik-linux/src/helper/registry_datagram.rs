//! Независимые protected CODEC5 slots; никакого наследования review CODEC4/UDP.
#[cfg(test)]
use super::fake_bootstrap_image;
use super::{DnsReleaseRecord, ImageContract, ProducerRecord, RegistryError, Sha256};
use sha2::Digest;
use std::str::FromStr;
pub(super) const BUILD_REVIEWED_PATCH: Option<&str> =
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339");
const SOURCE_REVIEWED_PATCH: Option<&str> =
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339");
const WIRE_REVIEWED_PATCH: Option<&str> =
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339");
const RELEASE_REVIEWED_PATCH: Option<&str> =
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339");
const REVIEWS: [Option<&str>; 3] = [
    SOURCE_REVIEWED_PATCH,
    WIRE_REVIEWED_PATCH,
    RELEASE_REVIEWED_PATCH,
];
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum DatagramScope {
    Source,
    Wire,
    Release,
}
impl DatagramScope {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Wire => 1,
            Self::Release => 2,
        }
    }
    pub(crate) fn contract(self) -> &'static str {
        match self {
            Self::Source => "udp-bootstrap-consumed-parent-member-send-v1",
            Self::Wire => "udp-bootstrap-bound-dns-transcript-v1",
            Self::Release => "udp-bootstrap-dns-consuming-close-join-v1",
        }
    }
}
// Это отдельный review-запрос TCP6 под CODEC5, а не расширение UDP5/Source4.
// R93/R96/R97: TCP5 принят независимо от datagram5, exact raw SS subset.
const TCP_REVIEWS: [Option<&str>; 3] = [
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339"),
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339"),
    Some("3666161f1210c374675f4a4b67afeedea426990953889f9a1212d12cc1158339"),
];
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tcp5Scope {
    Source,
    Wire,
    Release,
}
impl Tcp5Scope {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Source => 0,
            Self::Wire => 1,
            Self::Release => 2,
        }
    }
    pub(crate) fn contract(self) -> &'static str {
        match self {
            Self::Source => "tcp-codec5-bootstrap-parent-member-v1",
            Self::Wire => "tcp-codec5-bootstrap-bound-dns-transcript-v1",
            Self::Release => "tcp-codec5-bootstrap-dns-consuming-close-join-v1",
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Scope5 {
    Datagram(DatagramScope),
    Tcp(Tcp5Scope),
}
impl Scope5 {
    fn contract(self) -> &'static str {
        match self {
            Self::Datagram(s) => s.contract(),
            Self::Tcp(s) => s.contract(),
        }
    }
}
impl From<DatagramScope> for Scope5 {
    fn from(s: DatagramScope) -> Self {
        Self::Datagram(s)
    }
}
impl From<Tcp5Scope> for Scope5 {
    fn from(s: Tcp5Scope) -> Self {
        Self::Tcp(s)
    }
}
#[derive(Clone)]
pub(super) struct Provenance {
    scope: Scope5,
    patch: [u8; 32],
    reviewed: Option<[u8; 32]>,
}
impl Provenance {
    pub(super) fn decode(
        r: &DnsReleaseRecord,
        scope: impl Into<Scope5>,
        patch: &str,
        review: Option<&str>,
    ) -> Result<Self, RegistryError> {
        let scope = scope.into();
        let hash = |value: &[u8]| format!("{:x}", sha2::Sha256::digest(value));
        if r.contract != scope.contract()
            || r.version != 1
            || r.contract_sha256 != hash(format!("{}\0", scope.contract()).as_bytes())
            || r.schema_sha256 != hash(crate::profile_channel::dns_v2::DATAGRAM_SCHEMA)
        {
            return Err(RegistryError::Version);
        }
        let patch = Sha256::from_str(patch)
            .map_err(|_| RegistryError::Manifest)?
            .0;
        let reviewed = review
            .and_then(|p| Sha256::from_str(p).ok())
            .map(|p| p.0)
            .filter(|p| *p == patch);
        Ok(Self {
            scope,
            patch,
            reviewed,
        })
    }
}
#[derive(Clone)]
pub(crate) struct DatagramCapability {
    image: [u8; 32],
    proof: Provenance,
}
impl DatagramCapability {
    pub(crate) fn check(&self, image: [u8; 32], scope: DatagramScope) -> Result<(), RegistryError> {
        if self.image != image
            || self.proof.scope != Scope5::Datagram(scope)
            || self.proof.reviewed != Some(self.proof.patch)
        {
            return Err(RegistryError::Version);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(crate) struct Tcp5Capability {
    image: [u8; 32],
    proof: Provenance,
}
impl Tcp5Capability {
    pub(crate) fn check(&self, image: [u8; 32], scope: Tcp5Scope) -> Result<(), RegistryError> {
        if self.image != image
            || self.proof.scope != Scope5::Tcp(scope)
            || self.proof.reviewed != Some(self.proof.patch)
        {
            return Err(RegistryError::Version);
        }
        Ok(())
    }
}
impl ImageContract {
    pub(crate) fn tcp5_channel(
        &self,
        image: [u8; 32],
        scope: Tcp5Scope,
    ) -> Result<Option<Tcp5Capability>, RegistryError> {
        if self.image != image {
            return Err(RegistryError::HashMismatch);
        }
        let Some(proof) = self.tcp5[scope.index()]
            .as_ref()
            .filter(|p| p.reviewed.is_some())
        else {
            return Ok(None);
        };
        let cap = Tcp5Capability {
            image,
            proof: proof.clone(),
        };
        cap.check(image, scope)?;
        Ok(Some(cap))
    }
    pub(crate) fn datagram_channel(
        &self,
        image: [u8; 32],
        scope: DatagramScope,
    ) -> Result<Option<DatagramCapability>, RegistryError> {
        if self.image != image {
            return Err(RegistryError::HashMismatch);
        }
        let Some(proof) = self.datagram[scope.index()]
            .as_ref()
            .filter(|p| p.reviewed.is_some())
        else {
            return Ok(None);
        };
        let out = DatagramCapability {
            image,
            proof: proof.clone(),
        };
        out.check(image, scope)?;
        Ok(Some(out))
    }
}
pub(super) fn decode_tcp_slots(
    record: &ProducerRecord,
) -> Result<[Option<Provenance>; 3], RegistryError> {
    [
        (&record.bootstrap_tcp5_source, Tcp5Scope::Source),
        (&record.bootstrap_tcp5_dns_wire, Tcp5Scope::Wire),
        (&record.bootstrap_tcp5_dns_release, Tcp5Scope::Release),
    ]
    .map(|(r, s)| {
        r.as_ref()
            .map(|r| Provenance::decode(r, s, &record.patch_sha256, TCP_REVIEWS[s.index()]))
            .transpose()
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .try_into()
    .map_err(|_| RegistryError::Manifest)
}
#[cfg(test)]
pub(crate) fn fake_tcp_image(mut image: ImageContract, scopes: &[Tcp5Scope]) -> ImageContract {
    let patch = "55".repeat(32);
    image.tcp5 = [Tcp5Scope::Source, Tcp5Scope::Wire, Tcp5Scope::Release].map(|s| {
        scopes.contains(&s).then(|| {
            let r = DnsReleaseRecord {
                contract: s.contract().into(),
                version: 1,
                contract_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(format!("{}\0", s.contract()).as_bytes())
                ),
                schema_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(crate::profile_channel::dns_v2::DATAGRAM_SCHEMA)
                ),
            };
            Provenance::decode(&r, s, &patch, Some(&patch)).unwrap()
        })
    });
    image
}
pub(super) fn decode_slots(
    record: &ProducerRecord,
) -> Result<[Option<Provenance>; 3], RegistryError> {
    [
        (&record.bootstrap_datagram, DatagramScope::Source),
        (&record.bootstrap_datagram_dns_wire, DatagramScope::Wire),
        (
            &record.bootstrap_datagram_dns_release,
            DatagramScope::Release,
        ),
    ]
    .map(|(r, s)| {
        r.as_ref()
            .map(|r| Provenance::decode(r, s, &record.patch_sha256, REVIEWS[s.index()]))
            .transpose()
    })
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?
    .try_into()
    .map_err(|_| RegistryError::Manifest)
}
#[cfg(test)]
pub(crate) fn fake_image(image: [u8; 32], scopes: &[DatagramScope]) -> ImageContract {
    let mut out = fake_bootstrap_image(image, &[]);
    let patch = "55".repeat(32);
    out.datagram = [
        DatagramScope::Source,
        DatagramScope::Wire,
        DatagramScope::Release,
    ]
    .map(|s| {
        scopes.contains(&s).then(|| {
            let r = DnsReleaseRecord {
                contract: s.contract().into(),
                version: 1,
                contract_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(format!("{}\0", s.contract()).as_bytes())
                ),
                schema_sha256: format!(
                    "{:x}",
                    sha2::Sha256::digest(crate::profile_channel::dns_v2::DATAGRAM_SCHEMA)
                ),
            };
            Provenance::decode(&r, s, &patch, Some(&patch)).unwrap()
        })
    });
    out
}
#[cfg(test)]
mod tests {
    use super::super::{BootstrapScope, DnsReleaseRecord, Sha256, fake_dns_record};
    use super::{DatagramScope, Provenance, fake_image};
    use sha2::Digest;
    #[test]
    fn registry_tcp5_record_does_not_inherit_review_schema_or_udp_scope() {
        use super::{Tcp5Scope as T, fake_tcp_image};
        let mut record = fake_dns_record([17; 32]);
        let mut slot = slot(DatagramScope::Source);
        slot.contract = T::Source.contract().into();
        slot.contract_sha256 = format!(
            "{:x}",
            sha2::Sha256::digest(format!("{}\0", T::Source.contract()).as_bytes())
        );
        record.bootstrap_tcp5_source = Some(slot.clone());
        let checked = record.validate(Sha256([17; 32])).unwrap();
        assert!(
            checked.tcp5_channel([17; 32], T::Source).unwrap().is_none(),
            "legacy artifact не наследует TCP5 review"
        );
        assert!(
            checked
                .datagram_channel([17; 32], DatagramScope::Source)
                .unwrap()
                .is_none()
        );
        let positive = fake_tcp_image(fake_image([17; 32], &[DatagramScope::Source]), &[T::Source]);
        let cap = positive.tcp5_channel([17; 32], T::Source).unwrap().unwrap();
        assert!(cap.check([18; 32], T::Source).is_err());
        assert!(cap.check([17; 32], T::Wire).is_err());
        slot.schema_sha256 = format!(
            "{:x}",
            sha2::Sha256::digest(crate::profile_channel::dns_v2::SCHEMA)
        );
        record.bootstrap_tcp5_source = Some(slot);
        assert!(record.validate(Sha256([17; 32])).is_err());
        record.bootstrap_tcp5_source = Some(super::super::DnsReleaseRecord {
            contract: "unknown".into(),
            ..record.bootstrap_tcp5_source.take().unwrap()
        });
        assert!(record.validate(Sha256([17; 32])).is_err());
    }
    fn slot(scope: DatagramScope) -> DnsReleaseRecord {
        DnsReleaseRecord {
            contract: scope.contract().into(),
            version: 1,
            contract_sha256: format!(
                "{:x}",
                sha2::Sha256::digest(format!("{}\0", scope.contract()).as_bytes())
            ),
            schema_sha256: format!(
                "{:x}",
                sha2::Sha256::digest(crate::profile_channel::dns_v2::DATAGRAM_SCHEMA)
            ),
        }
    }
    #[test]
    fn registry_scope5_missing_review_and_cross_schema_never_inherit() {
        let mut r = fake_dns_record([17; 32]);
        r.bootstrap_datagram = Some(slot(DatagramScope::Source));
        let image = r.validate(Sha256([17; 32])).unwrap();
        assert!(
            image
                .datagram_channel([17; 32], DatagramScope::Source)
                .unwrap()
                .is_none()
        );
        r.bootstrap_datagram.as_mut().unwrap().schema_sha256 =
            format!("{:x}", sha2::Sha256::digest(b"YONIK-DNS-V2-CODEC-4\0"));
        assert!(r.validate(Sha256([17; 32])).is_err());
        r.bootstrap_datagram = Some(slot(DatagramScope::Wire));
        assert!(r.validate(Sha256([17; 32])).is_err());
        r.bootstrap_datagram = Some(slot(DatagramScope::Source));
        r.patch_sha256 = "55".repeat(32);
        assert!(r.validate(Sha256([17; 32])).is_err());
    }
    #[test]
    fn registry_scope5_explicit_review_image_and_scope_are_independent() {
        let image = fake_image([17; 32], &[DatagramScope::Source, DatagramScope::Release]);
        assert!(
            image
                .datagram_channel([17; 32], DatagramScope::Wire)
                .unwrap()
                .is_none()
        );
        let source = image
            .datagram_channel([17; 32], DatagramScope::Source)
            .unwrap()
            .unwrap();
        assert!(source.check([17; 32], DatagramScope::Source).is_ok());
        assert!(source.check([17; 32], DatagramScope::Release).is_err());
        assert!(source.check([18; 32], DatagramScope::Source).is_err());
        assert!(
            image
                .bootstrap_channel([17; 32], BootstrapScope::Source)
                .unwrap()
                .is_none()
        );
        assert!(!image.udp_reviewed);
        let mut r = slot(DatagramScope::Source);
        r.contract_sha256 = "00".repeat(32);
        assert!(
            Provenance::decode(
                &r,
                DatagramScope::Source,
                &"55".repeat(32),
                Some(&"55".repeat(32))
            )
            .is_err()
        );
    }
}
