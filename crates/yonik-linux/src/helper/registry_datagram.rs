//! Независимые protected CODEC5 slots; никакого наследования review CODEC4/UDP.
#[cfg(test)]
use super::fake_bootstrap_image;
use super::{DnsReleaseRecord, ImageContract, ProducerRecord, RegistryError, Sha256};
use sha2::Digest;
use std::str::FromStr;
pub(super) const BUILD_REVIEWED_PATCH: Option<&str> = None;
const SOURCE_REVIEWED_PATCH: Option<&str> = None;
const WIRE_REVIEWED_PATCH: Option<&str> = None;
const RELEASE_REVIEWED_PATCH: Option<&str> = None;
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
#[derive(Clone)]
pub(super) struct Provenance {
    scope: DatagramScope,
    patch: [u8; 32],
    reviewed: Option<[u8; 32]>,
}
impl Provenance {
    pub(super) fn decode(
        r: &DnsReleaseRecord,
        scope: DatagramScope,
        patch: &str,
        review: Option<&str>,
    ) -> Result<Self, RegistryError> {
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
            || self.proof.scope != scope
            || self.proof.reviewed != Some(self.proof.patch)
        {
            return Err(RegistryError::Version);
        }
        Ok(())
    }
}
impl ImageContract {
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
