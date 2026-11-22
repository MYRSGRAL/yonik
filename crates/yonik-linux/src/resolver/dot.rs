//! Системное доверие и ограниченный обмен DNS-over-TLS для резервного DNS.

use super::ResolverError;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature},
    pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject},
};
use std::{
    fs::{File, Metadata},
    io::{self, Cursor, Read, Write},
    net::IpAddr,
    os::unix::fs::MetadataExt,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use yonik_engine::fake_dns::MAX_DNS_PACKET;

const MAX_BUNDLE: usize = 2 * 1024 * 1024;
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
];

#[derive(Clone, PartialEq, Eq)]
struct BundleIdentity {
    device: u64,
    inode: u64,
    length: u64,
    changed: (i64, i64),
}

impl BundleIdentity {
    fn read(value: Metadata) -> Result<Self, ResolverError> {
        if !value.is_file() || value.uid() != 0 || value.mode() & 0o022 != 0 {
            return Err(ResolverError::Untrusted);
        }
        if value.len() > MAX_BUNDLE as u64 {
            return Err(ResolverError::Limit);
        }
        Ok(Self {
            device: value.dev(),
            inode: value.ino(),
            length: value.len(),
            changed: (value.ctime(), value.ctime_nsec()),
        })
    }
}

pub(crate) struct SystemDotTrust {
    config: Arc<ClientConfig>,
    path: &'static str,
    identity: BundleIdentity,
}

impl SystemDotTrust {
    pub(crate) async fn load() -> Result<Arc<Self>, ResolverError> {
        tokio::task::spawn_blocking(Self::read)
            .await
            .map_err(|_| ResolverError::Unavailable)?
            .map(Arc::new)
    }

    fn read() -> Result<Self, ResolverError> {
        let (file, path) = SYSTEM_BUNDLES
            .iter()
            .find_map(|&path| match File::open(path) {
                Ok(file) => Some(Ok((file, path))),
                Err(error) if error.kind() == io::ErrorKind::NotFound => None,
                Err(_) => Some(Err(ResolverError::Unavailable)),
            })
            .ok_or(ResolverError::Unsupported)??;
        let identity = BundleIdentity::read(file.metadata().map_err(unavailable)?)?;
        let mut pem = Vec::new();
        (&file)
            .take((MAX_BUNDLE + 1) as u64)
            .read_to_end(&mut pem)
            .map_err(unavailable)?;
        if pem.len() as u64 != identity.length
            || BundleIdentity::read(file.metadata().map_err(unavailable)?)? != identity
        {
            return Err(ResolverError::NetworkChanged);
        }
        let mut roots = RootCertStore::empty();
        roots
            .add_parsable_certificates(CertificateDer::pem_slice_iter(&pem).filter_map(Result::ok));
        if roots.is_empty() {
            return Err(ResolverError::Untrusted);
        }
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .map_err(|_| ResolverError::Unsupported)?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let trust = Self {
            config: Arc::new(config),
            path,
            identity,
        };
        trust.verify()?;
        Ok(trust)
    }

    fn verify(&self) -> Result<(), ResolverError> {
        if BundleIdentity::read(std::fs::metadata(self.path).map_err(unavailable)?)?
            != self.identity
        {
            return Err(ResolverError::NetworkChanged);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub(crate) enum DotPolicy {
    Strict(Arc<SystemDotTrust>),
    Opportunistic(Arc<ClientConfig>),
}

impl DotPolicy {
    pub(crate) fn opportunistic() -> Result<Self, ResolverError> {
        let provider = rustls::crypto::ring::default_provider();
        let verifier = OpportunisticVerifier(provider.signature_verification_algorithms);
        let config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|_| ResolverError::Unsupported)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        Ok(Self::Opportunistic(Arc::new(config)))
    }

    fn verify_trust(&self) -> Result<(), ResolverError> {
        match self {
            Self::Strict(trust) => trust.verify(),
            Self::Opportunistic(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
struct OpportunisticVerifier(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for OpportunisticVerifier {
    fn verify_server_cert(
        &self,
        _certificate: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // resolve1 в opportunistic не проверяет имя и цепочку доверия.
        // Подписи рукопожатия проверяются ключом сертификата.
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}

pub(crate) struct DotPeer {
    policy: DotPolicy,
    server_name: ServerName<'static>,
}

impl DotPeer {
    pub(crate) fn new(
        policy: DotPolicy,
        address: IpAddr,
        name: Option<&str>,
    ) -> Result<Self, ResolverError> {
        let server_name = match name {
            Some(name) => ServerName::try_from(name.strip_suffix('.').unwrap_or(name).to_owned())
                .map_err(|_| ResolverError::Malformed)?,
            None => ServerName::from(address),
        };
        Ok(Self {
            policy,
            server_name,
        })
    }

    pub(super) async fn handshake(
        &self,
        stream: &mut TcpStream,
    ) -> Result<ClientConnection, ResolverError> {
        self.policy.verify_trust()?;
        let config = match &self.policy {
            DotPolicy::Strict(trust) => &trust.config,
            DotPolicy::Opportunistic(config) => config,
        };
        let mut tls = ClientConnection::new(Arc::clone(config), self.server_name.clone())
            .map_err(|_| ResolverError::Untrusted)?;
        tls.set_buffer_limit(Some(MAX_DNS_PACKET + 2048));
        let mut encrypted = Vec::new();
        while tls.is_handshaking() {
            flush(&mut tls, stream, &mut encrypted).await?;
            if tls.is_handshaking() {
                receive(&mut tls, stream).await?;
            }
        }
        self.policy.verify_trust()?;
        Ok(tls)
    }

    /// Вызывается с дедлайном и отменой после проверки DNS-вопроса.
    pub(super) async fn exchange(
        &self,
        stream: &mut TcpStream,
        mut tls: ClientConnection,
        query: &[u8],
    ) -> Result<Vec<u8>, ResolverError> {
        let mut encrypted = Vec::new();
        let len = u16::try_from(query.len()).map_err(|_| ResolverError::Limit)?;
        tls.writer()
            .write_all(&len.to_be_bytes())
            .map_err(unavailable)?;
        tls.writer().write_all(query).map_err(unavailable)?;
        flush(&mut tls, stream, &mut encrypted).await?;

        let mut header = [0; 2];
        receive_exact(&mut tls, stream, &mut encrypted, &mut header).await?;
        let size = usize::from(u16::from_be_bytes(header));
        if !(12..=MAX_DNS_PACKET).contains(&size) {
            return Err(ResolverError::Limit);
        }
        let mut response = vec![0; size];
        receive_exact(&mut tls, stream, &mut encrypted, &mut response).await?;
        self.policy.verify_trust()?;
        Ok(response)
    }
}

async fn flush(
    tls: &mut ClientConnection,
    stream: &mut TcpStream,
    encrypted: &mut Vec<u8>,
) -> Result<(), ResolverError> {
    while tls.wants_write() {
        encrypted.clear();
        if tls.write_tls(encrypted).map_err(unavailable)? == 0 {
            return Err(ResolverError::Closed);
        }
        stream.write_all(encrypted).await.map_err(unavailable)?;
    }
    Ok(())
}

async fn receive(tls: &mut ClientConnection, stream: &mut TcpStream) -> Result<(), ResolverError> {
    let mut bytes = [0; 4096];
    let size = stream.read(&mut bytes).await.map_err(unavailable)?;
    if size == 0 {
        return Err(ResolverError::Closed);
    }
    let mut records = Cursor::new(&bytes[..size]);
    while records.position() < size as u64 {
        if tls.read_tls(&mut records).map_err(unavailable)? == 0 {
            return Err(ResolverError::Closed);
        }
        tls.process_new_packets()
            .map_err(|_| ResolverError::Untrusted)?;
    }
    Ok(())
}

async fn receive_exact(
    tls: &mut ClientConnection,
    stream: &mut TcpStream,
    encrypted: &mut Vec<u8>,
    mut target: &mut [u8],
) -> Result<(), ResolverError> {
    while !target.is_empty() {
        match tls.reader().read(target) {
            Ok(0) => return Err(ResolverError::Closed),
            Ok(size) => target = &mut target[size..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                flush(tls, stream, encrypted).await?;
                receive(tls, stream).await?;
            }
            Err(error) => return Err(unavailable(error)),
        }
    }
    Ok(())
}

fn unavailable(_: io::Error) -> ResolverError {
    ResolverError::Unavailable
}
