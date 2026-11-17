use std::num::NonZeroU16;
use yonik_import::ParsedServer;

use crate::{CompileError, CompiledConfig, Engine, compile_server};

/// Capability отдельного ELF для клиентского REALITY h2 legacy URI.
pub struct XrayRealityH2(());

impl XrayRealityH2 {
    pub const RELATIVE_PATH: &str = "xray-26.10.31-reality-h2/xray";

    // SHA256 отдельной compile-only сборки client-reality-h2 из retained source.
    pub const ELF_SHA256: [u8; 32] = [
        0xa1, 0xf2, 0x6a, 0x88, 0xe0, 0xf3, 0xc6, 0x56, 0xe8, 0x1c, 0x55, 0xa2, 0x51, 0x9c, 0x12,
        0x5b, 0x37, 0x57, 0x6c, 0x43, 0x1f, 0x54, 0x19, 0x83, 0x87, 0xae, 0x27, 0x51, 0xeb, 0x14,
        0x70, 0xbd,
    ];

    pub fn for_snapshot(engine: Engine, sha256: [u8; 32]) -> Option<Self> {
        (engine == Engine::Xray && sha256 == Self::ELF_SHA256).then_some(Self(()))
    }
}

/// Проверенный URI без доступного для запуска конфига до подтверждения ELF.
pub struct PendingXrayRealityH2(CompiledConfig);

impl PendingXrayRealityH2 {
    pub fn compile(server: &ParsedServer, port: NonZeroU16) -> Result<Self, CompileError> {
        compile_server(server, Engine::Xray, port, true).map(Self)
    }

    pub fn compile_policy(
        server: &ParsedServer,
        port: NonZeroU16,
        probe_port: NonZeroU16,
        policy: &yonik_domain::Policy,
        mode: crate::PolicyMode,
    ) -> Result<Self, crate::PolicyCompileError> {
        crate::routing::compile_xray_reality_h2_policy(server, port, probe_port, policy, mode)
            .map(Self)
    }

    pub fn listen_port(&self) -> NonZeroU16 {
        self.0.listen_port()
    }

    pub fn authorize(mut self, _: XrayRealityH2) -> CompiledConfig {
        self.0.value["outbounds"][0]["streamSettings"]["realitySettings"]["alpn"] =
            serde_json::json!(["h2"]);
        self.0
    }
}
