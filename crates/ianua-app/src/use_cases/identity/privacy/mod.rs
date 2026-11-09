//! Consent records, data erasure, and copies of a person's data.

/// What a person agreed to, and withdrawing it.
pub(crate) mod consent;
/// A person's data erased: asked for, held, cancelled, carried out.
pub(crate) mod erasure;
/// A copy of a person's data: asked for, built, downloaded, expired.
pub(crate) mod exports;

pub use consent::{
    ConsentHistoryPorts, ConsentHistoryUseCase, GrantConsentPorts, GrantConsentUseCase,
    RevokeConsentPorts, RevokeConsentRequest, RevokeConsentUseCase,
};
pub use erasure::{
    CancelErasureByLinkPorts, CancelErasureByLinkUseCase, CancelErasurePorts, CancelErasureUseCase,
    ErasurePolicy, ErasureReport, HoldErasurePorts, HoldErasureUseCase, ProcessErasuresPorts,
    ProcessErasuresUseCase, ReleaseErasurePorts, ReleaseErasureUseCase, RequestErasurePorts,
    RequestErasureRequest, RequestErasureUseCase,
};
pub use exports::{
    BuildExportsPorts, BuildExportsUseCase, BuildReport, DownloadExportPorts,
    DownloadExportUseCase, ExpireExportsPorts, ExpireExportsUseCase, ListExportsPorts,
    ListExportsUseCase, RequestExportPorts, RequestExportRequest, RequestExportUseCase,
};
