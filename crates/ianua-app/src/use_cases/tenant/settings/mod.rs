//! A tenant's settings: general, sign-in, mTLS, compliance, the names it
//! is reached on, its environment and break-glass self-service.

pub(crate) mod change_break_glass_policy;
pub(crate) mod change_compliance;
pub(crate) mod change_environment;
pub(crate) mod get_auth_config;
pub(crate) mod get_compliance;
pub(crate) mod get_hostname_config;
pub(crate) mod get_mtls_config;
pub(crate) mod update;
pub(crate) mod update_auth_config;
pub(crate) mod update_mtls_config;

pub use change_break_glass_policy::{ChangeBreakGlassPolicyPorts, ChangeBreakGlassPolicyUseCase};
pub use change_compliance::{
    ChangeCompliancePorts, ChangeComplianceRequest, ChangeComplianceUseCase,
};
pub use change_environment::{ChangeEnvironmentPorts, ChangeEnvironmentUseCase};
pub use get_auth_config::{GetAuthConfigPorts, GetAuthConfigUseCase};
pub use get_compliance::{GetCompliancePorts, GetComplianceUseCase};
pub use get_hostname_config::{GetHostnameConfigPorts, GetHostnameConfigUseCase, TenantHostnames};
pub use get_mtls_config::{GetMtlsConfigPorts, GetMtlsConfigUseCase};
pub use update::{UpdatePorts, UpdateRequest, UpdateUseCase};
pub use update_auth_config::{
    UpdateAuthConfigPorts, UpdateAuthConfigRequest, UpdateAuthConfigUseCase,
};
pub use update_mtls_config::{
    UpdateMtlsConfigPorts, UpdateMtlsConfigRequest, UpdateMtlsConfigUseCase,
};
