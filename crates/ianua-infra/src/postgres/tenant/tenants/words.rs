//! The words a tenant's choices are stored as.

use ianua_domain::domains::tenant::environment::TenantEnvironment;
use ianua_domain::domains::tenant::provisioning::infrastructure::CloudProvider;
use ianua_domain::domains::tenant::status::TenantStatus;

use crate::postgres::foundation::stored::stored_words;

stored_words! {
    TenantStatus as "status" {
        Provisioning => "provisioning",
        Active => "active",
        Suspended => "suspended",
        Archived => "archived",
        Deleted => "deleted",
    }
}

stored_words! {
    TenantEnvironment as "environment" {
        Production => "production",
        Staging => "staging",
        Development => "development",
    }
}

stored_words! {
    CloudProvider as "cloud" {
        Aws => "aws",
        Gcp => "gcp",
        Azure => "azure",
        DigitalOcean => "digitalocean",
        Kubernetes => "kubernetes",
    }
}
