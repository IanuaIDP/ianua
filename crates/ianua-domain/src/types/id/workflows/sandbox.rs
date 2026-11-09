uuid_id! {
    /// Id of a tenant's sandbox: a named recipe of code, pinned packages
    /// and limits, shared by every version of it.
    SandboxId
}

uuid_id! {
    /// Id of one saved version of a sandbox, which a workflow step names
    /// so what runs is what was reviewed.
    SandboxVersionId
}

uuid_id! {
    /// Id of one trial of a sandbox version on sample input, which a person
    /// reads back once it ran.
    SandboxTrialId
}

uuid_id! {
    /// Id of an image registry a tenant's administrator allowed sandbox
    /// versions to pull the company's own images from.
    ImageRegistryId
}
