/// Marks security records belonging to the organization plane.
///
/// It is used only as a type parameter, so no value can be constructed.
/// Organization ids and authority remain on the owning member and caller;
/// this marker prevents mixing their credentials with tenant credentials.
#[derive(Debug, Clone)]
pub enum ResolvedOrganization {}

impl crate::isolation::SecurityScope for ResolvedOrganization {}
