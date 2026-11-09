//! Who a route lets in, and how soon that changes: a permission of the
//! tenant's own, a tenant policy that lets in only a group and a role, a
//! route changed from open to signed-in only, and a person whose standing
//! changed. Each change is held to on the person's next request, and the
//! app sees nothing of anyone refused.
//!
//! - `permissions`: a route asking a permission lets in only who holds it,
//!   and stops them once the role is taken back.
//! - `allow_list`: a policy refusing by default lets in one group and one
//!   role, follows the group's members, and names its version in its
//!   records.
//! - `changes`: Tess closes an open route to signed-in people and opens it
//!   again, and nobody else can.
//! - `standing`: Uma deactivated and Rob removed are refused on their next
//!   request while Pat goes on.
//! - `undecided`: a route whose pipeline Tess never switched on forwards
//!   nothing until she does.

mod allow_list;
mod changes;
mod permissions;
mod standing;
mod undecided;
