//! What a person decides about their own data: the consent they give and
//! withdraw, purpose by purpose and version by version; the export of
//! their data, built by the worker and downloaded once by them alone; and
//! their erasure, which closes the account at once and is called off from
//! the mailbox, held by staff, carried out by the worker, or refused.
//!
//! - `consent`: Pat grants every purpose and withdraws them one by one;
//!   nobody but Pat gives or reads her consent; each version of the terms
//!   is its own decision.
//! - `exports`: Pat downloads each export once with no secret in it; even
//!   the administrator who asked for an export cannot download it; a
//!   download link expires before the export does.
//! - `erasure`: Pat calls off her erasure by mail and signs in afresh; a
//!   legal hold keeps her account past its due date; a due erasure
//!   removes her once even across a restart; only staff or Pat herself
//!   erase Pat, and only once.
//! - `members`: Max decides his own consent, not Ann; Max calls off his
//!   erasure and signs in afresh; Ann, the only owner, cannot erase her
//!   account.

mod consent;
mod erasure;
mod exports;
mod members;
