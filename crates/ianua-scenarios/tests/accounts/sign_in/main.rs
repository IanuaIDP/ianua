//! A company's members signing in, as a customer does it and as an
//! attacker tries it.
//!
//! - `first`: a founder's first sign-in, and what only members may read.
//! - `credentials`: Max's password changed by him or reset by Ann ends
//!   the session he held, his old password and an unspent reset link, and
//!   the replacement signs him in; a refused change keeps all of that;
//!   under pressure a solved puzzle admits one sign-in from its own
//!   browser.
//! - `attacks`: telling addresses apart, guessing from one address and
//!   from many, a session after sign-out, a tampered token or one in the
//!   address.
//! - `mailbox`: a sign-in waiting for the mailbox is finished only by its
//!   own link, once and while it is fresh; a mailed link signs in with no
//!   password, once, but still owes an authenticator code when one is
//!   enrolled; an issued link obeys the methods the company allows now;
//!   concurrent uses open only one session; an expired link opens none.
//! - `dependencies`: a cut cache, mail relay, audit store, database or
//!   bus turns no unfinished sign-in into access and spends no proof;
//!   once mended, Max signs in or finishes the sign-in he had.
//! - `factors`: authenticator codes, required enrollment and passkeys;
//!   setup grants nothing until confirmed, and replay, phishing, substituted
//!   accounts and challenges, and later policy changes cannot bypass a factor.
//!   Abandoning, disabling, resetting and recovering a factor prove both
//!   the refused access and the next usable sign-in.
//! - `federation`: real OIDC and SAML providers sign in once; mismatched
//!   claims, browser bindings and replay are refused. OIDC credentials keep
//!   their spaces and punctuation through storage and code exchange.
//! - `sessions`: who sees and ends another member's session; a locked,
//!   deactivated or suspended account is out at once and answers like a
//!   wrong guess; a member with no tenant signs in alone and moves in
//!   once granted, and naming a tenant at sign-in needs its grant. A
//!   remembered device skips the factor only with the right password,
//!   until forgotten, and is listed and forgotten by its member alone;
//!   its secret obeys the company's limit, a changed password, its age to
//!   the second and its account. A refused tenant move keeps the session
//!   it had; a valid move ends its predecessor. Idle and absolute expiry,
//!   to the second, need a fresh sign-in.
//! - `companies`: one address in two companies chooses by naming one, or
//!   by using the different password each company knows.
//! - `recovery`: single-use recovery codes and a forgotten password reset
//!   by mail, with the authenticator app answered when there is one; a code
//!   refused on another member's session stays usable by its owner; competing
//!   password resets spend one link and change the password only once; an expired
//!   reset changes nothing and a fresh link still lets the member recover.
//!   Resends obey the newest link's cooldown, refused factors preserve recovery,
//!   and replacing a printout needs fresh proof and invalidates every old code.
//!   Resets follow current password rules and account standing; mailbox proofs
//!   cannot change purpose. Pending and revoked sessions cannot misuse factors,
//!   TOTP races accept once, and recovery shares the factor's lock without
//!   removing it when the printout is exhausted.
//! - `tenant`: a tenant user's reset link read and resent, the code a
//!   reset asks for, what the sign-in page and the security page offer, a
//!   passkey added while a sign-in waits for one and one naming nobody, a
//!   setup given up, and a frozen session lifted by its own factor.

#![cfg(test)]

mod attacks;
mod companies;
mod credentials;
mod dependencies;
mod factors;
mod federation;
mod first;
mod mailbox;
mod recovery;
mod sessions;
mod support;
mod tenant;
