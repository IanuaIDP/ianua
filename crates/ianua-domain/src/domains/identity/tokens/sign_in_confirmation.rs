/// Marks a single-use link as the one that confirms a sign-in from the
/// person's mailbox.
///
/// A sign-in that raised a risk signal, from someone with no second factor,
/// waits for its person to follow this link. It finishes that one sign-in
/// and nothing else. A magic link signs in on its own, so the two never
/// stand in for each other. Mallory has Ann's password and is asked to
/// confirm. If the confirmation link were a magic link, the link in Ann's
/// mailbox would also open a fresh session for whoever follows it.
///
/// The compiler refuses one where the other is expected:
///
/// ```compile_fail
/// use ianua_domain::domains::authentication::sessions::way_in::WayIn;
/// use ianua_domain::domains::identity::account::user::User;
/// use ianua_domain::domains::identity::tokens::secure::SecureToken;
/// use ianua_domain::domains::identity::tokens::sign_in_confirmation::SignInConfirmation;
/// use ianua_domain::isolation::scope::ResolvedTenant;
///
/// fn misuse(
///     link: &mut SecureToken<ResolvedTenant, SignInConfirmation>,
///     ann: &User<ResolvedTenant>,
/// ) {
///     let _ = WayIn::by_magic_link(link, ann, ianua_domain::shared::clock::now());
/// }
/// ```
#[derive(Debug)]
pub struct SignInConfirmation;
