/// The clients a tenant registers and what they are allowed.
pub mod clients;
/// Who may register and change clients and API keys.
pub mod control;
/// Domain events for OAuth clients, API keys, codes, tokens, device flow and consent.
pub mod events;
/// What OAuth hands out: codes, tokens and device authorizations.
pub mod grants;
