-- Remove expired proofs left behind by interrupted issuances.
DELETE FROM platform_dns_proofs WHERE expires_at <= now()
