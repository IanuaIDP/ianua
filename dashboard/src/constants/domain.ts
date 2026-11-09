/**
 * The only choice a tenant makes when adding a domain: who runs its DNS.
 *
 * Delegated is listed first because it is the one that finishes by itself —
 * we write every record inside the zone, including the ones a certificate
 * renews against, so the tenant never touches it again. The names are in
 * messages/<language>.json under dashboard.domains.addModal.connection.
 */
export const DOMAIN_CONNECTION_IDS = ['Delegated', 'SelfManaged'] as const;
