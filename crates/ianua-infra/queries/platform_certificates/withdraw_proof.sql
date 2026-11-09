-- Withdraw this proof without removing a concurrent order's other challenge.
DELETE FROM platform_dns_proofs WHERE root = $1 AND value = $2
