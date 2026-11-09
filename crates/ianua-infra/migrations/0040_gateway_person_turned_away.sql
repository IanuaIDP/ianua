ALTER TABLE gateway_events DROP CONSTRAINT gateway_events_event_type_raised_by_the_gateway;

ALTER TABLE gateway_events ADD CONSTRAINT gateway_events_event_type_raised_by_the_gateway CHECK ((event_type = ANY (ARRAY['agents.action_authorized'::text, 'agents.action_denied'::text, 'agents.egress_denied'::text, 'agents.token_attack_refused'::text, 'proxy.honeypot_hit'::text, 'proxy.person_turned_away'::text, 'proxy.automated_threat_detected'::text, 'proxy.canary_token_triggered'::text, 'proxy.canary_token_leaked'::text]))) NOT VALID;
ALTER TABLE gateway_events VALIDATE CONSTRAINT gateway_events_event_type_raised_by_the_gateway;
