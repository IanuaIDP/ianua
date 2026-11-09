-- Links between tables of different contexts, made once both exist.

-- An invitation gives a role once accepted, so it may only name a role the
-- tenant keeps. Deleting a role takes the finished invitations that named
-- it, which are history the audit log keeps; the app refuses the delete
-- while a pending one still names it, as the person invited would get
-- nothing.
ALTER TABLE invitations
    ADD CONSTRAINT invitations_role_fkey FOREIGN KEY (tenant_id, role_id)
        REFERENCES roles (tenant_id, id) ON DELETE CASCADE;
CREATE INDEX invitations_giving_role ON invitations (tenant_id, role_id);

-- A break-glass grant means nothing without the account it was given to,
-- so it goes with the account. That it was granted is in the audit log.
ALTER TABLE break_glass_grants
    ADD CONSTRAINT break_glass_grants_user_fkey FOREIGN KEY (tenant_id, user_id)
        REFERENCES users (tenant_id, id) ON DELETE CASCADE;
