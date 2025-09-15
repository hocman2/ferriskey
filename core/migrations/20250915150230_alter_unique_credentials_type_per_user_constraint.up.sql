ALTER TABLE credentials
DROP CONSTRAINT unique_credential_type_per_user_id;

CREATE UNIQUE INDEX unique_credential_type_per_user_id_idx
ON credentials (user_id, credential_type)

-- Exceptional cred_type that can exist multiple times
-- for a same user
WHERE credential_type <> 'recovery-code';
