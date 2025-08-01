-- Create express_sessions table for session management
CREATE TABLE IF NOT EXISTS express_sessions (
  sid VARCHAR NOT NULL COLLATE "default",
  sess JSON NOT NULL,
  expire TIMESTAMP(6) NOT NULL
) WITH (OIDS=FALSE);

-- Add primary key constraint
ALTER TABLE express_sessions ADD CONSTRAINT session_pkey PRIMARY KEY (sid) NOT DEFERRABLE INITIALLY IMMEDIATE;

-- Create index on expire column for efficient cleanup
CREATE INDEX IF NOT EXISTS IDX_session_expire ON express_sessions (expire);
