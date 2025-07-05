ALTER TABLE user_sessions
ALTER COLUMN patient_id TYPE integer USING patient_id::integer; 
