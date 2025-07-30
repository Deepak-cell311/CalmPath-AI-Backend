-- Fix reminders foreign key constraint issue

-- First, let's see what invalid created_by values exist
-- SELECT DISTINCT created_by FROM reminders WHERE created_by NOT IN (SELECT id FROM users);

-- Update invalid created_by values to a valid user ID or NULL
UPDATE reminders 
SET created_by = NULL 
WHERE created_by NOT IN (SELECT id FROM users) OR created_by IS NULL;

-- Make the foreign key constraint nullable if it isn't already
ALTER TABLE reminders ALTER COLUMN created_by DROP NOT NULL; 