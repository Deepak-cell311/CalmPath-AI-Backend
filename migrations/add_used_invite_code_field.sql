-- Add usedInviteCode field to users table
ALTER TABLE users ADD COLUMN used_invite_code BOOLEAN DEFAULT FALSE; 