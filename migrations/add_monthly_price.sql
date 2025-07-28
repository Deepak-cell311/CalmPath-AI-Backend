-- Add monthly_price column to facilities table
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS monthly_price VARCHAR; 