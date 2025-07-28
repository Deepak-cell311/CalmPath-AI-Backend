-- Add branding fields to facilities table
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS tagline VARCHAR(255);
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS logo_url VARCHAR(255);
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS brand_color VARCHAR(16); 