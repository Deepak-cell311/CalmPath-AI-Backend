-- Add Stripe fields to facilities table
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS promo_code VARCHAR;
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS stripe_product_id VARCHAR;
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS stripe_price_id VARCHAR;
ALTER TABLE facilities ADD COLUMN IF NOT EXISTS stripe_coupon_id VARCHAR; 