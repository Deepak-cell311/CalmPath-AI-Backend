const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

async function createInviteTables() {
  const client = await pool.connect();
  
  try {
    console.log('Creating invite system tables...');
    
    // Create facility_invite_packages table
    await client.query(`
      CREATE TABLE IF NOT EXISTS "facility_invite_packages" (
        "id" serial PRIMARY KEY,
        "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
        "package_name" varchar(100) NOT NULL,
        "invite_count" integer NOT NULL,
        "price_in_cents" integer NOT NULL,
        "stripe_price_id" varchar,
        "is_active" boolean DEFAULT true,
        "created_at" timestamp DEFAULT now(),
        "updated_at" timestamp DEFAULT now()
      );
    `);
    
    // Create facility_invite_purchases table
    await client.query(`
      CREATE TABLE IF NOT EXISTS "facility_invite_purchases" (
        "id" serial PRIMARY KEY,
        "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
        "package_id" integer NOT NULL REFERENCES "facility_invite_packages"("id"),
        "stripe_session_id" varchar,
        "stripe_payment_intent_id" varchar,
        "total_paid_in_cents" integer NOT NULL,
        "invite_count" integer NOT NULL,
        "status" varchar DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'failed', 'refunded')),
        "purchased_at" timestamp DEFAULT now(),
        "completed_at" timestamp
      );
    `);
    
    // Create facility_invites table
    await client.query(`
      CREATE TABLE IF NOT EXISTS "facility_invites" (
        "id" serial PRIMARY KEY,
        "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
        "purchase_id" integer NOT NULL REFERENCES "facility_invite_purchases"("id"),
        "invite_code" varchar(20) NOT NULL UNIQUE,
        "invited_email" varchar,
        "invited_phone" varchar,
        "invited_name" varchar(100),
        "status" varchar DEFAULT 'unused' CHECK (status IN ('unused', 'used', 'expired')),
        "used_by_user_id" varchar REFERENCES "users"("id"),
        "used_at" timestamp,
        "expires_at" timestamp,
        "created_at" timestamp DEFAULT now(),
        "updated_at" timestamp DEFAULT now()
      );
    `);
    
    // Create indexes
    await client.query(`
      CREATE INDEX IF NOT EXISTS "idx_facility_invite_packages_facility_id" ON "facility_invite_packages"("facility_id");
      CREATE INDEX IF NOT EXISTS "idx_facility_invite_purchases_facility_id" ON "facility_invite_purchases"("facility_id");
      CREATE INDEX IF NOT EXISTS "idx_facility_invite_purchases_status" ON "facility_invite_purchases"("status");
      CREATE INDEX IF NOT EXISTS "idx_facility_invites_facility_id" ON "facility_invites"("facility_id");
      CREATE INDEX IF NOT EXISTS "idx_facility_invites_invite_code" ON "facility_invites"("invite_code");
      CREATE INDEX IF NOT EXISTS "idx_facility_invites_status" ON "facility_invites"("status");
    `);
    
    console.log('✅ Invite system tables created successfully!');
    
  } catch (error) {
    console.error('❌ Error creating tables:', error);
  } finally {
    client.release();
    await pool.end();
  }
}

createInviteTables(); 