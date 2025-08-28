const { Pool } = require('pg');
require('dotenv').config();

async function setupSupabaseSchemaOrdered() {
  console.log('🔧 Setting up Supabase schema in correct order...');
  
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is not set');
    return;
  }
  
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false
  });

  try {
    const client = await pool.connect();
    console.log('✅ Connected to Supabase database');
    
    // Create enums first
    console.log('🔨 Creating enums...');
    try {
      await client.query(`CREATE TYPE role AS ENUM ('admin', 'caregiver', 'patient', 'family')`);
      console.log('✅ role enum created');
    } catch (error) {
      if (error.message.includes('already exists')) {
        console.log('⚠️  role enum already exists');
      } else {
        throw error;
      }
    }
    
    try {
      await client.query(`CREATE TYPE care_level AS ENUM ('low', 'medium', 'high')`);
      console.log('✅ care_level enum created');
    } catch (error) {
      if (error.message.includes('already exists')) {
        console.log('⚠️  care_level enum already exists');
      } else {
        throw error;
      }
    }
    console.log('✅ Enums created');
    
    // Create tables in dependency order
    const tables = [
      // 1. Independent tables (no foreign keys)
      {
        name: 'sessions',
        sql: `CREATE TABLE IF NOT EXISTS "sessions" (
          "id" serial PRIMARY KEY NOT NULL,
          "start_time" timestamp DEFAULT now() NOT NULL,
          "end_time" timestamp,
          "duration" text,
          "interaction_count" integer NOT NULL DEFAULT 0,
          "calming_score" integer NOT NULL DEFAULT 0
        )`
      },
      {
        name: 'facilities',
        sql: `CREATE TABLE IF NOT EXISTS "facilities" (
          "id" varchar PRIMARY KEY NOT NULL,
          "name" varchar NOT NULL,
          "address" text,
          "phone" varchar,
          "admin_email" varchar,
          "subscription_tier" varchar DEFAULT 'basic',
          "monthly_price" varchar,
          "max_patients" integer DEFAULT 10,
          "is_active" boolean DEFAULT true,
          "promo_code" varchar,
          "stripe_product_id" varchar,
          "stripe_price_id" varchar,
          "stripe_coupon_id" varchar,
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now(),
          "tagline" varchar(255),
          "logo_url" varchar(255),
          "brand_color" varchar(16)
        )`
      },
      {
        name: 'auth_sessions',
        sql: `CREATE TABLE IF NOT EXISTS "auth_sessions" (
          "sid" varchar PRIMARY KEY NOT NULL,
          "sess" jsonb NOT NULL,
          "expire" timestamp NOT NULL
        )`
      },
      
      // 2. Tables that depend on facilities
      {
        name: 'users',
        sql: `CREATE TABLE IF NOT EXISTS "users" (
          "id" varchar PRIMARY KEY NOT NULL,
          "email" varchar UNIQUE,
          "first_name" varchar,
          "last_name" varchar,
          "profile_image_url" varchar,
          "phone_number" varchar(10) UNIQUE,
          "account_type" varchar DEFAULT 'Patient',
          "facility_id" varchar REFERENCES "facilities"("id"),
          "role" role DEFAULT 'patient',
          "password_hash" text NOT NULL,
          "stripe_customer_id" varchar,
          "stripe_subscription_id" varchar,
          "subscription_status" varchar DEFAULT 'inactive',
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now(),
          "status" varchar(20),
          "room_number" varchar,
          "care_level" care_level DEFAULT 'low',
          "medical_notes" text,
          "last_interaction" timestamp,
          "admission_date" timestamp,
          "emergency_contact" varchar,
          "emergency_phone" varchar,
          "is_active" boolean,
          "user_id" varchar,
          "relation_to_patient" varchar,
          "patient_access_code" varchar,
          "facility_staff_facility_id" varchar REFERENCES "facilities"("id"),
          "used_invite_code" boolean DEFAULT false
        )`
      },
      
      // 3. Tables that depend on users and facilities
      {
        name: 'patients',
        sql: `CREATE TABLE IF NOT EXISTS "patients" (
          "id" serial PRIMARY KEY NOT NULL,
          "facility_id" varchar REFERENCES "facilities"("id"),
          "user_id" varchar REFERENCES "users"("id"),
          "first_name" varchar NOT NULL,
          "last_name" varchar NOT NULL,
          "age" integer DEFAULT 0,
          "status" varchar(20) NOT NULL DEFAULT 'ok',
          "room_number" varchar,
          "care_level" care_level DEFAULT 'low',
          "medical_notes" text,
          "last_interaction" timestamp DEFAULT now(),
          "profile_image_url" varchar,
          "admission_date" timestamp DEFAULT now(),
          "emergency_contact" varchar,
          "emergency_phone" varchar,
          "is_active" boolean DEFAULT true,
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now()
        )`
      },
      
      // 4. Tables that depend on sessions, patients, and users
      {
        name: 'conversations',
        sql: `CREATE TABLE IF NOT EXISTS "conversations" (
          "id" serial PRIMARY KEY NOT NULL,
          "session_id" integer REFERENCES "sessions"("id"),
          "patient_id" integer REFERENCES "patients"("id"),
          "staff_id" varchar REFERENCES "users"("id"),
          "user_message" text NOT NULL,
          "transcript" text,
          "duration" integer,
          "sentiment" varchar(20),
          "ai_response" text NOT NULL,
          "intent" text,
          "redirection_type" text,
          "timestamp" timestamp DEFAULT now() NOT NULL
        )`
      },
      {
        name: 'emergency_events',
        sql: `CREATE TABLE IF NOT EXISTS "emergency_events" (
          "id" serial PRIMARY KEY NOT NULL,
          "session_id" integer REFERENCES "sessions"("id"),
          "event_type" text NOT NULL,
          "description" text,
          "timestamp" timestamp DEFAULT now() NOT NULL
        )`
      },
      {
        name: 'user_sessions',
        sql: `CREATE TABLE IF NOT EXISTS "user_sessions" (
          "id" serial PRIMARY KEY NOT NULL,
          "user_id" varchar REFERENCES "users"("id") NOT NULL,
          "patient_id" integer REFERENCES "patients"("id"),
          "session_id" integer REFERENCES "sessions"("id") NOT NULL,
          "timestamp" timestamp DEFAULT now() NOT NULL
        )`
      },
      
      // 5. Tables that depend on patients and users
      {
        name: 'memory_photos',
        sql: `CREATE TABLE IF NOT EXISTS "memory_photos" (
          "id" serial PRIMARY KEY NOT NULL,
          "uploaded_by" varchar(255) REFERENCES "users"("id"),
          "photoname" varchar(255) NOT NULL,
          "description" text,
          "context_and_story" text,
          "file" varchar(500) NOT NULL,
          "tags" jsonb NOT NULL DEFAULT '[]',
          "created_at" timestamp DEFAULT now() NOT NULL
        )`
      },
      {
        name: 'staff_notes',
        sql: `CREATE TABLE IF NOT EXISTS "staff_notes" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "staff_id" varchar NOT NULL REFERENCES "users"("id"),
          "content" text NOT NULL,
          "created_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'mood_logs',
        sql: `CREATE TABLE IF NOT EXISTS "mood_logs" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "status" varchar(20) NOT NULL,
          "logged_by" varchar,
          "notes" text,
          "created_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'therapeutic_photos',
        sql: `CREATE TABLE IF NOT EXISTS "therapeutic_photos" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "staff_id" varchar REFERENCES "users"("id"),
          "url" varchar(500) NOT NULL,
          "transcript" text,
          "description" text,
          "duration" integer,
          "sentiment" varchar(20),
          "category" varchar(50),
          "uploaded_by" varchar REFERENCES "users"("id"),
          "created_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'alerts',
        sql: `CREATE TABLE IF NOT EXISTS "alerts" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "type" varchar(50) NOT NULL,
          "message" text NOT NULL,
          "is_read" boolean DEFAULT false,
          "created_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'medications',
        sql: `CREATE TABLE IF NOT EXISTS "medications" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "name" varchar(255) NOT NULL,
          "dosage" varchar(100),
          "frequency" varchar(100),
          "time" varchar(100),
          "created_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'reminders',
        sql: `CREATE TABLE IF NOT EXISTS "reminders" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "created_by" varchar,
          "message" text NOT NULL,
          "scheduled_time" timestamp NOT NULL,
          "is_active" boolean DEFAULT true,
          "is_completed" boolean DEFAULT false,
          "completed_at" timestamp,
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now()
        )`
      },
      {
        name: 'personal_info',
        sql: `CREATE TABLE IF NOT EXISTS "personal_info" (
          "id" serial PRIMARY KEY NOT NULL,
          "patient_id" integer NOT NULL REFERENCES "patients"("id"),
          "work" text,
          "family" text,
          "hobbies" text,
          "food" text,
          "other" text,
          "created_by" varchar REFERENCES "users"("id"),
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now()
        )`
      },
      
      // 6. Tables that depend on facilities
      {
        name: 'facility_invite_packages',
        sql: `CREATE TABLE IF NOT EXISTS "facility_invite_packages" (
          "id" serial PRIMARY KEY NOT NULL,
          "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
          "package_name" varchar(100) NOT NULL,
          "invite_count" integer NOT NULL,
          "price_in_cents" integer NOT NULL,
          "stripe_price_id" varchar,
          "is_active" boolean DEFAULT true,
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now()
        )`
      },
      
      // 7. Tables that depend on facility_invite_packages
      {
        name: 'facility_invite_purchases',
        sql: `CREATE TABLE IF NOT EXISTS "facility_invite_purchases" (
          "id" serial PRIMARY KEY NOT NULL,
          "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
          "package_id" integer NOT NULL REFERENCES "facility_invite_packages"("id"),
          "stripe_session_id" varchar,
          "stripe_payment_intent_id" varchar,
          "total_paid_in_cents" integer NOT NULL,
          "invite_count" integer NOT NULL,
          "status" varchar DEFAULT 'pending',
          "purchased_at" timestamp DEFAULT now(),
          "completed_at" timestamp
        )`
      },
      
      // 8. Tables that depend on facility_invite_purchases and users
      {
        name: 'facility_invites',
        sql: `CREATE TABLE IF NOT EXISTS "facility_invites" (
          "id" serial PRIMARY KEY NOT NULL,
          "facility_id" varchar NOT NULL REFERENCES "facilities"("id"),
          "purchase_id" integer NOT NULL REFERENCES "facility_invite_purchases"("id"),
          "invite_code" varchar(20) NOT NULL UNIQUE,
          "invited_email" varchar,
          "invited_phone" varchar,
          "invited_name" varchar(100),
          "status" varchar DEFAULT 'unused',
          "used_by_user_id" varchar REFERENCES "users"("id"),
          "used_at" timestamp,
          "expires_at" timestamp,
          "created_at" timestamp DEFAULT now(),
          "updated_at" timestamp DEFAULT now()
        )`
      }
    ];
    
    // Create tables in order
    for (let i = 0; i < tables.length; i++) {
      const table = tables[i];
      console.log(`🔨 Creating table ${i + 1}/${tables.length}: ${table.name}`);
      
      try {
        await client.query(table.sql);
        console.log(`✅ Table ${table.name} created successfully`);
      } catch (error) {
        if (error.code === '42P07' || error.message.includes('already exists')) {
          console.log(`⚠️  Table ${table.name} already exists`);
        } else {
          console.error(`❌ Failed to create table ${table.name}:`, error.message);
          throw error;
        }
      }
    }
    
    // Create index for auth sessions
    console.log('🔨 Creating auth sessions index...');
    await client.query(`CREATE INDEX IF NOT EXISTS "IDX_session_expire" ON "auth_sessions" ("expire")`);
    console.log('✅ Auth sessions index created');
    
    console.log('🎉 Schema setup completed successfully!');
    
    // Verify the tables were created
    console.log('🔍 Verifying tables...');
    const tableNames = tables.map(t => t.name);
    
    for (const tableName of tableNames) {
      const tableCheck = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = $1
        );
      `, [tableName]);
      
      if (tableCheck.rows[0].exists) {
        console.log(`✅ Table ${tableName} exists`);
      } else {
        console.log(`❌ Table ${tableName} missing`);
      }
    }
    
    client.release();
    
  } catch (error) {
    console.error('❌ Schema setup failed:', error);
    throw error;
  } finally {
    await pool.end();
  }
}

// Run if called directly
if (require.main === module) {
  setupSupabaseSchemaOrdered()
    .then(() => {
      console.log('Schema setup script completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Schema setup script failed:', error);
      process.exit(1);
    });
}

module.exports = { setupSupabaseSchemaOrdered };
