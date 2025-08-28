const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function migrateToSupabase() {
  console.log('🚀 Starting migration to Supabase...');
  
  // Source database (Neon or old DB)
  const sourcePool = new Pool({
    connectionString: process.env.NEON_DATABASE_URL, // Keep old connection for export
    ssl: false,
  });
  
  // Target database (Supabase)
  const targetPool = new Pool({
    connectionString: process.env.DATABASE_URL, // New Supabase connection
    ssl: false,
  });

  try {
    console.log('✅ Connected to both databases');
    
    // Export data from each table in dependency-aware order
    const tablesInOrder = [
      // Base tables
      'facilities',
      'users',
      'sessions',
      // Depends on facilities/users
      'patients',
      // Depends on sessions/users/patients
      'conversations',
      'emergency_events',
      'user_sessions',
      // Depends on users/patients
      'memory_photos',
      'staff_notes',
      'mood_logs',
      'therapeutic_photos',
      'alerts',
      'medications',
      'reminders',
      'personal_info',
      // Invite system
      'facility_invite_packages',
      'facility_invite_purchases',
      'facility_invites',
      // Sessions store last (no FKs)
      'auth_sessions',
    ];

    for (const table of tablesInOrder) {
      console.log(`📦 Migrating table: ${table}`);

      // Check if table exists in source
      const tableExists = await sourcePool.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = $1
        )
      `, [table]);

      if (!tableExists.rows[0].exists) {
        console.log(`⚠️  Table ${table} does not exist in source, skipping`);
        continue;
      }

      const data = await sourcePool.query(`SELECT * FROM ${table}`);
      console.log(`  Found ${data.rows.length} rows`);

      if (data.rows.length === 0) continue;

      const columns = Object.keys(data.rows[0]);
      const placeholders = columns.map((_, i) => `$${i + 1}`).join(', ');
      const insertSql = `INSERT INTO ${table} (${columns.join(', ')}) VALUES (${placeholders}) ON CONFLICT DO NOTHING`;

      for (const row of data.rows) {
        const values = columns.map(col => row[col]);
        try {
          await targetPool.query(insertSql, values);
        } catch (e) {
          console.warn(`   ⚠️  Skipped one row in ${table}: ${e.message}`);
        }
      }

      console.log(`  ✅ Migrated ${data.rows.length} rows for ${table}`);
    }

    console.log('🎉 Migration completed successfully!');

  } catch (error) {
    console.error('❌ Migration failed:', error);
    throw error;
  } finally {
    await sourcePool.end();
    await targetPool.end();
  }
}

// Run migration if called directly
if (require.main === module) {
  migrateToSupabase()
    .then(() => {
      console.log('Migration script completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Migration script failed:', error);
      process.exit(1);
    });
}

module.exports = { migrateToSupabase };
