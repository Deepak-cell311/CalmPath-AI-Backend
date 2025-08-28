const { Pool } = require('pg');
const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function setupSupabaseSchema() {
  console.log('🔧 Setting up Supabase schema manually...');
  
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
    
    // Read the complete schema file
    const schemaPath = path.join(__dirname, '..', 'scripts', 'complete-schema.sql');
    const schemaSQL = fs.readFileSync(schemaPath, 'utf8');
    
    // Split the SQL into individual statements (better parsing)
    const statements = schemaSQL
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('--'))
      .join('\n')
      .split(';')
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0);
    
    console.log(`📋 Found ${statements.length} SQL statements to execute`);
    
    // Execute each statement
    for (let i = 0; i < statements.length; i++) {
      const statement = statements[i];
      if (statement.trim().length === 0) continue;
      
      console.log(`🔨 Executing statement ${i + 1}/${statements.length}...`);
      console.log(`   Statement preview: ${statement.substring(0, 50)}...`);
      
      try {
        await client.query(statement);
        console.log(`✅ Statement ${i + 1} executed successfully`);
      } catch (error) {
        // If it's a "relation already exists" error, that's okay
        if (error.code === '42P07' || error.message.includes('already exists')) {
          console.log(`⚠️  Statement ${i + 1} skipped (already exists)`);
        } else {
          console.error(`❌ Statement ${i + 1} failed:`, error.message);
          console.error(`   Full statement: ${statement}`);
          // Don't throw, continue with other statements
        }
      }
    }
    
    console.log('🎉 Schema setup completed successfully!');
    
    // Verify the tables were created
    console.log('🔍 Verifying tables...');
    const tables = [
      'users', 'facilities', 'patients', 'sessions', 'conversations',
      'memory_photos', 'staff_notes', 'mood_logs', 'therapeutic_photos',
      'alerts', 'medications', 'reminders', 'personal_info',
      'facility_invite_packages', 'facility_invite_purchases', 'facility_invites',
      'auth_sessions', 'user_sessions', 'emergency_events'
    ];
    
    for (const table of tables) {
      const tableCheck = await client.query(`
        SELECT EXISTS (
          SELECT FROM information_schema.tables 
          WHERE table_schema = 'public' 
          AND table_name = $1
        );
      `, [table]);
      
      if (tableCheck.rows[0].exists) {
        console.log(`✅ Table ${table} exists`);
      } else {
        console.log(`❌ Table ${table} missing`);
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
  setupSupabaseSchema()
    .then(() => {
      console.log('Schema setup script completed');
      process.exit(0);
    })
    .catch((error) => {
      console.error('Schema setup script failed:', error);
      process.exit(1);
    });
}

module.exports = { setupSupabaseSchema };
