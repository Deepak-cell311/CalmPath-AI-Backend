const { Pool } = require('pg');
require('dotenv').config();

async function testSupabaseConnection() {
    console.log('🧪 Testing Supabase database connection...');
    console.log('DATABASE_URL present:', !!process.env.DATABASE_URL);
    
    if (!process.env.DATABASE_URL) {
        console.error('❌ DATABASE_URL is not set');
        return;
    }
    
    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    });
    
    try {
        // Test basic connection
        const client = await pool.connect();
        console.log('✅ Database connection successful');
        
        // Test if tables exist
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
                const countResult = await client.query(`SELECT COUNT(*) FROM ${table}`);
                console.log(`✅ Table ${table}: ${countResult.rows[0].count} rows`);
            } else {
                console.log(`❌ Table ${table}: Not found`);
            }
        }
        
        // Test session store
        const sessionCheck = await client.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'auth_sessions'
            );
        `);
        
        if (sessionCheck.rows[0].exists) {
            console.log('✅ Session store table exists');
        } else {
            console.log('❌ Session store table missing');
        }
        
        // Test Supabase-specific features
        console.log('🔍 Testing Supabase features...');
        
        // Check if we can create a test table
        await client.query(`
            CREATE TABLE IF NOT EXISTS test_migration (
                id SERIAL PRIMARY KEY,
                message TEXT,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        console.log('✅ Can create tables');
        
        // Insert test data
        await client.query(`
            INSERT INTO test_migration (message) VALUES ($1)
            ON CONFLICT DO NOTHING
        `, ['Migration test successful']);
        console.log('✅ Can insert data');
        
        // Query test data
        const testResult = await client.query('SELECT * FROM test_migration');
        console.log('✅ Can query data:', testResult.rows.length, 'rows');
        
        // Clean up test table
        await client.query('DROP TABLE IF EXISTS test_migration');
        console.log('✅ Can drop tables');
        
        client.release();
        console.log('🎉 All Supabase tests passed!');
        
    } catch (error) {
        console.error('❌ Connection test failed:', error);
    } finally {
        await pool.end();
    }
}

testSupabaseConnection();
