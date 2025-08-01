const { Pool } = require('pg');
require('dotenv').config();

async function testDatabaseConnection() {
    console.log('Testing database connection...');
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
        
        // Test if auth_sessions table exists
        const tableCheck = await client.query(`
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'auth_sessions'
            );
        `);
        
        if (tableCheck.rows[0].exists) {
            console.log('✅ auth_sessions table exists');
            
            // Check table structure
            const tableStructure = await client.query(`
                SELECT column_name, data_type 
                FROM information_schema.columns 
                WHERE table_name = 'auth_sessions' 
                ORDER BY ordinal_position;
            `);
            
            console.log('Table structure:');
            tableStructure.rows.forEach(row => {
                console.log(`  - ${row.column_name}: ${row.data_type}`);
            });
            
            // Test inserting a session
            const testSessionId = 'test-session-' + Date.now();
            const testData = { user: { id: 1, email: 'test@example.com' } };
            const expireTime = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours from now
            
            const insertResult = await client.query(`
                INSERT INTO auth_sessions (sid, sess, expire) 
                VALUES ($1, $2, $3) 
                ON CONFLICT (sid) DO UPDATE SET 
                sess = EXCLUDED.sess, 
                expire = EXCLUDED.expire
            `, [testSessionId, JSON.stringify(testData), expireTime]);
            
            console.log('✅ Test session inserted successfully');
            
            // Test retrieving the session
            const getResult = await client.query(`
                SELECT * FROM auth_sessions WHERE sid = $1
            `, [testSessionId]);
            
            if (getResult.rows.length > 0) {
                console.log('✅ Test session retrieved successfully');
                console.log('Session data:', getResult.rows[0]);
            } else {
                console.log('❌ Test session not found after insert');
            }
            
            // Clean up test session
            await client.query(`
                DELETE FROM auth_sessions WHERE sid = $1
            `, [testSessionId]);
            
            console.log('✅ Test session cleaned up');
            
        } else {
            console.log('❌ auth_sessions table does not exist');
        }
        
        client.release();
        
    } catch (error) {
        console.error('❌ Database test failed:', error);
    } finally {
        await pool.end();
    }
}

testDatabaseConnection(); 