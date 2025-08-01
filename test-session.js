const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
const { Pool } = require('pg');

// Test database connection
async function testSessionStore() {
    try {
        console.log('Testing session store connection...');
        
        const PgSession = connectPgSimple(session);
        const sessionStore = new PgSession({
            conObject: {
                connectionString: process.env.DATABASE_URL,
            },
            tableName: 'auth_sessions',
            createTableIfMissing: true,
        });
        
        // Test connection
        sessionStore.on('connect', () => {
            console.log('✅ Session store connected successfully');
        });
        
        sessionStore.on('error', (error) => {
            console.error('❌ Session store error:', error);
        });
        
        // Test session operations
        const testSessionId = 'test-session-' + Date.now();
        const testData = { user: { id: 1, email: 'test@example.com' } };
        
        // Test set
        sessionStore.set(testSessionId, testData, (err) => {
            if (err) {
                console.error('❌ Error setting session:', err);
            } else {
                console.log('✅ Session set successfully');
                
                // Test get
                sessionStore.get(testSessionId, (err, data) => {
                    if (err) {
                        console.error('❌ Error getting session:', err);
                    } else {
                        console.log('✅ Session retrieved successfully:', data);
                        
                        // Test destroy
                        sessionStore.destroy(testSessionId, (err) => {
                            if (err) {
                                console.error('❌ Error destroying session:', err);
                            } else {
                                console.log('✅ Session destroyed successfully');
                                process.exit(0);
                            }
                        });
                    }
                });
            }
        });
        
    } catch (error) {
        console.error('❌ Test failed:', error);
        process.exit(1);
    }
}

// Load environment variables
require('dotenv').config();

testSessionStore(); 