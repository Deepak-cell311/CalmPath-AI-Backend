const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
require('dotenv').config();

async function testProductionSession() {
    console.log('=== Production Session Test ===');
    console.log('NODE_ENV:', process.env.NODE_ENV);
    console.log('DATABASE_URL present:', !!process.env.DATABASE_URL);
    console.log('SESSION_SECRET present:', !!process.env.SESSION_SECRET);
    
    if (!process.env.DATABASE_URL) {
        console.error('❌ DATABASE_URL is not set');
        return;
    }
    
    try {
        const PgSession = connectPgSimple(session);
        
        // Test with production-like settings
        const sessionStore = new PgSession({
            conObject: {
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            },
            tableName: 'auth_sessions',
            createTableIfMissing: true,
        });
        
        console.log('Session store created with SSL:', process.env.NODE_ENV === 'production');
        
        // Test session operations
        const testSessionId = 'prod-test-' + Date.now();
        const testData = {
            user: { id: 1, email: 'test@example.com' },
            cookie: {
                originalMaxAge: 24 * 60 * 60 * 1000,
                expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
                secure: process.env.NODE_ENV === 'production',
                httpOnly: true,
                path: '/'
            }
        };
        
        console.log('Testing session store with production settings...');
        console.log('Cookie secure setting:', process.env.NODE_ENV === 'production');
        
        // Test set
        sessionStore.set(testSessionId, testData, (err) => {
            if (err) {
                console.error('❌ Error setting session:', err);
                console.error('Error details:', err.message);
            } else {
                console.log('✅ Session set successfully');
                
                // Test get
                sessionStore.get(testSessionId, (err, data) => {
                    if (err) {
                        console.error('❌ Error getting session:', err);
                    } else {
                        console.log('✅ Session retrieved successfully');
                        console.log('Session data:', JSON.stringify(data, null, 2));
                        
                        // Test destroy
                        sessionStore.destroy(testSessionId, (err) => {
                            if (err) {
                                console.error('❌ Error destroying session:', err);
                            } else {
                                console.log('✅ Session destroyed successfully');
                                console.log('✅ Production session test passed!');
                                process.exit(0);
                            }
                        });
                    }
                });
            }
        });
        
    } catch (error) {
        console.error('❌ Production session test failed:', error);
        process.exit(1);
    }
}

testProductionSession(); 