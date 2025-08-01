const session = require('express-session');
const connectPgSimple = require('connect-pg-simple');
require('dotenv').config();

async function testSessionStore() {
    console.log('Testing session store...');
    console.log('DATABASE_URL:', process.env.DATABASE_URL ? 'Present' : 'Missing');
    
    if (!process.env.DATABASE_URL) {
        console.error('❌ DATABASE_URL is not set');
        return;
    }
    
    try {
        const PgSession = connectPgSimple(session);
        
        const sessionStore = new PgSession({
            conObject: {
                connectionString: process.env.DATABASE_URL,
                ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            },
            tableName: 'auth_sessions',
            createTableIfMissing: true,
        });
        
        console.log('Session store created');
        
        // Test session operations
        const testSessionId = 'test-session-' + Date.now();
        const testData = {
            user: { id: 1, email: 'test@example.com' },
            cookie: {
                originalMaxAge: 24 * 60 * 60 * 1000,
                expires: new Date(Date.now() + 24 * 60 * 60 * 1000),
                secure: false,
                httpOnly: true,
                path: '/'
            }
        };
        
        console.log('Testing session store set...');
        
        // Test set
        sessionStore.set(testSessionId, testData, (err) => {
            if (err) {
                console.error('❌ Error setting session:', err);
            } else {
                console.log('✅ Session set successfully');
                
                // Test get
                console.log('Testing session store get...');
                sessionStore.get(testSessionId, (err, data) => {
                    if (err) {
                        console.error('❌ Error getting session:', err);
                    } else {
                        console.log('✅ Session retrieved successfully');
                        console.log('Session data:', data);
                        
                        // Test destroy
                        console.log('Testing session store destroy...');
                        sessionStore.destroy(testSessionId, (err) => {
                            if (err) {
                                console.error('❌ Error destroying session:', err);
                            } else {
                                console.log('✅ Session destroyed successfully');
                                console.log('✅ All session store tests passed!');
                                process.exit(0);
                            }
                        });
                    }
                });
            }
        });
        
    } catch (error) {
        console.error('❌ Session store test failed:', error);
        process.exit(1);
    }
}

testSessionStore(); 