const { Pool } = require('pg');

console.log('=== Environment Variable Debug ===');
console.log('DATABASE_URL length:', process.env.DATABASE_URL ? process.env.DATABASE_URL.length : 'Not set');
console.log('DATABASE_URL value:', process.env.DATABASE_URL);
console.log('NODE_ENV:', process.env.NODE_ENV);

if (process.env.DATABASE_URL) {
    try {
        // Try to parse the URL
        const url = new URL(process.env.DATABASE_URL);
        console.log('\n=== URL Parsing ===');
        console.log('Protocol:', url.protocol);
        console.log('Hostname:', url.hostname);
        console.log('Port:', url.port);
        console.log('Pathname:', url.pathname);
        console.log('Username:', url.username);
        console.log('Password length:', url.password ? url.password.length : 'No password');
        
        // Test connection
        console.log('\n=== Testing Connection ===');
        const pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: false
        });
        
        const client = await pool.connect();
        const result = await client.query('SELECT NOW() as current_time');
        console.log('Connection successful!');
        console.log('Current time:', result.rows[0].current_time);
        client.release();
        await pool.end();
        
    } catch (error) {
        console.error('Error:', error.message);
        console.error('Error code:', error.code);
        console.error('Error hostname:', error.hostname);
    }
} else {
    console.log('DATABASE_URL is not set!');
}
