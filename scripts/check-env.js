require('dotenv').config();

console.log('🔍 Checking environment variables...');
console.log('');

console.log('DATABASE_URL:', process.env.DATABASE_URL ? '✅ Set' : '❌ Not set');
if (process.env.DATABASE_URL) {
  // Mask the password for security
  const maskedUrl = process.env.DATABASE_URL.replace(/:\/\/[^:]+:[^@]+@/, '://***:***@');
  console.log('  URL:', maskedUrl);
}

console.log('NEON_DATABASE_URL:', process.env.NEON_DATABASE_URL ? '⚠️  Still set (should be removed)' : '✅ Not set');
if (process.env.NEON_DATABASE_URL) {
  const maskedUrl = process.env.NEON_DATABASE_URL.replace(/:\/\/[^:]+:[^@]+@/, '://***:***@');
  console.log('  URL:', maskedUrl);
}

console.log('');
console.log('NODE_ENV:', process.env.NODE_ENV || 'Not set');
console.log('PORT:', process.env.PORT || 'Not set');

// Test database connection
if (process.env.DATABASE_URL) {
  console.log('');
  console.log('🔌 Testing database connection...');
  
  const { Pool } = require('pg');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: false
  });

  pool.query('SELECT NOW() as current_time, version() as db_version')
    .then(result => {
      console.log('✅ Database connection successful!');
      console.log('  Current time:', result.rows[0].current_time);
      console.log('  Database version:', result.rows[0].db_version.split(' ')[0]);
      pool.end();
    })
    .catch(err => {
      console.log('❌ Database connection failed:', err.message);
      pool.end();
    });
} else {
  console.log('');
  console.log('❌ Cannot test database connection - DATABASE_URL not set');
}
