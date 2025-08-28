const { Pool } = require('pg');
require('dotenv').config();

async function testConnection() {
  console.log('🧪 Testing different connection configurations...');
  
  if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL is not set');
    return;
  }
  
  console.log('Connection string:', process.env.DATABASE_URL.substring(0, 50) + '...');
  
  // Test different SSL configurations
  const configs = [
    { name: 'No SSL', ssl: false },
    { name: 'SSL with rejectUnauthorized: false', ssl: { rejectUnauthorized: false } },
    { name: 'SSL with no-verify', ssl: { rejectUnauthorized: false, ca: undefined } },
    { name: 'SSL with require', ssl: 'require' }
  ];
  
  for (const config of configs) {
    console.log(`\n🔍 Testing: ${config.name}`);
    
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: config.ssl
    });
    
    try {
      const client = await pool.connect();
      console.log(`✅ ${config.name} - Connection successful!`);
      
      // Test a simple query
      const result = await client.query('SELECT NOW()');
      console.log(`✅ Query successful: ${result.rows[0].now}`);
      
      client.release();
      await pool.end();
      
      console.log(`🎉 ${config.name} works! Use this configuration.`);
      return config;
      
    } catch (error) {
      console.log(`❌ ${config.name} - Failed: ${error.message}`);
      await pool.end();
    }
  }
  
  console.log('\n❌ All SSL configurations failed. Try using Supabase dashboard instead.');
}

testConnection();
