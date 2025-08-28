require('dotenv').config();

console.log('🔍 Environment Variable Analysis');
console.log('================================');
console.log('');

console.log('Local DATABASE_URL:');
if (process.env.DATABASE_URL) {
    const maskedUrl = process.env.DATABASE_URL.replace(/:\/\/[^:]+:[^@]+@/, '://***:***@');
    console.log('  ✅ Set:', maskedUrl);
    
    // Check if it's Supabase or Neon
    if (process.env.DATABASE_URL.includes('supabase.co')) {
        console.log('  📍 This is a Supabase connection');
    } else if (process.env.DATABASE_URL.includes('neon.tech')) {
        console.log('  ⚠️  This is still a Neon connection!');
    } else {
        console.log('  ❓ Unknown database provider');
    }
} else {
    console.log('  ❌ Not set');
}

console.log('');
console.log('Local NEON_DATABASE_URL:');
if (process.env.NEON_DATABASE_URL) {
    const maskedUrl = process.env.NEON_DATABASE_URL.replace(/:\/\/[^:]+:[^@]+@/, '://***:***@');
    console.log('  ⚠️  Still set:', maskedUrl);
} else {
    console.log('  ✅ Not set (good)');
}

console.log('');
console.log('🚨 The Problem:');
console.log('Your local .env file has the correct Supabase URL,');
console.log('but Railway (deployed environment) still has the old Neon URL.');
console.log('');
console.log('📋 To Fix:');
console.log('1. Go to Railway Dashboard → Your backend project');
console.log('2. Click "Variables" tab');
console.log('3. Delete any existing DATABASE_URL');
console.log('4. Add new DATABASE_URL with your Supabase connection string');
console.log('5. Remove NEON_DATABASE_URL if it exists');
console.log('6. Redeploy the application');
