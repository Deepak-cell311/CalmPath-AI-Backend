# Supabase Migration Guide

## Overview
This guide will help you migrate from Neon to Supabase for the CalmPath AI application.

## Prerequisites
- ✅ Supabase project created
- ✅ Connection string: `postgresql://postgres:@Bluorigin16@db.niolmjuvgsubjaszdvpl.supabase.co:5432/postgres`
- ✅ Supabase URL: `https://niolmjuvgsubjaszdvpl.supabase.co`
- ✅ Anon Key: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5pb2xtanV2Z3N1Ymphc3pkdnBsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYzODUxODIsImV4cCI6MjA3MTk2MTE4Mn0.q05ZNrrVL-beqdBJWJmssmuD2QayP7iwWGcx0CfQvZw`

## Step 1: Update Environment Variables

### Backend (.env):
```env
# Old Neon URL (keep for migration)
NEON_DATABASE_URL=your_current_neon_connection_string

# New Supabase URL
DATABASE_URL=postgresql://postgres:@Bluorigin16@db.niolmjuvgsubjaszdvpl.supabase.co:5432/postgres?sslmode=require

# Supabase specific variables
NEXT_PUBLIC_SUPABASE_URL=https://niolmjuvgsubjaszdvpl.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5pb2xtanV2Z3N1Ymphc3pkdnBsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYzODUxODIsImV4cCI6MjA3MTk2MTE4Mn0.q05ZNrrVL-beqdBJWJmssmuD2QayP7iwWGcx0CfQvZw

NODE_ENV=production
```

### Frontend (.env.local):
```env
DATABASE_URL=postgresql://postgres:@Bluorigin16@db.niolmjuvgsubjaszdvpl.supabase.co:5432/postgres?sslmode=require
NEXT_PUBLIC_SUPABASE_URL=https://niolmjuvgsubjaszdvpl.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5pb2xtanV2Z3N1Ymphc3pkdnBsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTYzODUxODIsImV4cCI6MjA3MTk2MTE4Mn0.q05ZNrrVL-beqdBJWJmssmuD2QayP7iwWGcx0CfQvZw
NEXT_PUBLIC_API_URL=https://your-api-domain.com
```

## Step 2: Install Dependencies

```bash
cd CalmPath-AI-Backend
pnpm install
```

## Step 3: Generate and Push Schema

1. **Generate Schema**:
   ```bash
   pnpm run db:generate
   ```

2. **Push Schema to Supabase**:
   ```bash
   pnpm run db:push
   ```

## Step 4: Test Connection

```bash
node test-supabase-connection.js
```

## Step 5: Migrate Data (if needed)

If you have existing data in Neon that needs to be migrated:

```bash
node scripts/migrate-to-supabase.js
```

## Step 6: Test Application

1. **Test Backend**:
   ```bash
   pnpm run dev
   ```

2. **Test Frontend**:
   ```bash
   cd ../CalmPath-AI
   npm run dev
   ```

## Step 7: Deploy to Production

1. **Build Backend**:
   ```bash
   pnpm run build
   pnpm start
   ```

2. **Build Frontend**:
   ```bash
   cd ../CalmPath-AI
   npm run build
   npm start
   ```

## Troubleshooting

### Connection Issues:
- **SSL Error**: Make sure `?sslmode=require` is added to the connection string
- **Authentication Error**: Verify the password in the connection string
- **Network Error**: Check if your IP is allowed in Supabase dashboard

### Migration Issues:
- **Table Not Found**: Run `pnpm run db:push` first to create tables
- **Data Type Mismatch**: Check for any schema differences
- **Foreign Key Errors**: Ensure tables are created in the correct order

### Performance Issues:
- **Slow Queries**: Check Supabase dashboard for query performance
- **Connection Pool**: Already configured with optimal settings
- **Indexes**: Consider adding indexes for frequently queried columns

## Supabase Dashboard Features

### 1. **Table Editor**
- View and edit data directly in the browser
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/editor`

### 2. **SQL Editor**
- Run custom SQL queries
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/sql/new`

### 3. **Database Settings**
- Configure connection settings
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/settings/database`

### 4. **Logs**
- View query logs and errors
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/logs`

## Monitoring

### 1. **Usage Dashboard**
- Monitor database usage and performance
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/usage`

### 2. **Performance Insights**
- View slow queries and optimization suggestions
- URL: `https://niolmjuvgsubjaszdvpl.supabase.co/project/default/performance`

## Security Best Practices

1. **Environment Variables**: Never commit secrets to version control
2. **Connection Pooling**: Already configured for optimal performance
3. **SSL**: Always use SSL in production (configured)
4. **Row Level Security**: Consider enabling for sensitive tables
5. **Backup**: Supabase handles automatic backups

## Cost Optimization

### Free Tier Limits:
- 500MB database storage
- 2GB bandwidth
- 50,000 monthly active users
- 500MB file storage

### Pro Plan ($25/month):
- 8GB database storage
- 250GB bandwidth
- 100,000 monthly active users
- 100GB file storage

## Rollback Plan

If you need to rollback to Neon:

1. **Keep Neon Database**: Don't delete until migration is verified
2. **Update Environment Variables**: Switch back to Neon URLs
3. **Revert Code Changes**: If needed, revert to Neon-specific code
4. **Test Thoroughly**: Ensure everything works before deleting Neon

## Next Steps

1. ✅ Update environment variables
2. ✅ Install dependencies
3. ✅ Generate and push schema
4. ✅ Test connection
5. ✅ Migrate data (if needed)
6. ✅ Test application
7. ✅ Deploy to production
8. ✅ Monitor performance
9. ✅ Consider additional Supabase features

## Additional Supabase Features (Optional)

### 1. **Real-time Subscriptions**
```typescript
// Example: Real-time patient updates
import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
)

// Subscribe to patient changes
supabase
  .channel('patients')
  .on('postgres_changes', { event: '*', schema: 'public', table: 'patients' }, payload => {
    console.log('Patient changed:', payload)
  })
  .subscribe()
```

### 2. **Row Level Security**
```sql
-- Enable RLS on users table
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Create policy for users to see only their own data
CREATE POLICY "Users can view own data" ON users
  FOR SELECT USING (auth.uid()::text = id);
```

### 3. **Database Functions**
```sql
-- Example: Function to get patient stats
CREATE OR REPLACE FUNCTION get_patient_stats(facility_id_param text)
RETURNS TABLE(total bigint, active bigint, invited bigint, inactive bigint)
LANGUAGE sql
AS $$
  SELECT 
    COUNT(*) as total,
    COUNT(CASE WHEN status = 'Active' THEN 1 END) as active,
    COUNT(CASE WHEN status = 'Invited' THEN 1 END) as invited,
    COUNT(CASE WHEN status = 'Inactive' THEN 1 END) as inactive
  FROM patients
  WHERE facility_id = facility_id_param;
$$;
```

## Support

- **Supabase Documentation**: https://supabase.com/docs
- **Supabase Community**: https://github.com/supabase/supabase/discussions
- **Supabase Discord**: https://discord.supabase.com
