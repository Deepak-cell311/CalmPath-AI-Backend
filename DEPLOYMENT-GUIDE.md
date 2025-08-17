# EC2 Deployment Guide for CalmPath AI Backend

## Issue Resolution: Multer Uploads Directory

The error `ENOENT: no such file or directory, open '/root/CalmPath-AI-Backend/dist/server/uploads/...'` occurs because the uploads directory doesn't exist in the production build.

## Solutions Implemented

### 1. Automatic Directory Creation
- Modified multer configuration to create uploads directory if it doesn't exist
- Added startup check in `server/index.ts` to ensure uploads directory exists
- Added postbuild script to create directory during build process

### 2. Deployment Steps

#### Step 1: Build the Application
```bash
cd CommonServer
npm run build
# or
pnpm build
```

#### Step 2: Setup Uploads Directory (if needed)
```bash
npm run setup-uploads
# or manually:
mkdir -p dist/server/uploads
chmod 755 dist/server/uploads
```

#### Step 3: Deploy to EC2
```bash
# Copy your built application to EC2
scp -r dist/ user@your-ec2-ip:/path/to/your/app/

# Or if using git:
git pull origin main
npm run build
npm run setup-uploads
```

#### Step 4: Start the Application
```bash
# Using PM2
pm2 start dist/server/index.js --name "calmpath-backend"

# Or directly
node dist/server/index.js
```

### 3. Verification

After deployment, verify that:
1. The uploads directory exists: `/root/CalmPath-AI-Backend/dist/server/uploads/`
2. The directory has proper permissions (755)
3. The application can write to the directory

### 4. Troubleshooting

#### If uploads still fail:
1. **Run the debug script:**
   ```bash
   cd CommonServer
   npm run debug-uploads
   ```

2. **Test the uploads endpoint:**
   ```bash
   curl https://app.calmpath.ai/api/test-uploads
   ```

3. **Check directory permissions:**
   ```bash
   ls -la /root/CalmPath-AI-Backend/dist/server/
   ```

4. **Check if the directory exists:**
   ```bash
   ls -la /root/CalmPath-AI-Backend/dist/server/uploads/
   ```

5. **Create manually if needed:**
   ```bash
   mkdir -p /root/CalmPath-AI-Backend/dist/server/uploads
   chmod 755 /root/CalmPath-AI-Backend/dist/server/uploads
   ```

6. **Restart the application:**
   ```bash
   pm2 restart calmpath-backend
   ```

#### For delete operations:
1. **Check PM2 logs for detailed error information:**
   ```bash
   pm2 logs calmpath-backend --lines 50
   ```

2. **Test delete endpoint manually:**
   ```bash
   curl -X DELETE https://app.calmpath.ai/api/family/memoryPhotos/1755421861207
   ```

3. **Verify file exists before deletion:**
   ```bash
   ls -la /root/CalmPath-AI-Backend/dist/server/uploads/1755421861207-nail.jpg
   ```

#### Check PM2 logs:
```bash
pm2 logs calmpath-backend
```

### 5. Environment Variables

Ensure these environment variables are set in your EC2 instance:
- `DATABASE_URL`
- `NODE_ENV=production`
- Any other required environment variables

### 6. File Permissions

The uploads directory needs write permissions for the user running the Node.js process:
```bash
chown -R $USER:$USER /root/CalmPath-AI-Backend/dist/server/uploads
chmod 755 /root/CalmPath-AI-Backend/dist/server/uploads
```

## Changes Made

1. **routes.ts**: Added directory creation in multer configuration
2. **index.ts**: Added startup directory check
3. **package.json**: Added postbuild and setup-uploads scripts
4. **setup-uploads.js**: Created utility script for directory setup

These changes ensure the uploads directory exists and has proper permissions in both development and production environments.
