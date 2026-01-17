const fs = require('fs');
const path = require('path');

const envContent = `# Server Configuration
# HOST is hardcoded to 0.0.0.0 in code (required for Railway)
# PORT is provided by Railway automatically - don't set it here for production
# For local development, you can set PORT=2004 if needed
PORT=2004

# JWT Secret - CHANGE THIS IN PRODUCTION!
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345

# Frontend URL
FRONTEND_URL=http://192.168.29.151:2003

# Cloudinary Configuration (for cloud image storage)
# Get these from https://cloudinary.com/console
# ⚠️  IMPORTANT: Cloudinary provides free tier with 25GB storage
# Sign up at https://cloudinary.com/users/register/free
CLOUDINARY_CLOUD_NAME=your-cloud-name
CLOUDINARY_API_KEY=your-api-key
CLOUDINARY_API_SECRET=your-api-secret

# Image Encryption is disabled - all images are stored in Cloudinary without encryption

# Supabase Configuration (for resume file storage)
# Get these from https://supabase.com/dashboard
# ⚠️  IMPORTANT: 
# 1. Go to https://supabase.com and create a project (or use existing)
# 2. Go to Project Settings > API
# 3. Copy your Project URL (SUPABASE_URL)
# 4. Copy your Service Role Key (SUPABASE_SERVICE_ROLE_KEY) - Keep this secret!
# 5. Go to Storage and create a bucket named "resumes" (or use existing)
# 6. Make sure the bucket is public or configure proper RLS policies
SUPABASE_URL=https://nmlxuhbqbmtrcfvodzxm.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5tbHh1aGJxYm10cmNmdm9kenhtIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc2ODUzMzQzNSwiZXhwIjoyMDg0MTA5NDM1fQ.Colyt6ciXXPBZ1kJD-zqE-yHzvS9Z-N2k9Ye5_ks0dw
# Alternative: Use anon key if you prefer (less secure, but works for public buckets)
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im5tbHh1aGJxYm10cmNmdm9kenhtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njg1MzM0MzUsImV4cCI6MjA4NDEwOTQzNX0.ovfk1ZJUMTcR6f00T1HDRXNRRSiWpNAz4SWkNg_yUn4
# Dropbox Configuration (for resume file storage - legacy/fallback)
# Option 1: OAuth2 Authentication (Recommended)
# Get these from https://www.dropbox.com/developers/apps

# Option 2: Direct Access Token (Alternative - for server-to-server)
# If you prefer to use a direct access token instead of OAuth2:
# 1. Generate an access token from your Dropbox app settings
# 2. Paste it below (this will be used as fallback if no user tokens exist)
DROPBOX_ACCESS_TOKEN=
# Image Base URL (for CDN serving)
# Priority: IMAGE_BASE_URL > BASE_URL > default Railway URL
# IMAGE_BASE_URL= http://192.168.29.151:2004
# BASE_URL= http://192.168.29.151:2004

# PostgreSQL Database Configuration
# For Railway: Use DATABASE_URL (automatically provided by Railway)
# For local development: Use individual connection parameters below
DB_HOST=localhost
DB_PORT=8956
DB_NAME=acdc
DB_USER=postgres
DB_PASSWORD=acdc@it01


`;

const envPath = path.join(__dirname, '.env');

if (!fs.existsSync(envPath)) {
  fs.writeFileSync(envPath, envContent);
  console.log('✅ .env file created successfully!');
  console.log('📝 Configuration:');
  console.log('   Server:');
  console.log('   - HOST: 0.0.0.0 (hardcoded in code, required for Railway)');
  console.log('   - PORT: 2004 (for local dev, Railway provides PORT automatically)');
  console.log('   - JWT_SECRET: Set to default (⚠️  CHANGE in production!)');
  console.log('   - FRONTEND_URL: http://192.168.29.151:2003');
  console.log('');
  console.log('   Database (Local Development):');
  console.log('   - DB_HOST: localhost');
  console.log('   - DB_PORT: 5432');
  console.log('   - DB_NAME: backend');
  console.log('   - DB_USER: postgres');
  console.log('   - DB_PASSWORD: acdc@it01');
  console.log('');
  console.log('   ⚠️  Note: Railway automatically provides DATABASE_URL');
  console.log('   ⚠️  Note: Railway automatically provides PORT');
  console.log('   ⚠️  Note: HOST is hardcoded to 0.0.0.0 in code (required)');
} else {
  console.log('⚠️  .env file already exists. Skipping...');
  console.log('   If you want to recreate it, delete .env first.');
}

