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
# ⚠️  IMPORTANT: 
# 1. Go to https://www.dropbox.com/developers/apps
# 2. Create a new app (choose "Scoped access" and "Full Dropbox")
# 3. Get App Key and App Secret from the app settings
# 4. Add redirect URI: http://your-domain/api/dropbox/callback
# 5. Admin users can authenticate via /api/dropbox/auth endpoint
DROPBOX_APP_KEY=72obxasu0xv5109	
DROPBOX_APP_SECRET=fb9feuyhzpmbhol
DROPBOX_ACCESS_TOKEN=sl.u.AGODyOrOvurE-zOeMqU3vc_gyKMk35m0wCLilJoBe_3WLsHIZqGPooFD0pd_iBwDa08flmuWgXIGPqcB6N7tHGtb3WJfsoSuvQRXyXK1p4LFdf8dpK6GjLPVz1SIIkmX5hB6GQtxkiES2bsUP3KCkzHN_JbYNy2HSsfgBmhAOT7ezynZqObTsC2zB65mhKCpEcHH6mT6FSd3KxowCbNqALn72CSKwLAKfFHpf9NoGk7QD_HeP4f6sFYT292UpUiVGwGrA_rQzYynJ-Ij3o03c3zsIUiRA-OTkReUBkmd-I41XfzZmHZFjyAHptl44O3yuBXLIrivP7HLEWRovnipJBaRttc0brPMpq85hRHq_h806Ppca52dZerT6XTQCw19ZoU_HERnZeVumr2fBiuA2xmx9C1IJy-HyNaQ_p0FWSdIj2_1NqcdGzGcdJ2thFriKJNLocxt_39nO5JeB7asyJJljP-d94pOXOK_twDOGbTOocwZtQ7w13CqbMyMRZ5h8N_IDcfmrWg-FLZ8l-xAgS6GZ5N65ne8qGOCxu5xqcPaz41W8zQiFPIFJ9Zv7ODGmXBamkdtqsRJKLJt2VVpbJt_v2D86CdrFsVzkrRn6mm20R3-hT4d0ZuwUOEfGKwykGGop7yP1B_ugOs5_BTBuS3vh7nQfBGzBD2JKqyorQfGS0hqqdD3YfMzIVS0MN-0RPqMQsaXjWjOo0H4-zsW9YfWWtaxiGkKR5h7o5Pc6AXDDZWkPgLW4uEGi5blatu09BDLthznWbxs4x0OtTX9nQAmxR1u8317BU1UTpkFZsJx30ppSqgjBakzDqcL3886S2BScU9NRSW5fzyZxB8KaNliA9IKAWNIrFiVabF8tVdk9wpiL78FrZG8DIuraC8lik2qLwMhzCCCC82O3WT2gwf4EstOIk6j74LJHM3oBDdhAcky9C8WCoAssJHffi9X1tHUa_akK6tf__fjpp8EdDF8QzgQ3INrpUo1Tr1zC142r4W8CL1kQLAlnwxKwmahfCMoCe_hj2kheEwrqmLmsDviEj-lsKaxLzhd8G3A9NW7uR7re7ApkRCocU_XCEpHh0fOWPuSOoyTeXzPnShDOPSYdhTxayejXI4adGEBiWWFJEiFOcXOMSoDDDlBNBw5zsva7sNjtS7uUvmfx7fDIrIRSnIZ6P94KTiQT2n5JGTWBp_JIyFFpNs2jRg4UHhPFOWdixEWdmxg3g47cedsxbAiO7sgvAJlGoQF4ICliZVjS5SFuZMfe2pUuYz-u6srfysz5Fonnr6652oxwa21idtrwwNa0RlKtmxiObMuFQ3KrfK2ruMRJLOOcWzR2zwUa9101JJukfN7es-RDfGiRFFYPG3t8X6MgeSFRcj9KgX6F5Oc3YNfUhNQ1IK7-STTJU_EMQ_9KBHYV8KJpvToEvCC

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

