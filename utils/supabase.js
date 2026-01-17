const { createClient } = require('@supabase/supabase-js');
const path = require('path');

let supabaseClient = null;

/**
 * Initialize Supabase client
 */
function initializeSupabase() {
  if (supabaseClient) {
    return supabaseClient;
  }

  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

  if (!supabaseUrl || !supabaseKey) {
    console.warn('⚠️  Supabase not configured: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_ANON_KEY) are required');
    return null;
  }

  try {
    supabaseClient = createClient(supabaseUrl, supabaseKey, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });
    console.log('✅ Supabase client initialized successfully');
    return supabaseClient;
  } catch (error) {
    console.error('❌ Error initializing Supabase client:', error.message);
    return null;
  }
}

/**
 * Check if Supabase is configured
 */
function isSupabaseConfigured() {
  const supabaseUrl = process.env.SUPABASE_URL;
  const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
  return !!(supabaseUrl && supabaseKey);
}

/**
 * Upload file to Supabase Storage
 * @param {Buffer} fileBuffer - File buffer to upload
 * @param {string} bucketName - Supabase storage bucket name (default: 'resume')
 * @param {string} filePath - Path/filename in the bucket (e.g., 'resume/firstname_lastname.pdf')
 * @returns {Promise<{path: string, url: string}>} - Returns the path and public URL
 */
async function uploadToSupabase(fileBuffer, bucketName = 'resume', filePath) {
  if (!isSupabaseConfigured()) {
    throw new Error('Supabase is not configured. Please set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY environment variables.');
  }

  const client = initializeSupabase();
  if (!client) {
    throw new Error('Failed to initialize Supabase client');
  }

  // Validate file buffer
  if (!Buffer.isBuffer(fileBuffer)) {
    throw new Error('Invalid file buffer: expected Buffer object');
  }

  if (fileBuffer.length === 0) {
    throw new Error('File buffer is empty (0 bytes)');
  }

  try {
    console.log(`📤 Uploading to Supabase Storage: ${filePath} (${fileBuffer.length} bytes)`);

    // Upload file to Supabase Storage
    const { data, error } = await client.storage
      .from(bucketName)
      .upload(filePath, fileBuffer, {
        contentType: 'application/pdf',
        upsert: true // Overwrite if file exists
      });

    if (error) {
      console.error('❌ Supabase upload error:', error);
      throw new Error(`Supabase upload failed: ${error.message}`);
    }

    console.log('✅ File uploaded to Supabase Storage successfully');

    // Get public URL
    const { data: urlData } = client.storage
      .from(bucketName)
      .getPublicUrl(filePath);

    const publicUrl = urlData.publicUrl;

    console.log(`   Path: ${filePath}`);
    console.log(`   URL: ${publicUrl}`);

    return {
      path: filePath,
      url: publicUrl
    };
  } catch (error) {
    console.error('❌ Error uploading to Supabase:', error.message);
    throw error;
  }
}

/**
 * Delete file from Supabase Storage
 * @param {string} filePath - Path to file in Supabase Storage
 * @param {string} bucketName - Supabase storage bucket name (default: 'resume')
 * @returns {Promise<void>}
 */
async function deleteFromSupabase(filePath, bucketName = 'resume') {
  if (!isSupabaseConfigured()) {
    console.warn('⚠️  Supabase not configured, skipping deletion');
    return;
  }

  const client = initializeSupabase();
  if (!client) {
    console.warn('⚠️  Failed to initialize Supabase client, skipping deletion');
    return;
  }

  try {
    console.log(`🗑️  Deleting from Supabase Storage: ${filePath}`);

    const { error } = await client.storage
      .from(bucketName)
      .remove([filePath]);

    if (error) {
      console.error('❌ Error deleting from Supabase:', error.message);
      throw error;
    }

    console.log(`✅ File deleted from Supabase Storage: ${filePath}`);
  } catch (error) {
    console.error('❌ Error deleting from Supabase:', error.message);
    throw error;
  }
}

/**
 * Get public URL for a file in Supabase Storage
 * @param {string} filePath - Path to file in Supabase Storage
 * @param {string} bucketName - Supabase storage bucket name (default: 'resume')
 * @returns {string} - Public URL
 */
function getSupabaseUrl(filePath, bucketName = 'resume') {
  if (!isSupabaseConfigured()) {
    return null;
  }

  const client = initializeSupabase();
  if (!client) {
    return null;
  }

  const { data } = client.storage
    .from(bucketName)
    .getPublicUrl(filePath);

  return data.publicUrl;
}

/**
 * Download file from Supabase Storage
 * @param {string} filePath - Path to file in Supabase Storage
 * @param {string} bucketName - Supabase storage bucket name (default: 'resume')
 * @returns {Promise<Buffer>} - File buffer
 */
async function downloadFromSupabase(filePath, bucketName = 'resume') {
  if (!isSupabaseConfigured()) {
    throw new Error('Supabase is not configured');
  }

  const client = initializeSupabase();
  if (!client) {
    throw new Error('Failed to initialize Supabase client');
  }

  try {
    const { data, error } = await client.storage
      .from(bucketName)
      .download(filePath);

    if (error) {
      throw new Error(`Failed to download file: ${error.message}`);
    }

    // Convert Blob to Buffer
    const arrayBuffer = await data.arrayBuffer();
    return Buffer.from(arrayBuffer);
  } catch (error) {
    console.error('❌ Error downloading from Supabase:', error.message);
    throw error;
  }
}

module.exports = {
  initializeSupabase,
  isSupabaseConfigured,
  uploadToSupabase,
  deleteFromSupabase,
  getSupabaseUrl,
  downloadFromSupabase
};
