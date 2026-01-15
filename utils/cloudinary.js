const cloudinary = require('cloudinary').v2;
const stream = require('stream');

/**
 * Cloudinary Image Upload Utility
 * 
 * Features:
 * - Upload images directly to Cloudinary cloud storage
 * - Returns secure URLs (CDN)
 * - Works across all devices (no local storage needed)
 * - Automatic image optimization
 */

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/**
 * Check if Cloudinary is configured
 * @returns {boolean}
 */
function isCloudinaryConfigured() {
  return !!(
    process.env.CLOUDINARY_CLOUD_NAME &&
    process.env.CLOUDINARY_API_KEY &&
    process.env.CLOUDINARY_API_SECRET
  );
}

/**
 * Upload image buffer to Cloudinary
 * @param {Buffer} fileBuffer - Image file buffer
 * @param {string} folder - Optional folder name in Cloudinary
 * @param {string} publicId - Optional public ID (filename)
 * @returns {Promise<{url: string, secure_url: string, public_id: string}>}
 */
async function uploadToCloudinary(fileBuffer, folder = 'acdc-images', publicId = null) {
  return new Promise((resolve, reject) => {
    // Convert buffer to stream
    const uploadStream = cloudinary.uploader.upload_stream(
      {
        folder: folder,
        public_id: publicId,
        resource_type: 'auto', // Auto-detect image or video
        overwrite: false,
        unique_filename: true,
        use_filename: true,
        // Optimize images automatically
        transformation: [
          { quality: 'auto' },
          { fetch_format: 'auto' }
        ]
      },
      (error, result) => {
        if (error) {
          console.error('❌ Cloudinary upload error:', error.message);
          reject(error);
        } else {
          console.log(`✅ Uploaded to Cloudinary: ${result.public_id}`);
          resolve({
            url: result.url,
            secure_url: result.secure_url,
            public_id: result.public_id,
            width: result.width,
            height: result.height,
            format: result.format,
            bytes: result.bytes
          });
        }
      }
    );

    // Create readable stream from buffer
    const bufferStream = new stream.Readable();
    bufferStream.push(fileBuffer);
    bufferStream.push(null);
    
    // Pipe buffer to upload stream
    bufferStream.pipe(uploadStream);
  });
}

/**
 * Delete file from Cloudinary
 * @param {string} publicId - Cloudinary public ID (can include folder path)
 * @returns {Promise<void>}
 */
async function deleteFromCloudinary(publicId) {
  if (!isCloudinaryConfigured()) {
    throw new Error('Cloudinary is not configured');
  }

  try {
    // Extract public_id from URL if full URL is provided
    let actualPublicId = publicId;
    if (publicId.includes('cloudinary.com')) {
      // Extract public_id from URL
      // Format: https://res.cloudinary.com/{cloud_name}/image/upload/{folder}/{public_id}.{ext}
      const match = publicId.match(/\/upload\/(.+?)(?:\.[^.]+)?$/);
      if (match) {
        actualPublicId = match[1];
        // Remove file extension if present
        actualPublicId = actualPublicId.replace(/\.[^.]+$/, '');
      }
    }

    const result = await cloudinary.uploader.destroy(actualPublicId);
    if (result.result === 'ok') {
      console.log(`✅ Deleted from Cloudinary: ${actualPublicId}`);
    } else if (result.result === 'not found') {
      console.log(`⚠️  File not found in Cloudinary: ${actualPublicId}`);
    } else {
      console.log(`⚠️  Cloudinary deletion result: ${result.result} for ${actualPublicId}`);
    }
  } catch (error) {
    console.error(`❌ Error deleting from Cloudinary: ${error.message}`);
    throw error;
  }
}

module.exports = {
  uploadToCloudinary,
  deleteFromCloudinary,
  isCloudinaryConfigured
};

