const { Dropbox } = require('dropbox');

/**
 * Dropbox File Upload Utility
 * 
 * Features:
 * - Upload files directly to Dropbox cloud storage
 * - Returns shared links (URLs) for file access
 * - Works across all devices (no local storage needed)
 * - Store file paths in database
 */

// Initialize Dropbox client
let dropboxClient = null;
let db = null; // Database instance (will be set by setDatabase)

// Set database instance for token retrieval
function setDatabase(database) {
  db = database;
}

// Initialize Dropbox client with token (from env or database)
async function initializeDropbox(userId = null) {
  // If we have a user ID, try to get token from database
  if (userId && db) {
    try {
      const getToken = db.prepare('SELECT * FROM dropbox_tokens WHERE user_id = ?');
      const tokenData = await getToken.get(userId);
      
      if (tokenData && tokenData.access_token) {
        // Check if token is expired
        if (tokenData.expires_at && new Date(tokenData.expires_at) < new Date()) {
          // Token expired, try to refresh
          if (tokenData.refresh_token) {
            try {
              const refreshedToken = await refreshDropboxToken(tokenData.refresh_token);
              // Update token in database
              const updateToken = db.prepare(`
                UPDATE dropbox_tokens 
                SET access_token = ?, expires_at = ?, updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
              `);
              await updateToken.run(refreshedToken.access_token, refreshedToken.expires_at, userId);
              return new Dropbox({ accessToken: refreshedToken.access_token });
            } catch (refreshError) {
              console.error('Failed to refresh Dropbox token:', refreshError.message);
              throw new Error('Dropbox token expired and refresh failed. Please re-authenticate.');
            }
          } else {
            throw new Error('Dropbox token expired and no refresh token available. Please re-authenticate.');
          }
        }
        
        // Return client with database token
        return new Dropbox({ accessToken: tokenData.access_token });
      }
    } catch (error) {
      console.error('Error getting Dropbox token from database:', error.message);
    }
  }
  
  // Fallback to environment variable
  if (!process.env.DROPBOX_ACCESS_TOKEN) {
    throw new Error('DROPBOX_ACCESS_TOKEN is not set in environment variables and no user token found');
  }
  
  // Use environment token (create singleton for env token)
  if (!dropboxClient) {
    dropboxClient = new Dropbox({
      accessToken: process.env.DROPBOX_ACCESS_TOKEN
    });
  }
  return dropboxClient;
}

// Refresh Dropbox access token
async function refreshDropboxToken(refreshToken) {
  if (!process.env.DROPBOX_APP_KEY || !process.env.DROPBOX_APP_SECRET) {
    throw new Error('DROPBOX_APP_KEY and DROPBOX_APP_SECRET are required for token refresh');
  }
  
  const response = await fetch('https://api.dropbox.com/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: process.env.DROPBOX_APP_KEY,
      client_secret: process.env.DROPBOX_APP_SECRET,
    }),
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(`Token refresh failed: ${error.error_description || error.error}`);
  }
  
  const data = await response.json();
  const expiresAt = new Date();
  expiresAt.setSeconds(expiresAt.getSeconds() + (data.expires_in || 14400)); // Default 4 hours
  
  return {
    access_token: data.access_token,
    expires_at: expiresAt.toISOString(),
  };
}

// Get Dropbox client for a specific user (for use in routes)
async function getDropboxClient(userId = null) {
  return await initializeDropbox(userId);
}

/**
 * Check if Dropbox is configured (env token or database tokens)
 * @returns {boolean}
 */
function isDropboxConfigured() {
  // Check environment variable
  if (process.env.DROPBOX_ACCESS_TOKEN) {
    return true;
  }
  
  // Check if we have app credentials for OAuth
  if (process.env.DROPBOX_APP_KEY && process.env.DROPBOX_APP_SECRET) {
    return true;
  }
  
  return false;
}

/**
 * Upload file buffer to Dropbox
 * @param {Buffer} fileBuffer - File buffer
 * @param {string} folder - Folder path in Dropbox (e.g., '/resumes')
 * @param {string} filename - Filename for the uploaded file
 * @returns {Promise<{path: string, url: string, name: string}>}
 */
async function uploadToDropbox(fileBuffer, folder = '/resumes', filename = null, userId = null) {
  if (!isDropboxConfigured() && !userId) {
    throw new Error('Dropbox is not configured. Please set DROPBOX_ACCESS_TOKEN in .env or authenticate with Dropbox');
  }

  const dbx = await initializeDropbox(userId);
  
  // Generate unique filename if not provided
  if (!filename) {
    const timestamp = Date.now();
    const random = Math.round(Math.random() * 1E9);
    filename = `file-${timestamp}-${random}.pdf`;
  }

  // Ensure folder path starts with / and doesn't end with /
  let folderPath = folder.startsWith('/') ? folder : `/${folder}`;
  folderPath = folderPath.replace(/\/+$/, ''); // Remove trailing slashes
  
  // Full path in Dropbox
  const dropboxPath = `${folderPath}/${filename}`;

  try {
    // Validate and convert fileBuffer
    if (!fileBuffer) {
      throw new Error('File buffer is null or undefined');
    }

    // Ensure fileBuffer is a Buffer
    let buffer;
    if (Buffer.isBuffer(fileBuffer)) {
      buffer = fileBuffer;
    } else if (fileBuffer instanceof Uint8Array) {
      buffer = Buffer.from(fileBuffer);
    } else if (typeof fileBuffer === 'string') {
      // If it's a base64 string, decode it
      buffer = Buffer.from(fileBuffer, 'base64');
    } else if (fileBuffer.buffer && fileBuffer.buffer instanceof ArrayBuffer) {
      // Handle TypedArray
      buffer = Buffer.from(fileBuffer.buffer);
    } else {
      throw new Error(`Invalid file buffer type: ${typeof fileBuffer}`);
    }

    // Validate buffer has content
    if (buffer.length === 0) {
      throw new Error('File buffer is empty (0 bytes)');
    }

    console.log(`📤 Uploading to Dropbox: ${dropboxPath} (${buffer.length} bytes)`);

    // Upload file to Dropbox
    const result = await dbx.filesUpload({
      path: dropboxPath,
      contents: buffer,
      mode: { '.tag': 'overwrite' }, // Overwrite if exists
      autorename: false,
      mute: false
    });

    console.log(`✅ Uploaded to Dropbox: ${result.path_display}`);

    // Create a shared link for the file
    let sharedLink;
    try {
      const linkResult = await dbx.sharingCreateSharedLinkWithSettings({
        path: result.path_lower,
        settings: {
          requested_visibility: { '.tag': 'public' }
        }
      });
      sharedLink = linkResult.url;
      console.log(`🔗 Created shared link: ${sharedLink}`);
    } catch (linkError) {
      console.log(`⚠️  Link creation error: ${linkError.message}`);
      
      // If link already exists, get the existing link
      if (linkError.error?.error?.['.tag'] === 'shared_link_already_exists') {
        try {
          const existingLinks = await dbx.sharingListSharedLinks({
            path: result.path_lower,
            direct_only: true
          });
          if (existingLinks.links && existingLinks.links.length > 0) {
            sharedLink = existingLinks.links[0].url;
            console.log(`🔗 Using existing shared link: ${sharedLink}`);
          }
        } catch (getLinkError) {
          console.warn('⚠️  Could not get existing shared link:', getLinkError.message);
        }
      }
      
      // If still no link, create a temporary link
      if (!sharedLink) {
        try {
          const directLink = await dbx.filesGetTemporaryLink({
            path: result.path_lower
          });
          sharedLink = directLink.link;
          console.log(`🔗 Created temporary link: ${sharedLink}`);
        } catch (tempLinkError) {
          console.warn('⚠️  Could not create temporary link:', tempLinkError.message);
          // Fallback: return the path (will need to generate link later)
          sharedLink = result.path_display;
        }
      }
    }

    // Convert shared link to direct download link if needed
    // Handle both /s/ (old format) and /scl/fi/ (new format) URLs
    if (sharedLink && (sharedLink.includes('dropbox.com/s/') || sharedLink.includes('dropbox.com/scl/fi/'))) {
      // Replace ?dl=0 with ?dl=1 for direct download
      sharedLink = sharedLink.replace('?dl=0', '?dl=1');
      // Add ?dl=1 if no query parameter exists
      if (!sharedLink.includes('?dl=')) {
        // Check if URL already has query parameters
        const urlParts = sharedLink.split('?');
        if (urlParts.length > 1) {
          // Remove existing query params and add ?dl=1
          sharedLink = urlParts[0] + '?dl=1';
        } else {
          sharedLink += '?dl=1';
        }
      }
    }

    return {
      path: result.path_display, // Full path in Dropbox
      path_lower: result.path_lower, // Lowercase path
      url: sharedLink, // Direct download URL
      name: result.name, // Filename
      size: result.size, // File size in bytes
      id: result.id // Dropbox file ID
    };
  } catch (error) {
    // Log detailed error information
    console.error('❌ Dropbox upload failed:');
    console.error('  Error message:', error.message);
    console.error('  Error status:', error.status);
    
    if (error.error) {
      console.error('  Error details:', JSON.stringify(error.error, null, 2));
    }
    
    // Provide helpful error messages
    if (error.status === 400) {
      const errorMsg = error.error?.error_summary || error.message;
      throw new Error(`Dropbox upload failed (Bad Request): ${errorMsg}. Check file path and access token permissions.`);
    } else if (error.status === 401) {
      throw new Error('Dropbox authentication failed. Check your DROPBOX_ACCESS_TOKEN.');
    } else if (error.status === 409) {
      throw new Error(`Dropbox conflict error: ${error.error?.error_summary || error.message}`);
    } else if (error.status === 429) {
      throw new Error('Dropbox rate limit exceeded. Please try again later.');
    }
    
    throw new Error(`Dropbox upload failed: ${error.message}`);
  }
}

/**
 * Delete file from Dropbox
 * @param {string} dropboxPath - Dropbox path (e.g., '/resumes/filename.pdf')
 * @returns {Promise<void>}
 */
async function deleteFromDropbox(dropboxPath) {
  if (!isDropboxConfigured()) {
    throw new Error('Dropbox is not configured');
  }

  const dbx = initializeDropbox();

  try {
    // Ensure path starts with /
    const path = dropboxPath.startsWith('/') ? dropboxPath : `/${dropboxPath}`;
    
    await dbx.filesDeleteV2({
      path: path
    });
    
    console.log(`✅ Deleted from Dropbox: ${path}`);
  } catch (error) {
    if (error.error?.error?.['.tag'] === 'path_lookup' && 
        error.error?.error?.path_lookup?.['.tag'] === 'not_found') {
      console.log(`⚠️  File not found in Dropbox: ${dropboxPath}`);
    } else {
      console.error(`❌ Error deleting from Dropbox: ${error.message}`);
      throw error;
    }
  }
}

/**
 * Get shared link for a file (create if doesn't exist)
 * @param {string} dropboxPath - Dropbox path
 * @returns {Promise<string>} - Shared link URL
 */
async function getSharedLink(dropboxPath) {
  if (!isDropboxConfigured()) {
    throw new Error('Dropbox is not configured');
  }

  const dbx = initializeDropbox();
  
  // Ensure path starts with /
  const path = dropboxPath.startsWith('/') ? dropboxPath : `/${dropboxPath}`;

  // Validate that path is a file, not a folder (should have a file extension or filename)
  if (path === '/resumes' || path.endsWith('/') || !path.includes('.')) {
    throw new Error(`Invalid path: ${path} appears to be a folder, not a file`);
  }

  try {
    // Try to get existing links first
    const existingLinks = await dbx.sharingListSharedLinks({
      path: path,
      direct_only: true
    });
    
    if (existingLinks.links && existingLinks.links.length > 0) {
      let url = existingLinks.links[0].url;
      // Validate it's a file URL, not a folder URL
      if (url.includes('/home/')) {
        throw new Error(`Got folder URL instead of file URL: ${url}`);
      }
      // Convert to direct download link for both /s/ and /scl/fi/ formats
      if (url.includes('dropbox.com/s/') || url.includes('dropbox.com/scl/fi/')) {
        url = url.replace('?dl=0', '?dl=1');
        // Remove other query parameters and add ?dl=1 if not present
        if (!url.includes('?dl=')) {
          // Check if URL already has query parameters
          const urlParts = url.split('?');
          if (urlParts.length > 1) {
            url = urlParts[0] + '?dl=1';
          } else {
            url += '?dl=1';
          }
        }
      }
      return url;
    }
    
    // Create new link if none exists
    const linkResult = await dbx.sharingCreateSharedLinkWithSettings({
      path: path,
      settings: {
        requested_visibility: { '.tag': 'public' }
      }
    });
    
    let url = linkResult.url;
    // Validate it's a file URL, not a folder URL
    if (url.includes('/home/')) {
      throw new Error(`Created folder URL instead of file URL: ${url}`);
    }
    // Convert to direct download link for both /s/ and /scl/fi/ formats
    if (url.includes('dropbox.com/s/') || url.includes('dropbox.com/scl/fi/')) {
      url = url.replace('?dl=0', '?dl=1');
      // Remove other query parameters and add ?dl=1 if not present
      if (!url.includes('?dl=')) {
        // Check if URL already has query parameters
        const urlParts = url.split('?');
        if (urlParts.length > 1) {
          url = urlParts[0] + '?dl=1';
        } else {
          url += '?dl=1';
        }
      }
    }
    return url;
  } catch (error) {
    console.error('Error getting/creating shared link:', error.message);
    
    // Fallback: try temporary link
    try {
      const tempLink = await dbx.filesGetTemporaryLink({
        path: path
      });
      return tempLink.link;
    } catch (tempError) {
      console.error('Error getting temporary link:', tempError.message);
      throw new Error(`Could not get shared link for ${path}: ${error.message}`);
    }
  }
}

module.exports = {
  uploadToDropbox,
  deleteFromDropbox,
  getSharedLink,
  isDropboxConfigured,
  getDropboxClient,
  setDatabase,
  refreshDropboxToken
};