require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { uploadToCloudinary, isCloudinaryConfigured, deleteFromCloudinary } = require('./utils/cloudinary');
const { uploadToSupabase, isSupabaseConfigured, deleteFromSupabase, getSupabaseUrl } = require('./utils/supabase');
// Load database module - wrap in try-catch to prevent crashes on startup
let db;
try {
  db = require('./database');
} catch (error) {
  console.error('Error loading database module:', error);
  // Create a mock db object to prevent crashes - will fail gracefully in routes
  db = {
    query: async () => { throw new Error('Database not initialized'); },
    get: async () => { throw new Error('Database not initialized'); },
    all: async () => { throw new Error('Database not initialized'); },
    run: async () => { throw new Error('Database not initialized'); },
    prepare: () => ({
      get: async () => { throw new Error('Database not initialized'); },
      all: async () => { throw new Error('Database not initialized'); },
      run: async () => { throw new Error('Database not initialized'); }
    })
  };
}





// Ensure uploads directory exists
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Configure multer - use memory storage for Cloudinary, disk storage as fallback
const useCloudinary = isCloudinaryConfigured();

let storage;
if (useCloudinary) {
  // Memory storage for Cloudinary uploads (files stay in memory, then upload to cloud)
  storage = multer.memoryStorage();
  console.log('☁️  Cloudinary configured - images will be uploaded to cloud storage');
} else {
  // Disk storage for local file storage (fallback)
  storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, uploadsDir);
    },
    filename: function (req, file, cb) {
      // Generate unique filename: timestamp-random-originalname
      const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
      const ext = path.extname(file.originalname);
      const name = path.basename(file.originalname, ext).replace(/[^a-zA-Z0-9]/g, '_');
      cb(null, `${name}-${uniqueSuffix}${ext}`);
    }
  });
  console.log('📁 Using local file storage (Cloudinary not configured)');
}

const upload = multer({
  storage: storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// Helper function to convert file buffer to Base64
const fileToBase64 = (file) => {
  if (!file) return null;
  const base64 = file.buffer.toString('base64');
  const mimeType = file.mimetype || 'image/jpeg';
  return `data:${mimeType};base64,${base64}`;
};

// Helper function to handle file upload or URL - uploads to Cloudinary if configured
const handleFileOrUrl = async (req, folder = 'acdc-images') => {
  // Check if file was uploaded
  if (req.file) {
    if (useCloudinary) {
      // Upload to Cloudinary and return URL
      try {
        const result = await uploadToCloudinary(req.file.buffer, folder);
        console.log(`✅ Uploaded to Cloudinary: ${result.secure_url}`);
        return result.secure_url; // Return Cloudinary secure URL
      } catch (error) {
        console.error('❌ Cloudinary upload failed:', error.message);
        throw error;
      }
    } else {
      // File is saved to disk by multer, return filename
      return req.file.filename;
    }
  }
  // Check for URL, Base64, or existing filename in request body
  const { fileUrl, image, icon, logo } = req.body || {};
  const url = fileUrl || image || icon || logo;
  if (url) {
    // Ensure it's a string (not an object)
    if (typeof url === 'string') {
      // If it's base64 data, keep for backward compatibility
      // Otherwise return as is (URL or filename)
      return url;
    } else if (url !== null && url !== undefined) {
      // Try to convert to string if it's not null/undefined
      return String(url);
    }
  }
  return null;
};

// Helper function to handle multiple file uploads or URLs - uploads to Cloudinary if configured
const handleFilesOrUrls = async (req, fieldNames, folder = 'acdc-images') => {
  const result = {};

  for (const fieldName of fieldNames) {
    // Check if file was uploaded for this field
    if (req.files && req.files[fieldName] && req.files[fieldName][0]) {
      const file = req.files[fieldName][0];

      if (useCloudinary) {
        // Upload to Cloudinary and return URL
        try {
          const cloudinaryResult = await uploadToCloudinary(file.buffer, folder);
          result[fieldName] = cloudinaryResult.secure_url;
          console.log(`✅ Uploaded ${fieldName} to Cloudinary: ${cloudinaryResult.secure_url}`);
        } catch (error) {
          console.error(`❌ Cloudinary upload failed for ${fieldName}:`, error.message);
          throw error;
        }
      } else {
        // File is saved to disk by multer, return filename
        result[fieldName] = file.filename;
      }
    } else if (req.body && req.body[fieldName]) {
      // Check for URL, Base64, or existing filename in request body
      const value = req.body[fieldName];
      // If it's base64 data, keep for backward compatibility
      // But new uploads will be saved as files
      if (value.startsWith('data:') || (value.length > 1000 && !value.includes('.'))) {
        // It's base64 data - keep as is for backward compatibility
        result[fieldName] = value;
      } else {
        // It's a URL or filename - use as is
        result[fieldName] = value;
      }
    }
  }

  return result;
};

// Helper function to delete file from disk or Cloudinary
// Handles both local files and Cloudinary URLs
// Returns a promise but never throws - always handles errors gracefully
const deleteFileIfExists = async (filename, cloudinaryPublicId = null) => {
  if (!filename) return;

  try {
    // Skip base64 data
    if (filename.startsWith('data:')) {
      return;
    }

    // Handle Cloudinary URLs
    if (filename.includes('cloudinary.com')) {
      if (useCloudinary) {
        try {
          await deleteFromCloudinary(cloudinaryPublicId || filename);
          console.log(`✅ Deleted from Cloudinary: ${cloudinaryPublicId || filename}`);
        } catch (error) {
          // If file doesn't exist or deletion fails, log but don't throw
          console.log(`⚠️  Could not delete Cloudinary file: ${cloudinaryPublicId || filename} - ${error.message}`);
        }
      }
      return;
    }

    // Handle other HTTP URLs (external URLs, don't delete)
    if (filename.startsWith('http://') || filename.startsWith('https://')) {
      return;
    }

    // Handle local files (filename only, not URL)
    if (filename.includes('.')) {
      const filePath = path.join(__dirname, 'uploads', filename);
      if (fs.existsSync(filePath)) {
        fs.unlinkSync(filePath);
        console.log(`✅ Deleted local file: ${filename}`);
      }
    }
  } catch (error) {
    // Never throw - always handle errors gracefully
    console.error(`❌ Error deleting file ${filename?.substring(0, 50) || 'unknown'}:`, error.message);
  }
};


// Helper function to get Indian Standard Time (IST) - UTC+5:30
const getISTTimestamp = () => {
  const now = new Date();
  // Convert to IST (UTC+5:30)
  const istOffset = 5.5 * 60 * 60 * 1000; // 5.5 hours in milliseconds
  const istTime = new Date(now.getTime() + istOffset);
  // Format as SQLite/PostgreSQL compatible timestamp string
  return istTime.toISOString().replace('T', ' ').substring(0, 19);
};

// Helper function to safely add a column to a table (handles PostgreSQL and SQLite)
const safeAddColumn = async (tableName, columnName, columnType) => {
  try {
    // Try to add the column - if it already exists, PostgreSQL/SQLite will throw an error
    await db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnType}`);
    console.log(`Added ${columnName} column to ${tableName} table`);
  } catch (error) {
    // Check if error is "column already exists"
    // PostgreSQL error code: 42701 = duplicate_column
    // SQLite error message contains "duplicate column name"
    // The error might be nested in error.error for PostgreSQL
    const errorObj = error.error || error;
    const errorCode = errorObj.code || error.code;
    const errorMessage = errorObj.message || error.message || String(error);

    // Check for PostgreSQL error code 42701 or error messages indicating duplicate column
    if (errorCode === '42701' ||
      (errorMessage && (
        errorMessage.toLowerCase().includes('already exists') ||
        errorMessage.toLowerCase().includes('duplicate column') ||
        errorMessage.toLowerCase().includes('duplicate_column') ||
        (errorMessage.toLowerCase().includes('column') && errorMessage.toLowerCase().includes('already exists'))
      ))) {
      // Column already exists, this is fine - ignore the error silently
      return;
    }
    // For other errors, log but don't throw (to prevent breaking the request)
    console.error(`Error adding column ${columnName} to ${tableName}:`, {
      code: errorCode,
      message: errorMessage,
      fullError: error
    });
  }
};

// Helper function to get file URL - returns URLs for filenames, keeps base64 for backward compatibility
// Accepts optional req parameter to get dynamic BASE_URL from request
const getFileUrl = (data, req = null) => {
  if (!data) return null;

  // If it's already a full URL (including Cloudinary URLs, Dropbox URLs), return as is
  if (data.startsWith('http://') || data.startsWith('https://')) {
    return data;
  }

  // If it's already a data URI (Base64), return as is (for backward compatibility with old data)
  if (data.startsWith('data:')) {
    return data;
  }

  // Dropbox paths start with / - we'll handle them in specific endpoints that need URLs
  // For now, return the path as-is (will be handled in resume endpoints)

  // If it's Base64 without data URI prefix, add it (for backward compatibility)
  if (data.length > 100 && !data.includes(' ') && !data.includes('\n') && !data.includes('/') && !data.includes('\\') && !data.includes('.')) {
    // Likely Base64 string, add default image MIME type
    return `data:image/jpeg;base64,${data}`;
  }

  // Filename - return URL to file serving endpoint
  if (data.includes('.') && (data.endsWith('.jpg') || data.endsWith('.jpeg') || data.endsWith('.png') || data.endsWith('.gif') || data.endsWith('.webp') || data.endsWith('.svg'))) {
    // Use dynamic BASE_URL from request if available, otherwise use configured BASE_URL
    let baseUrl = BASE_URL;
    if (req) {
      // Get BASE_URL from request for better cross-device compatibility
      const protocol = req.protocol || 'https';
      const host = req.get('host') || req.hostname;
      if (host) {
        baseUrl = `${protocol}://${host}`;
      }
    }
    // Return URL to the file serving endpoint
    return `${baseUrl}/api/files/${encodeURIComponent(data)}`;
  }

  // Unknown format - return null to prevent 404 errors
  return null;
};

const app = express();
const http = require('http');
const server = http.createServer(app);
const { Server } = require('socket.io');
// Railway Configuration - REQUIRED
// Use PORT provided in environment or default to 2004 (for local development)
const port = process.env.PORT || 2004;
// Host must be 0.0.0.0 for Railway to connect (all network interfaces)
const host = '0.0.0.0';
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://192.168.29.151:2003';

// Initialize Socket.IO
const io = new Server(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production'
      ? FRONTEND_URL
      : '*', // Allow all origins in development
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Socket.IO connection handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Helper function to emit updates to all clients
const emitUpdate = (event, data) => {
  io.emit(event, data);
};

// Base URL for constructing absolute URLs (used internally)
// Images are stored in /uploads folder and served via /api/files/:filename
// Priority: IMAGE_BASE_URL env var > BASE_URL env var > default Railway URL
// For disk hosting, set IMAGE_BASE_URL in .env file to your domain/IP
const BASE_URL = process.env.IMAGE_BASE_URL || process.env.BASE_URL || 'https://backendacdc-production.up.railway.app';

// Log Cloudinary and storage configuration on startup
console.log('='.repeat(60));
if (useCloudinary) {
  console.log('☁️  Cloudinary: CONFIGURED ✅');
  console.log('   Images will be uploaded to cloud storage');
  console.log('   Images accessible from any device via Cloudinary CDN');
} else {
  console.log('⚠️  Cloudinary: NOT CONFIGURED');
  console.log('   Using local file storage (files may not be accessible from other devices)');
  console.log('   To enable Cloudinary, add CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, and CLOUDINARY_API_SECRET to .env');
  console.log('   Sign up at: https://cloudinary.com/users/register/free');
}
console.log('📸 Image Base URL:', BASE_URL);
console.log('📁 Uploads directory:', path.join(__dirname, 'uploads'));
console.log('='.repeat(60));

// Middleware - Allow CORS from frontend URL or any origin in development
app.use(cors({
  origin: process.env.NODE_ENV === 'production'
    ? FRONTEND_URL
    : true, // Allow all origins in development for easy access from any device
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Middleware to ensure req.body exists (fallback for edge cases)
app.use((req, res, next) => {
  if (!req.body && (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH')) {
    req.body = {};
  }
  next();
});

// File storage - URLs are stored directly in database

// Routes

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Access token required'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
};

// Admin only middleware
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({
      success: false,
      message: 'Admin access required'
    });
  }
  next();
};

// Root route
app.get('/', (req, res) => {
  res.json({
    status: 'OK',
    message: 'Backend API is running',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      api: '/api'
    }
  });
});


// Health check - should work even if database is not connected
app.get('/api/health', async (req, res) => {
  try {
    // Try to ping the database
    await db.query('SELECT 1');
    res.json({
      status: 'OK',
      message: 'Server is running',
      database: 'connected',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    // Server is running but database might not be connected
    res.status(503).json({
      status: 'PARTIAL',
      message: 'Server is running but database connection failed',
      database: 'disconnected',
      timestamp: new Date().toISOString(),
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// File serving endpoint - serves images directly without encryption
app.get('/api/files/:filename', async (req, res) => {
  try {
    const filename = decodeURIComponent(req.params.filename);

    // Security: prevent directory traversal
    if (filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      console.error('Invalid filename detected:', filename);
      return res.status(400).json({ success: false, message: 'Invalid filename' });
    }

    const filePath = path.join(__dirname, 'uploads', filename);

    // Check if file exists
    if (!fs.existsSync(filePath)) {
      console.error('File not found:', filePath);
      return res.status(404).json({ success: false, message: 'File not found', filename: filename });
    }

    // Set appropriate headers
    const ext = path.extname(filename).toLowerCase();
    const mimeTypes = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.webp': 'image/webp',
      '.svg': 'image/svg+xml',
      '.ico': 'image/x-icon',
      '.mp4': 'video/mp4',
      '.webm': 'video/webm',
      '.pdf': 'application/pdf'
    };

    const mimeType = mimeTypes[ext] || 'application/octet-stream';

    // Set CORS headers to allow images to be loaded from frontend/CDN
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET');
    res.setHeader('Content-Type', mimeType);
    res.setHeader('Cache-Control', 'public, max-age=31536000'); // Cache for 1 year (CDN-friendly)

    // Serve file directly
    const fileStream = fs.createReadStream(filePath);
    fileStream.on('error', (error) => {
      console.error('Error streaming file:', error);
      if (!res.headersSent) {
        res.status(500).json({ success: false, message: 'Error serving file' });
      }
    });
    fileStream.pipe(res);
  } catch (error) {
    console.error('Error serving file:', error);
    res.status(500).json({ success: false, message: 'Error serving file', error: error.message });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find user by email or username
    const getUser = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?');
    const user = await getUser.get(email, email);

    if (!user) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Check if password is hashed (bcrypt hashes start with $2a$, $2b$, or $2y$)
    const isPasswordHashed = user.password && user.password.startsWith('$2');

    let isPasswordValid = false;

    if (isPasswordHashed) {
      // Password is hashed, use bcrypt to compare
      isPasswordValid = bcrypt.compareSync(password, user.password);
    } else {
      // Password is plain text, compare directly
      isPasswordValid = password === user.password;

      // If password matches and it's plain text, hash it and update the database
      if (isPasswordValid) {
        const hashedPassword = bcrypt.hashSync(password, 10);
        const updatePassword = db.prepare('UPDATE users SET password = ? WHERE id = ?');
        await updatePassword.run(hashedPassword, user.id);
        console.log(`Password hashed and updated for user: ${user.email}`);
      }
    }

    if (!isPasswordValid) {
      return res.status(401).json({
        success: false,
        message: 'Invalid email or password'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Return success response
    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Register endpoint (optional, for creating new users)
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password, role = 'admin' } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Username, email, and password are required'
      });
    }

    // Check if user already exists
    const checkUser = db.prepare('SELECT * FROM users WHERE email = ? OR username = ?');
    const existingUser = await checkUser.get(email, username);

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: 'User with this email or username already exists'
      });
    }

    // Hash password
    const hashedPassword = bcrypt.hashSync(password, 10);

    // Insert new user
    const insertUser = db.prepare(`
      INSERT INTO users (username, email, password, role)
      VALUES (?, ?, ?, ?)
    `);

    const result = await insertUser.run(username, email, hashedPassword, role);

    res.json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: result.lastInsertRowid,
        username,
        email,
        role
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Verify token endpoint (for protected routes)
app.get('/api/verify', (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'No token provided'
      });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({
      success: true,
      user: decoded
    });
  } catch (error) {
    res.status(401).json({
      success: false,
      message: 'Invalid or expired token'
    });
  }
});

// Get all users (admin only)
app.get('/api/users', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const getUsers = db.prepare('SELECT id, username, email, role, created_at FROM users');
    const users = await getUsers.all();
    res.json({
      success: true,
      users
    });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get welcome content (public) - Optimized for fast response
app.get('/api/content/welcome', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('welcome');

    // Get all background images - handle case where table doesn't exist
    let images = [];
    try {
      const getImages = db.prepare('SELECT * FROM background_images WHERE page_key = ? ORDER BY display_order ASC, created_at ASC');
      images = await getImages.all('welcome');
    } catch (error) {
      // Table doesn't exist yet, return empty array
      console.log('Background images table not found, returning empty array');
      images = [];
    }

    // Filter out duplicates by ID (in case of any database issues)
    const uniqueImages = images.filter((img, index, self) =>
      index === self.findIndex(i => i.id === img.id)
    );

    // Optimize: Only process URLs if data exists, avoid unnecessary function calls
    const backgroundImages = uniqueImages.map(img => {
      const result = {
        id: img.id,
        url: null,
        filename: img.image_filename,
        title: img.title || null,
        displayOrder: img.display_order
      };

      // Only call getFileUrl if filename exists (faster)
      if (img.image_filename) {
        result.url = getFileUrl(img.image_filename, req);
      }

      return result;
    });

    if (!content) {
      return res.status(404).json({
        success: false,
        message: 'Content not found'
      });
    }

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      content: {
        title: content.title,
        subtitle: content.subtitle,
        buttonText: content.button_text,
        subtitleUrl: content.subtitle_url || null,
        backgroundImage: content.background_image ? getFileUrl(content.background_image, req) : null,
        backgroundVideo: content.background_video ? getFileUrl(content.background_video, req) : null,
        backgroundImages: backgroundImages
      }
    };

    res.json(result);
  } catch (error) {
    console.error('Error fetching content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update welcome content (public endpoint - frontend handles admin check)
app.put('/api/content/welcome', async (req, res) => {
  try {
    const { title, subtitle, buttonText, subtitleUrl, backgroundImage, backgroundVideo } = req.body;

    if (!title) {
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('welcome');

    if (existing) {
      // Update existing content
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, button_text = ?, subtitle_url = ?,
            background_image = ?, background_video = ?,
            updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(
        title,
        subtitle || null,
        buttonText || null,
        subtitleUrl || null,
        backgroundImage || null,
        backgroundVideo || null,
        1, // Default admin user ID
        'welcome'
      );
    } else {
      // Create new content
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, button_text, subtitle_url, background_image, background_video, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      await insertContent.run(
        'welcome',
        title,
        subtitle || null,
        buttonText || null,
        subtitleUrl || null,
        backgroundImage || null,
        backgroundVideo || null,
        1 // Default admin user ID
      );
    }

    res.json({
      success: true,
      message: 'Welcome content updated successfully',
      content: {
        title,
        subtitle,
        buttonText,
        subtitleUrl: subtitleUrl || null,
        backgroundImage: getFileUrl(backgroundImage),
        backgroundVideo: getFileUrl(backgroundVideo)
      }
    });
  } catch (error) {
    console.error('Error updating content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload background image/video (admin only) - accepts file upload or URL
app.post('/api/content/welcome/upload', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    let fileData = null;
    let fileType = null;

    // Check if file was uploaded
    if (req.file) {
      if (useCloudinary) {
        // Upload to Cloudinary and get URL
        try {
          const folder = 'acdc-images/welcome';
          const result = await uploadToCloudinary(req.file.buffer, folder);
          fileData = result.secure_url; // Cloudinary URL
          fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
          console.log(`✅ Uploaded to Cloudinary: ${fileData}`);
        } catch (error) {
          console.error('❌ Cloudinary upload failed:', error.message);
          return res.status(500).json({
            success: false,
            message: 'Failed to upload image to cloud storage: ' + error.message
          });
        }
      } else {
        // File is saved to disk, get filename (not base64)
        fileData = req.file.filename;
        fileType = req.file.mimetype.startsWith('image/') ? 'image' : 'video';
      }
    } else {
      // Check for URL or existing filename in request body
      const fileDataFromBody = await handleFileOrUrl(req, 'acdc-images/welcome');
      if (!fileDataFromBody) {
        return res.status(400).json({
          success: false,
          message: 'File or URL is required'
        });
      }
      fileData = fileDataFromBody;
      // Determine type from data
      if (fileData.startsWith('data:')) {
        fileType = fileData.startsWith('data:image/') ? 'image' : 'video';
      } else if (fileData.includes('.')) {
        fileType = /\.(jpg|jpeg|png|gif|webp)$/i.test(fileData) ? 'image' : 'video';
      } else {
        // Default to image if can't determine
        fileType = 'image';
      }
    }

    // Determine if it's an image or video
    const isImage = fileType === 'image' || (fileData.startsWith('data:image/') || /\.(jpg|jpeg|png|gif|webp)$/i.test(fileData));
    const isVideo = fileType === 'video' || (fileData.startsWith('data:video/') || /\.(mp4|webm|mov)$/i.test(fileData));

    if (isImage) {
      // For images, add to background_images table
      let imageUrls = [];
      let imageId = null;
      try {
        const getMaxOrder = db.prepare('SELECT MAX(display_order) as max_order FROM background_images WHERE page_key = ?');
        const maxOrderResult = await getMaxOrder.get('welcome');
        const nextOrder = (maxOrderResult?.max_order ?? -1) + 1;

        // Get title from request body (optional)
        const { title } = req.body || {};
        const imageTitle = title ? title.trim() : null;

        const insertImage = db.prepare(`
          INSERT INTO background_images (page_key, image_filename, title, display_order, created_by)
          VALUES (?, ?, ?, ?, ?)
        `);
        const result = await insertImage.run('welcome', fileData, imageTitle, nextOrder, req.user.id);
        imageId = result.lastInsertRowid;

        // Get all background images for Socket.IO update - Optimized
        const getBackgroundImages = db.prepare('SELECT * FROM background_images WHERE page_key = ? ORDER BY display_order ASC, id ASC');
        const images = await getBackgroundImages.all('welcome');
        // Optimize: Only process URLs if data exists
        imageUrls = images.map(img => {
          const result = {
            id: img.id,
            url: null,
            filename: img.image_filename ? (img.image_filename.length > 50 ? img.image_filename.substring(0, 50) + '...' : img.image_filename) : '',
            title: img.title || null,
            displayOrder: img.display_order
          };

          // Only call getFileUrl if filename exists (faster)
          if (img.image_filename) {
            result.url = getFileUrl(img.image_filename, req);
          }

          return result;
        });
      } catch (error) {
        console.error('Error handling background images:', error.message);
        // If database operation fails, throw error to be caught by outer catch
        throw new Error('Failed to save image to database: ' + error.message);
      }

      // Get welcome content for response
      let welcomeContent = null;
      try {
        const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
        welcomeContent = await getContent.get('welcome');
      } catch (error) {
        console.error('Error fetching welcome content:', error.message);
        // Continue even if welcome content fetch fails
      }

      const updatedContent = {
        title: welcomeContent?.title || '',
        subtitle: welcomeContent?.subtitle || '',
        buttonText: welcomeContent?.button_text || '',
        subtitleUrl: welcomeContent?.subtitle_url || null,
        backgroundImage: welcomeContent?.background_image || null,
        backgroundVideo: welcomeContent?.background_video || null,
        backgroundImages: imageUrls
      };

      res.json({
        success: true,
        message: 'Image uploaded successfully',
        fileUrl: fileData,
        filename: req.file ? req.file.originalname : 'uploaded-image',
        type: 'image',
        imageId: imageId,
        content: updatedContent // Include updated content with all images for immediate display
      });

      // Emit Socket.IO event for live update
      try {
        emitUpdate('welcome:updated', updatedContent);
      } catch (socketError) {
        console.error('Error emitting Socket.IO update:', socketError.message);
        // Don't fail the request if Socket.IO fails
      }
    } else if (isVideo) {
      // For videos, update page_content table (single video)
      const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
      const existing = await checkContent.get('welcome');

      if (existing) {
        // Old video will be replaced by new one

        const updateContent = db.prepare(`
          UPDATE page_content 
          SET background_video = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
          WHERE page_key = ?
        `);
        await updateContent.run(fileData, req.user.id, 'welcome');
      } else {
        const insertContent = db.prepare(`
          INSERT INTO page_content (page_key, title, subtitle, background_video, updated_by)
          VALUES (?, ?, ?, ?, ?)
        `);
        await insertContent.run(
          'welcome',
          'Welcome to Our Website',
          'We are team of talented designers making websites with Bootstrap',
          fileData,
          req.user.id
        );
      }

      // Get all background images for Socket.IO update
      let imageUrls = [];
      try {
        const getBackgroundImages = db.prepare('SELECT * FROM background_images WHERE page_key = ? ORDER BY display_order ASC, id ASC');
        const images = await getBackgroundImages.all('welcome');
        imageUrls = images.map(img => ({
          id: img.id,
          url: img.image_filename, // Already URL
          filename: img.image_filename,
          displayOrder: img.display_order
        }));
      } catch (error) {
        console.error('Error fetching background images:', error.message);
        imageUrls = [];
      }

      const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
      const welcomeContent = await getContent.get('welcome');

      const updatedContent = {
        title: welcomeContent?.title || '',
        subtitle: welcomeContent?.subtitle || '',
        buttonText: welcomeContent?.button_text || '',
        backgroundImage: welcomeContent?.background_image || null,
        backgroundVideo: getFileUrl(fileData),
        backgroundImages: imageUrls
      };

      res.json({
        success: true,
        message: 'Video uploaded successfully',
        fileUrl: fileData,
        filename: req.file ? req.file.originalname : 'uploaded-video',
        type: 'video'
      });

      // Emit Socket.IO event for live update
      emitUpdate('welcome:updated', updatedContent);
    } else {
      return res.status(400).json({
        success: false,
        message: 'Invalid file type'
      });
    }
  } catch (error) {
    console.error('Error uploading file:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + (error.message || 'Unknown error occurred')
    });
  }
});

// Delete background image (admin only)
app.delete('/api/content/welcome/images/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const imageId = parseInt(req.params.id);

    if (isNaN(imageId) || imageId <= 0) {
      return res.status(400).json({
        success: false,
        message: 'Invalid image ID'
      });
    }

    let image = null;
    try {
      const getImage = db.prepare('SELECT * FROM background_images WHERE id = ?');
      image = await getImage.get(imageId);
    } catch (error) {
      console.error('Error accessing background images table:', error.message);
      return res.status(500).json({
        success: false,
        message: 'Error accessing background images table: ' + error.message
      });
    }

    if (!image) {
      return res.status(404).json({
        success: false,
        message: 'Image not found'
      });
    }

    // Delete file from disk/Cloudinary if it exists (don't fail if file doesn't exist)
    await deleteFileIfExists(image.image_filename);

    // Delete from database
    try {
      const deleteImage = db.prepare('DELETE FROM background_images WHERE id = ?');
      await deleteImage.run(imageId);
    } catch (error) {
      console.error('Error deleting image from database:', error.message);
      return res.status(500).json({
        success: false,
        message: 'Error deleting image from database: ' + error.message
      });
    }

    // Get all remaining background images for Socket.IO update
    let imageUrls = [];
    try {
      const getBackgroundImages = db.prepare('SELECT * FROM background_images WHERE page_key = ? ORDER BY display_order ASC, id ASC');
      const images = await getBackgroundImages.all('welcome');
      imageUrls = images.map(img => ({
        id: img.id,
        url: getFileUrl(img.image_filename),
        filename: img.image_filename,
        title: img.title || null,
        displayOrder: img.display_order
      }));
    } catch (error) {
      console.error('Error fetching remaining background images:', error.message);
      imageUrls = [];
    }

    // Get welcome content for Socket.IO update
    let welcomeContent = null;
    try {
      const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
      welcomeContent = await getContent.get('welcome');
    } catch (error) {
      console.error('Error fetching welcome content:', error.message);
    }

    const updatedContent = {
      title: welcomeContent?.title || '',
      subtitle: welcomeContent?.subtitle || '',
      buttonText: welcomeContent?.button_text || '',
      backgroundImage: getFileUrl(welcomeContent?.background_image),
      backgroundVideo: getFileUrl(welcomeContent?.background_video),
      backgroundImages: imageUrls
    };

    res.json({
      success: true,
      message: 'Image deleted successfully'
    });

    // Emit Socket.IO event for live update
    try {
      emitUpdate('welcome:updated', updatedContent);
    } catch (socketError) {
      console.error('Error emitting Socket.IO update:', socketError.message);
      // Don't fail the request if Socket.IO fails
    }
  } catch (error) {
    console.error('Error deleting image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + (error.message || 'Unknown error occurred')
    });
  }
});

// Get about section content (public) - Optimized for fast response
app.get('/api/content/about', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('about');

    // Combine short_description and full_description if description doesn't exist
    let description = content?.description || '';
    if (!description && content) {
      const parts = [];
      if (content.short_description) parts.push(content.short_description);
      if (content.full_description) parts.push(content.full_description);
      description = parts.join(' ');
    }

    if (!content) {
      const defaultDescription = 'ACDC Tech Was Founded in 2017 with Research and Development Project in the domain of Embedded, PCB Design, IoT, Robotics and Automation. ACDC Tech has a team of minds that is limitless. Our dedicated engineers and developers are top-notch in their endeavor, giving customers the value for their money. We are doing Service and product-based projects and provide customized solutions to our valuable customers. ACDC Tech is a way to Innovation. ACDC Tech have innovator\'s and Robotics Lab around India, we provide different courses in the field of Electronics and Robotics. In this Lab school and college students can join and explore their innovative and creative ideas. We provide different courses at the center and provide Workshops and seminars at School and colleges on Embedded, PCB Design, IoT, Robotics and Automation fields. We are the official mentor and Vendor of ATL by NITI Ayog Under AIM(Atal Innovation Mission). We installed Number of ATLs across India.';

      return res.json({
        success: true,
        content: {
          bannerText: '# Acdc Tech Best Startup Company.',
          title: 'Welcome to',
          companyName: 'ACDC TECH',
          description: defaultDescription,
          logoImage: null
        }
      });
    }

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      content: {
        bannerText: content.banner_text || '# Acdc Tech Best Startup Company.',
        title: content.title || 'Welcome to',
        companyName: content.company_name || 'ACDC TECH',
        description: description || '',
        logoImage: null
      }
    };

    if (content.logo_image) {
      result.content.logoImage = getFileUrl(content.logo_image, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching about content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete apply-now background image (admin only)
app.delete('/api/content/apply-now/background', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('apply-now');

    if (!existing || !existing.background_image) {
      return res.json({
        success: true,
        message: 'No background image to delete'
      });
    }

    // Delete file from disk/Cloudinary if it exists
    await deleteFileIfExists(existing.background_image);

    // Update database to remove background image
    const updateContent = db.prepare(`
      UPDATE page_content 
      SET background_image = NULL, updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE page_key = ?
    `);
    await updateContent.run(req.user.id, 'apply-now');

    res.json({
      success: true,
      message: 'Background image deleted successfully'
    });

    // Emit Socket.IO event for live update
    emitUpdate('apply-now:updated', { backgroundImage: null });
  } catch (error) {
    console.error('Error deleting background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + (error.message || 'Unknown error occurred')
    });
  }
});

// Update about section content (admin only)
app.put('/api/content/about', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { bannerText, title, companyName, description, logoImage } = req.body;

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('about');

    // Extract filename from URL if it's a full URL
    const logoFilename = logoImage ? (logoImage.includes('/') ? logoImage.split('/').pop() : logoImage) : null;

    if (existing) {
      // Update existing content
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, company_name = ?, banner_text = ?, 
            description = ?, logo_image = ?,
            updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(
        title || existing.title,
        companyName || existing.company_name,
        bannerText || existing.banner_text,
        description !== undefined ? description : (existing.description || ''),
        logoFilename,
        req.user.id,
        'about'
      );
    } else {
      // Create new content
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, company_name, banner_text, description, logo_image, updated_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);
      await insertContent.run(
        'about',
        title || 'Welcome to',
        companyName || 'ACDC TECH',
        bannerText || '# Acdc Tech Best Startup Company.',
        description || '',
        logoFilename,
        req.user.id
      );
    }

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const updated = await getContent.get('about');

    const updatedContent = {
      bannerText: bannerText !== undefined ? bannerText : (updated?.banner_text || ''),
      title: title !== undefined ? title : (updated?.title || ''),
      companyName: companyName !== undefined ? companyName : (updated?.company_name || ''),
      description: description !== undefined ? description : (updated?.description || ''),
      logoImage: getFileUrl(logoFilename || updated?.logo_image)
    };

    res.json({
      success: true,
      message: 'About content updated successfully',
      content: updatedContent
    });

    // Emit Socket.IO event for live update
    emitUpdate('about:updated', updatedContent);
  } catch (error) {
    console.error('Error updating about content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload about section logo (admin only) - accepts URL from frontend
app.post('/api/content/about/logo', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { fileUrl } = req.body || {};

    if (!fileUrl) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Extract filename from URL for storage
    const urlParts = fileUrl.split('/');
    const filename = urlParts[urlParts.length - 1].split('?')[0];

    // Update or create about content with URL
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('about');

    if (existing) {
      // Delete old logo if exists
      if (existing.logo_image && existing.logo_image.startsWith('http')) {
        // Old logo will be replaced
      }

      const updateContent = db.prepare(`
        UPDATE page_content 
        SET logo_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileUrl, req.user.id, 'about');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, company_name, logo_image, updated_by)
        VALUES (?, ?, ?, ?, ?)
      `);
      await insertContent.run(
        'about',
        'Welcome to',
        'ACDC TECH',
        fileUrl,
        req.user.id
      );
    }

    // Get updated about content
    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const updated = await getContent.get('about');
    const updatedContent = {
      bannerText: updated?.banner_text || '',
      title: updated?.title || '',
      companyName: updated?.company_name || '',
      description: updated?.description || '',
      logoImage: getFileUrl(updated?.logo_image)
    };

    res.json({
      success: true,
      message: 'Logo uploaded successfully',
      fileUrl,
      filename: filename
    });

    // Emit Socket.IO event for live update
    emitUpdate('about:updated', updatedContent);
  } catch (error) {
    console.error('Error uploading logo:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get goal section content (vision and mission) - public - Optimized for fast response
app.get('/api/content/goal', async (req, res) => {
  try {
    // Remove cache headers to ensure fresh data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('goal');

    // Check if use_bullets and bullet_type columns exist using SQLite PRAGMA
    let hasUseBulletsColumn = false;
    let hasBulletTypeColumn = false;
    try {
      const tableInfo = db.prepare('PRAGMA table_info(page_content)');
      const columns = await tableInfo.all();
      hasUseBulletsColumn = columns.some(col => col.name === 'use_bullets');
      hasBulletTypeColumn = columns.some(col => col.name === 'bullet_type');
    } catch (e) {
      console.log('Could not check for use_bullets or bullet_type column:', e.message);
      // Fallback: check if columns exist in content object
      if (content) {
        hasUseBulletsColumn = 'use_bullets' in content;
        hasBulletTypeColumn = 'bullet_type' in content;
      }
    }

    if (!content) {
      const defaultVision = 'To be a leading technology company that transforms innovative ideas into reality, driving digital transformation and empowering businesses worldwide with cutting-edge solutions. We envision a future where technology seamlessly integrates with human needs, creating sustainable and impactful solutions that make a difference in people\'s lives and businesses. Our vision extends beyond just delivering products and services — we aim to be a catalyst for innovation, fostering a culture of excellence, creativity, and continuous learning that inspires the next generation of technologists.';
      const defaultMission = 'To deliver exceptional technology solutions and services that exceed client expectations, while maintaining the highest standards of quality, integrity, and innovation in everything we do. We are committed to understanding our clients\' unique challenges and providing tailored solutions that drive growth, efficiency, and competitive advantage in their respective industries. Through continuous research, development, and collaboration, we strive to stay at the forefront of technological advancement, ensuring our clients always have access to the most effective and modern solutions available.';

      return res.json({
        success: true,
        content: {
          vision: defaultVision,
          mission: defaultMission,
          backgroundImage: null,
          visionIcon: null,
          missionIcon: null,
          useBullets: false,
          bulletType: 'disc'
        }
      });
    }

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      content: {
        vision: content.vision || '',
        mission: content.mission || '',
        backgroundImage: null,
        visionIcon: null,
        missionIcon: null,
        useBullets: hasUseBulletsColumn ? (content.use_bullets === 1 || content.use_bullets === true) : false,
        bulletType: hasBulletTypeColumn ? (content.bullet_type || 'disc') : 'disc'
      }
    };

    if (content.goal_background_image) {
      result.content.backgroundImage = getFileUrl(content.goal_background_image, req);
    }
    if (content.vision_icon) {
      result.content.visionIcon = getFileUrl(content.vision_icon, req);
    }
    if (content.mission_icon) {
      result.content.missionIcon = getFileUrl(content.mission_icon, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching goal content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update goal section content (vision and mission) - admin only
// Multer middleware is optional - only processes multipart/form-data, JSON requests work normally
app.put('/api/content/goal', authenticateToken, requireAdmin, upload.fields([{ name: 'visionIcon', maxCount: 1 }, { name: 'missionIcon', maxCount: 1 }]), async (req, res) => {
  try {
    // Parse JSON body if Content-Type is application/json (multer only processes multipart/form-data)
    let vision, mission, useBullets, bulletType, visionIcon, missionIcon;

    if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
      // JSON request - body is already parsed by express.json()
      const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      vision = body.vision;
      mission = body.mission;
      useBullets = body.useBullets;
      bulletType = body.bulletType;
      visionIcon = body.visionIcon;
      missionIcon = body.missionIcon;
    } else {
      // FormData request - multer parsed it
      vision = req.body.vision;
      mission = req.body.mission;
      useBullets = req.body.useBullets;
      bulletType = req.body.bulletType;
      visionIcon = req.body.visionIcon;
      missionIcon = req.body.missionIcon;
    }

    console.log('Received update request:', { vision: vision?.substring(0, 50), mission: mission?.substring(0, 50), useBullets, bulletType, hasVisionIcon: !!visionIcon, hasMissionIcon: !!missionIcon });

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['visionIcon', 'missionIcon'], 'acdc-images/goal');

    // Get existing content to check for old files
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('goal');

    // Handle vision icon: new file upload, explicit removal (null), or keep existing
    let visionIconUrl = undefined;
    if (files.visionIcon) {
      // New file uploaded - Cloudinary URL or filename is in files.visionIcon
      visionIconUrl = files.visionIcon;
      // Delete old file if it exists and is different
      if (existing && existing.vision_icon && existing.vision_icon !== visionIconUrl) {
        await deleteFileIfExists(existing.vision_icon);
      }
    } else if (visionIcon !== undefined) {
      // Explicit value provided (could be null for removal)
      if (visionIcon === '' || visionIcon === null) {
        // Explicit removal - delete old file and set to null
        if (existing && existing.vision_icon) {
          await deleteFileIfExists(existing.vision_icon);
        }
        visionIconUrl = null;
      } else {
        // URL or existing filename provided
        visionIconUrl = visionIcon;
      }
    }

    // Handle mission icon: new file upload, explicit removal (null), or keep existing
    let missionIconUrl = undefined;
    if (files.missionIcon) {
      // New file uploaded - Cloudinary URL or filename is in files.missionIcon
      missionIconUrl = files.missionIcon;
      // Delete old file if it exists and is different
      if (existing && existing.mission_icon && existing.mission_icon !== missionIconUrl) {
        await deleteFileIfExists(existing.mission_icon);
      }
    } else if (missionIcon !== undefined) {
      // Explicit value provided (could be null for removal)
      if (missionIcon === '' || missionIcon === null) {
        // Explicit removal - delete old file and set to null
        if (existing && existing.mission_icon) {
          await deleteFileIfExists(existing.mission_icon);
        }
        missionIconUrl = null;
      } else {
        // URL or existing filename provided
        missionIconUrl = missionIcon;
      }
    }

    // Check if use_bullets and bullet_type columns exist using SQLite PRAGMA
    let hasUseBulletsColumn = false;
    let hasBulletTypeColumn = false;
    try {
      const tableInfo = db.prepare('PRAGMA table_info(page_content)');
      const columns = await tableInfo.all();
      hasUseBulletsColumn = columns.some(col => col.name === 'use_bullets');
      hasBulletTypeColumn = columns.some(col => col.name === 'bullet_type');
    } catch (e) {
      console.log('Could not check for use_bullets or bullet_type column:', e.message);
      // Fallback: check if columns exist in existing object
      if (existing) {
        hasUseBulletsColumn = 'use_bullets' in existing;
        hasBulletTypeColumn = 'bullet_type' in existing;
      }
    }

    if (existing) {
      // Build update query dynamically based on what needs to be updated
      const updates = [];
      const values = [];

      if (vision !== undefined) {
        updates.push('vision = ?');
        values.push(vision);
      }
      if (mission !== undefined) {
        updates.push('mission = ?');
        values.push(mission);
      }
      if (useBullets !== undefined && hasUseBulletsColumn) {
        updates.push('use_bullets = ?');
        values.push(useBullets ? 1 : 0);
      }
      if (bulletType !== undefined && hasBulletTypeColumn) {
        updates.push('bullet_type = ?');
        values.push(bulletType);
      }
      if (visionIconUrl !== undefined) {
        updates.push('vision_icon = ?');
        values.push(visionIconUrl);
      }
      if (missionIconUrl !== undefined) {
        updates.push('mission_icon = ?');
        values.push(missionIconUrl);
      }

      updates.push('updated_at = CURRENT_TIMESTAMP');
      updates.push('updated_by = ?');
      values.push(req.user.id);
      values.push('goal');

      if (updates.length > 2) { // More than just updated_at and updated_by
        const updateQuery = `UPDATE page_content SET ${updates.join(', ')} WHERE page_key = ?`;
        const updateContent = db.prepare(updateQuery);
        const updateResult = await updateContent.run(...values);
        console.log(`Updated goal content: ${updateResult.changes} row(s) affected`);
        if (updateResult.changes === 0) {
          console.warn('Warning: No rows were updated. Content may not exist or values are unchanged.');
        }
      }
    } else {
      // Create new content
      if (hasUseBulletsColumn && hasBulletTypeColumn) {
        const insertContent = db.prepare(`
          INSERT INTO page_content (page_key, title, vision, mission, use_bullets, bullet_type, vision_icon, mission_icon, updated_by)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        await insertContent.run(
          'goal',
          'Our Goal', // title is required (NOT NULL constraint)
          vision || '',
          mission || '',
          useBullets ? 1 : 0,
          bulletType || 'disc',
          visionIconUrl || null,
          missionIconUrl || null,
          req.user.id
        );
      } else if (hasUseBulletsColumn) {
        const insertContent = db.prepare(`
          INSERT INTO page_content (page_key, title, vision, mission, use_bullets, vision_icon, mission_icon, updated_by)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `);
        await insertContent.run(
          'goal',
          'Our Goal', // title is required (NOT NULL constraint)
          vision || '',
          mission || '',
          useBullets ? 1 : 0,
          visionIconUrl || null,
          missionIconUrl || null,
          req.user.id
        );
      } else {
        const insertContent = db.prepare(`
          INSERT INTO page_content (page_key, title, vision, mission, vision_icon, mission_icon, updated_by)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        await insertContent.run(
          'goal',
          'Our Goal',
          vision || '',
          mission || '',
          visionIconUrl || null,
          missionIconUrl || null,
          req.user.id
        );
      }
    }

    // Fetch the updated content from database to ensure we return the actual saved values
    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const updated = await getContent.get('goal');

    if (!updated) {
      console.error('Error: Content was not found after update/insert');
      return res.status(500).json({
        success: false,
        message: 'Failed to retrieve updated content'
      });
    }

    // Return the actual database values (which include line breaks and all saved data)
    const updatedContent = {
      vision: updated.vision || '',
      mission: updated.mission || '',
      backgroundImage: getFileUrl(updated.goal_background_image),
      visionIcon: getFileUrl(updated.vision_icon),
      missionIcon: getFileUrl(updated.mission_icon),
      useBullets: hasUseBulletsColumn ? (updated.use_bullets === 1 || updated.use_bullets === true) : false,
      bulletType: hasBulletTypeColumn ? (updated.bullet_type || 'disc') : 'disc'
    };

    console.log('Returning updated content:', {
      visionLength: updatedContent.vision.length,
      missionLength: updatedContent.mission.length,
      hasVisionIcon: !!updatedContent.visionIcon,
      hasMissionIcon: !!updatedContent.missionIcon,
      useBullets: updatedContent.useBullets,
      bulletType: updatedContent.bulletType
    });

    res.json({
      success: true,
      message: 'Goal content updated successfully',
      content: updatedContent
    });

    // Emit Socket.IO event for live update
    emitUpdate('goal:updated', updatedContent);
  } catch (error) {
    console.error('Error updating goal content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload goal section background image (admin only)
app.post('/api/content/goal/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    // Update or create goal content with Base64 or URL
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('goal');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET goal_background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'goal');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, goal_background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('goal', 'Our Goal', fileData, req.user.id);
    }

    // Get updated goal content
    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const updated = await getContent.get('goal');
    const updatedContent = {
      vision: updated?.vision || '',
      mission: updated?.mission || '',
      backgroundImage: getFileUrl(fileData)
    };

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: fileData,
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });

    // Emit Socket.IO event for live update
    emitUpdate('goal:updated', updatedContent);
  } catch (error) {
    console.error('Error uploading goal background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get products hero background (public) - Optimized for fast response
app.get('/api/content/products-hero', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('products-hero');

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      backgroundImage: null,
      heading: content?.title || 'ACDC Products',
      subtitle: content?.subtitle || null
    };

    if (content?.background_image) {
      result.backgroundImage = getFileUrl(content.background_image, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching products hero background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload products hero background image (admin only)
app.post('/api/content/products-hero/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('products-hero');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'products-hero');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('products-hero', 'Our Products', fileData, req.user.id);
    }

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: getFileUrl(fileData, req),
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });
  } catch (error) {
    console.error('Error uploading products hero background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get services hero background (public) - Optimized for fast response
app.get('/api/content/services-hero', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('services-hero');

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      backgroundImage: null,
      heading: content?.title || 'Our Services',
      subtitle: content?.subtitle || null
    };

    if (content?.background_image) {
      result.backgroundImage = getFileUrl(content.background_image, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching services hero background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload services hero background image (admin only)
app.post('/api/content/services-hero/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('services-hero');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'services-hero');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('services-hero', 'Our Services', fileData, req.user.id);
    }

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: getFileUrl(fileData, req),
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });
  } catch (error) {
    console.error('Error uploading services hero background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get blog hero background (public) - Optimized for fast response
app.get('/api/content/blog-hero', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('blog-hero');

    res.json({
      success: true,
      backgroundImage: content?.background_image ? getFileUrl(content.background_image, req) : null,
      heading: content?.title || 'Blog',
      subtitle: content?.subtitle || null
    });
  } catch (error) {
    console.error('Error fetching blog hero background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload blog hero background image (admin only)
app.post('/api/content/blog-hero/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('blog-hero');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'blog-hero');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('blog-hero', 'Blog', fileData, req.user.id);
    }

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: getFileUrl(fileData, req),
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });
  } catch (error) {
    console.error('Error uploading blog hero background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get career hero background (public) - Optimized for fast response
app.get('/api/content/career-hero', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('career-hero');

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      backgroundImage: null,
      heading: content?.title || 'CAREER',
      subtitle: content?.subtitle || null
    };

    if (content?.background_image) {
      result.backgroundImage = getFileUrl(content.background_image, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching career hero background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload career hero background image (admin only)
app.post('/api/content/career-hero/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('career-hero');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'career-hero');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('career-hero', 'CAREER', fileData, req.user.id);
    }

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: getFileUrl(fileData, req),
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });
  } catch (error) {
    console.error('Error uploading career hero background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get contact hero background (public) - Optimized for fast response
app.get('/api/content/contact-hero', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('contact-hero');

    // Optimize: Only call getFileUrl if data exists
    const result = {
      success: true,
      backgroundImage: null,
      heading: content?.title || 'Contact Us',
      subtitle: content?.subtitle || null
    };

    if (content?.background_image) {
      result.backgroundImage = getFileUrl(content.background_image, req);
    }

    res.json(result);
  } catch (error) {
    console.error('Error fetching contact hero background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update hero heading (admin only)
app.put('/api/content/:pageKey/heading', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { pageKey } = req.params;
    const { heading, subtitle } = req.body;

    // Validate pageKey
    const validPageKeys = ['services-hero', 'blog-hero', 'career-hero', 'products-hero', 'contact-hero'];
    if (!validPageKeys.includes(pageKey)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid page key'
      });
    }

    // Validate heading
    if (!heading || typeof heading !== 'string' || heading.trim().length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Heading is required and cannot be empty'
      });
    }

    // Validate subtitle (optional)
    const subtitleValue = subtitle && typeof subtitle === 'string' ? subtitle.trim() : null;

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get(pageKey);

    if (existing) {
      // Update existing content
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, updated_by = ?, updated_at = CURRENT_TIMESTAMP
        WHERE page_key = ?
      `);
      await updateContent.run(heading.trim(), subtitleValue, req.user.id, pageKey);
    } else {
      // Create new content with heading and subtitle
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run(pageKey, heading.trim(), subtitleValue, req.user.id);
    }

    res.json({
      success: true,
      message: 'Heading updated successfully'
    });
  } catch (error) {
    console.error('Error updating heading:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Upload contact hero background image (admin only)
app.post('/api/content/contact-hero/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('contact-hero');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(fileData, req.user.id, 'contact-hero');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('contact-hero', 'Contact Us', fileData, req.user.id);
    }

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: getFileUrl(fileData, req),
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });
  } catch (error) {
    console.error('Error uploading contact hero background image:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get apply now section background (public)
app.get('/api/content/apply-now', async (req, res) => {
  try {
    // Remove cache headers to ensure fresh data
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('apply-now');

    if (!content) {
      return res.json({
        success: true,
        backgroundImage: null
      });
    }

    res.json({
      success: true,
      backgroundImage: content.background_image ? getFileUrl(content.background_image, req) : null
    });
  } catch (error) {
    console.error('Error fetching apply now background:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Upload apply now section background image (admin only)
app.post('/api/content/apply-now/background', authenticateToken, requireAdmin, upload.single('file'), async (req, res) => {
  try {
    const fileData = await handleFileOrUrl(req);

    if (!fileData) {
      return res.status(400).json({
        success: false,
        message: 'File or URL is required'
      });
    }

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('apply-now');

    // Delete old background image if exists
    if (existing && existing.background_image) {
      await deleteFileIfExists(existing.background_image);
    }

    if (existing) {
      // Ensure title is not null when updating
      const titleValue = existing.title || 'Apply Now';
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, background_image = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(titleValue, fileData, req.user.id, 'apply-now');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, background_image, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('apply-now', 'Apply Now', fileData, req.user.id);
    }

    // Return full URL for easy rendering
    const fullUrl = getFileUrl(fileData, req);

    res.json({
      success: true,
      message: 'Background image uploaded successfully',
      fileUrl: fullUrl,
      filename: req.file ? req.file.originalname : 'uploaded-image'
    });

    // Emit Socket.IO event for live update
    emitUpdate('apply-now:updated', { backgroundImage: fullUrl });
  } catch (error) {
    console.error('Error uploading apply now background image:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error: ' + (error.message || 'Unknown error occurred'),
      error: error.message
    });
  }
});

// Get members statistics (public)
app.get('/api/content/members-stats', async (req, res) => {
  try {
    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('members-stats');

    let statsData = {
      clients: '250+',
      projects: '375+'
    };

    if (content && content.subtitle) {
      try {
        const parsed = JSON.parse(content.subtitle);
        statsData = {
          clients: parsed.clients || '250+',
          projects: parsed.projects || '375+'
        };
      } catch (e) {
        // If parsing fails, use defaults
      }
    }

    res.json({
      success: true,
      stats: statsData
    });
  } catch (error) {
    console.error('Error fetching members stats:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update members statistics (admin only)
app.put('/api/content/members-stats', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { clients, projects } = req.body;

    if (!clients && !projects) {
      return res.status(400).json({
        success: false,
        message: 'At least one stat value (clients or projects) is required'
      });
    }

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('members-stats');

    let statsData = {
      clients: '250+',
      projects: '375+'
    };

    // Get existing values if they exist
    if (existing && existing.subtitle) {
      try {
        const parsed = JSON.parse(existing.subtitle);
        statsData = {
          clients: parsed.clients || '250+',
          projects: parsed.projects || '375+'
        };
      } catch (e) {
        // Use defaults if parsing fails
      }
    }

    // Update with new values
    if (clients !== undefined) {
      statsData.clients = typeof clients === 'number' ? `${clients}+` : clients;
    }
    if (projects !== undefined) {
      statsData.projects = typeof projects === 'number' ? `${projects}+` : projects;
    }

    if (existing) {
      // Update existing content
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(JSON.stringify(statsData), req.user.id, 'members-stats');
    } else {
      // Create new content
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('members-stats', 'Members Statistics', JSON.stringify(statsData), req.user.id);
    }

    res.json({
      success: true,
      message: 'Members statistics updated successfully',
      stats: statsData
    });
  } catch (error) {
    console.error('Error updating members stats:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get contact page content (public)
app.get('/api/content/contact', async (req, res) => {
  try {
    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('contact');

    let contactData = {
      title: 'Contact for any query',
      description: 'Get in touch with us for any questions or inquiries. We\'re here to help you with your needs.',
      address: '405, Amora Arcade, Nr. Mauni International School, Mota Varachha - Uttran, Surat-394 105, Gujarat, India',
      phone: '+91 (0261) 356-5444',
      email: 'account@acdctech.in',
      mapUrl: 'https://www.google.com/maps/embed?pb=!1m18!1m12!1m3!1d3719.5!2d72.8!3d21.2!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!3m3!1m2!1s0x0%3A0x0!2zMjHCsDEyJzAwLjAiTiA3MsKwNDgnMDAuMCJF!5e0!3m2!1sen!2sin!4v1234567890123!5m2!1sen!2sin'
    };

    if (content && content.subtitle) {
      try {
        const parsed = JSON.parse(content.subtitle);
        contactData = { ...contactData, ...parsed };
      } catch (e) {
        // If subtitle is not JSON, use it as description
        contactData.description = content.subtitle;
      }
    }

    res.json({
      success: true,
      content: contactData
    });
  } catch (error) {
    console.error('Error fetching contact content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update contact page content (admin only)
app.put('/api/content/contact', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { title, description, address, phone, email, mapUrl } = req.body;

    const contactData = {
      title: title || 'Contact for any query',
      description: description || 'Get in touch with us for any questions or inquiries. We\'re here to help you with your needs.',
      address: address || '',
      phone: phone || '',
      email: email || '',
      mapUrl: mapUrl || ''
    };

    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('contact');

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(contactData.title, JSON.stringify(contactData), req.user.id, 'contact');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('contact', contactData.title, JSON.stringify(contactData), req.user.id);
    }

    res.json({
      success: true,
      message: 'Contact content updated successfully',
      content: contactData
    });

    // Emit Socket.IO event for live update
    emitUpdate('contact:content:updated', { content: contactData });
  } catch (error) {
    console.error('Error updating contact content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get footer content (public) - Optimized for fast response
app.get('/api/content/footer', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('footer');

    const BASE_URL = process.env.BASE_URL || `http://${req.get('host')}`;

    let footerData = {
      companyName: 'Advance Circuit Development Center',
      phone: '+91 (0261) 356-5444',
      email: 'account@acdctech.in',
      address: '405, Amora Arcade, Nr. Mauni International School, Mota Varachha - Uttran, Surat-394 105, Gujarat, India',
      newsletterDescription: 'Best solution for your it startup business consecteturadipiscing elit.',
      facebook: '#',
      twitter: '#',
      linkedin: '#',
      instagram: '#',
      pinterest: '#',
      youtube: '#',
      copyright: 'ACDC TECH',
      logo: null
    };

    if (content && content.subtitle) {
      try {
        const parsed = JSON.parse(content.subtitle);
        footerData = { ...footerData, ...parsed };
        // Convert logo filename to full URL if it exists - Optimize: Only call getFileUrl if needed
        if (footerData.logo && !footerData.logo.startsWith('http') && !footerData.logo.startsWith('data:')) {
          footerData.logo = getFileUrl(footerData.logo);
        }
        // Convert social media icon filenames to full URLs if they exist - Optimize: Only call getFileUrl if needed
        const iconFields = ['facebookIcon', 'twitterIcon', 'linkedinIcon', 'instagramIcon', 'pinterestIcon', 'youtubeIcon'];
        iconFields.forEach(field => {
          if (footerData[field] && !footerData[field].startsWith('http') && !footerData[field].startsWith('data:')) {
            footerData[field] = getFileUrl(footerData[field]);
          }
        });
      } catch (e) {
        // If subtitle is not JSON, use it as description
        footerData.newsletterDescription = content.subtitle;
      }
    }

    res.json({
      success: true,
      content: footerData
    });
  } catch (error) {
    console.error('Error fetching footer content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update footer content (admin only) - handles both JSON and FormData
app.put('/api/content/footer', authenticateToken, requireAdmin, upload.single('logo'), async (req, res) => {
  try {
    // Parse body fields - handle both JSON and FormData
    const body = req.body || {};

    // Helper to safely get string value from body
    const getStringValue = (key, defaultValue = undefined) => {
      const value = body[key];
      if (value === undefined || value === null) return defaultValue;
      return String(value);
    };

    const companyName = getStringValue('companyName');
    const phone = getStringValue('phone');
    const email = getStringValue('email');
    const address = getStringValue('address');
    const newsletterDescription = getStringValue('newsletterDescription');
    const facebook = getStringValue('facebook');
    const twitter = getStringValue('twitter');
    const linkedin = getStringValue('linkedin');
    const instagram = getStringValue('instagram');
    const pinterest = getStringValue('pinterest');
    const youtube = getStringValue('youtube');
    const copyright = getStringValue('copyright');
    const logo = body.logo; // Can be string, null, or undefined
    const facebookIcon = body.facebookIcon;
    const twitterIcon = body.twitterIcon;
    const linkedinIcon = body.linkedinIcon;
    const instagramIcon = body.instagramIcon;
    const pinterestIcon = body.pinterestIcon;
    const youtubeIcon = body.youtubeIcon;

    // Get existing footer data to preserve icons if not uploading new ones
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('footer');

    let existingData = {
      logo: null,
      facebookIcon: null,
      twitterIcon: null,
      linkedinIcon: null,
      instagramIcon: null,
      pinterestIcon: null,
      youtubeIcon: null
    };

    if (existing && existing.subtitle) {
      try {
        const parsed = JSON.parse(existing.subtitle);
        existingData = { ...existingData, ...parsed };
      } catch (e) {
        // Ignore parse errors
      }
    }

    // Handle file upload or URL from request body - uploads to Cloudinary if configured
    let newLogo = null;
    try {
      newLogo = await handleFileOrUrl(req, 'acdc-images/footer');
    } catch (uploadError) {
      console.error('Error handling file upload:', uploadError);
      // Continue without logo if upload fails
    }

    if (newLogo !== null) {
      // Delete old logo if exists (only for local files, not Cloudinary URLs)
      if (existingData.logo && typeof existingData.logo === 'string' && !existingData.logo.startsWith('http') && !existingData.logo.startsWith('data:')) {
        await deleteFileIfExists(existingData.logo);
      }
      existingData.logo = newLogo;
    } else if (logo !== undefined) {
      // Fallback to logo from body if no file uploaded
      existingData.logo = (typeof logo === 'string' || logo === null) ? logo : null;
    }

    const iconFieldNames = ['facebookIcon', 'twitterIcon', 'linkedinIcon', 'instagramIcon', 'pinterestIcon', 'youtubeIcon'];
    const iconValues = {
      facebookIcon: facebookIcon !== undefined ? (typeof facebookIcon === 'string' || facebookIcon === null ? facebookIcon : null) : existingData.facebookIcon,
      twitterIcon: twitterIcon !== undefined ? (typeof twitterIcon === 'string' || twitterIcon === null ? twitterIcon : null) : existingData.twitterIcon,
      linkedinIcon: linkedinIcon !== undefined ? (typeof linkedinIcon === 'string' || linkedinIcon === null ? linkedinIcon : null) : existingData.linkedinIcon,
      instagramIcon: instagramIcon !== undefined ? (typeof instagramIcon === 'string' || instagramIcon === null ? instagramIcon : null) : existingData.instagramIcon,
      pinterestIcon: pinterestIcon !== undefined ? (typeof pinterestIcon === 'string' || pinterestIcon === null ? pinterestIcon : null) : existingData.pinterestIcon,
      youtubeIcon: youtubeIcon !== undefined ? (typeof youtubeIcon === 'string' || youtubeIcon === null ? youtubeIcon : null) : existingData.youtubeIcon
    };

    // Update icon values
    iconFieldNames.forEach(field => {
      if (iconValues[field] !== undefined) {
        existingData[field] = iconValues[field] || null;
      }
    });

    const footerData = {
      companyName: companyName !== undefined ? companyName : (existingData.companyName || 'Advance Circuit Development Center'),
      phone: phone !== undefined ? phone : (existingData.phone || '+91 (0261) 356-5444'),
      email: email !== undefined ? email : (existingData.email || 'account@acdctech.in'),
      address: address !== undefined ? address : (existingData.address || ''),
      newsletterDescription: newsletterDescription !== undefined ? newsletterDescription : (existingData.newsletterDescription || 'Best solution for your it startup business consecteturadipiscing elit.'),
      facebook: facebook !== undefined ? facebook : (existingData.facebook || '#'),
      twitter: twitter !== undefined ? twitter : (existingData.twitter || '#'),
      linkedin: linkedin !== undefined ? linkedin : (existingData.linkedin || '#'),
      instagram: instagram !== undefined ? instagram : (existingData.instagram || '#'),
      pinterest: pinterest !== undefined ? pinterest : (existingData.pinterest || '#'),
      youtube: youtube !== undefined ? youtube : (existingData.youtube || '#'),
      copyright: copyright !== undefined ? copyright : (existingData.copyright || 'ACDC TECH'),
      logo: existingData.logo || null,
      facebookIcon: existingData.facebookIcon || null,
      twitterIcon: existingData.twitterIcon || null,
      linkedinIcon: existingData.linkedinIcon || null,
      instagramIcon: existingData.instagramIcon || null,
      pinterestIcon: existingData.pinterestIcon || null,
      youtubeIcon: existingData.youtubeIcon || null
    };

    // Ensure user ID exists
    const userId = req.user?.id || null;

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run('Footer', JSON.stringify(footerData), userId, 'footer');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('footer', 'Footer', JSON.stringify(footerData), userId);
    }

    // Return logo and icons with proper URL handling
    const responseData = { ...footerData };
    try {
      responseData.logo = getFileUrl(responseData.logo, req);
      iconFieldNames.forEach(field => {
        responseData[field] = getFileUrl(responseData[field], req);
      });
    } catch (urlError) {
      console.error('Error generating file URLs:', urlError);
      // Continue with original values if URL generation fails
    }

    res.json({
      success: true,
      message: 'Footer content updated successfully',
      content: responseData
    });

    // Emit Socket.IO event for live update
    emitUpdate('footer:updated', responseData);
  } catch (error) {
    console.error('Error updating footer content:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'An error occurred while updating footer content'
    });
  }
});

// Get header content (public) - Optimized for fast response
app.get('/api/content/header', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('header');

    const BASE_URL = process.env.BASE_URL || `http://${req.get('host')}`;

    let headerData = {
      logo: null
    };

    if (content && content.subtitle) {
      try {
        const parsed = JSON.parse(content.subtitle);
        headerData = {
          ...headerData,
          logo: parsed.logo !== undefined ? parsed.logo : headerData.logo
        };
        // Convert logo filename to full URL if it exists - Cloudinary URLs are already full URLs, so keep as-is
        if (headerData.logo && !headerData.logo.startsWith('http://') && !headerData.logo.startsWith('https://') && !headerData.logo.startsWith('data:')) {
          headerData.logo = getFileUrl(headerData.logo, req);
        }
      } catch (e) {
        // Ignore parse errors
      }
    }

    res.json({
      success: true,
      content: headerData
    });
  } catch (error) {
    console.error('Error fetching header content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update header content (admin only) - handles both JSON and FormData
app.put('/api/content/header', authenticateToken, requireAdmin, upload.single('logo'), async (req, res) => {
  try {
    // Get existing header data to preserve logos if not uploading new ones
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('header');

    let existingLogo = null;
    if (existing && existing.subtitle) {
      try {
        const parsed = JSON.parse(existing.subtitle);
        existingLogo = parsed.logo !== undefined ? parsed.logo : null;
      } catch (e) {
        // Ignore parse errors
      }
    }

    // Handle file upload or URL from request body - uploads to Cloudinary if configured
    let newLogo = null;
    try {
      newLogo = await handleFileOrUrl(req, 'acdc-images/header');
    } catch (uploadError) {
      console.error('Error handling file upload:', uploadError);
      // Continue without logo if upload fails
    }

    if (newLogo !== null) {
      // Delete old logo if exists (only for local files, not Cloudinary URLs)
      if (existingLogo && typeof existingLogo === 'string' && !existingLogo.startsWith('http') && !existingLogo.startsWith('https') && !existingLogo.startsWith('data:')) {
        await deleteFileIfExists(existingLogo);
      }
      existingLogo = newLogo;
    } else if (req.body?.logo !== undefined) {
      // Fallback to logo from body if no file uploaded
      existingLogo = (typeof req.body.logo === 'string' || req.body.logo === null) ? req.body.logo : null;
    }

    // Build headerData object
    const headerData = {
      logo: existingLogo !== null ? existingLogo : null
    };

    // Ensure user ID exists
    const userId = req.user?.id || null;

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run('Header', JSON.stringify(headerData), userId, 'header');
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('header', 'Header', JSON.stringify(headerData), userId);
    }

    // Return logo with proper URL handling - Cloudinary URLs are already full URLs, so keep as-is
    const responseData = {
      logo: existingLogo !== null ? existingLogo : null
    };

    try {
      // Only process if it's not already a full URL (Cloudinary URLs start with https://)
      if (responseData.logo && !responseData.logo.startsWith('http://') && !responseData.logo.startsWith('https://') && !responseData.logo.startsWith('data:')) {
        responseData.logo = getFileUrl(responseData.logo, req);
      }
    } catch (urlError) {
      console.error('Error generating file URL:', urlError);
      // Continue with original value if URL generation fails
    }

    console.log('Sending header response:', {
      logo: responseData.logo ? 'exists' : 'null'
    });

    res.json({
      success: true,
      message: 'Header content updated successfully',
      content: responseData
    });

    // Emit Socket.IO event for live update
    emitUpdate('header:updated', responseData);
  } catch (error) {
    console.error('Error updating header content:', error);
    console.error('Error stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'An error occurred while updating header content'
    });
  }
});

// Get all clients (public) - Optimized for fast response
app.get('/api/clients', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const BASE_URL = process.env.BASE_URL || `http://${req.get('host')}`;
    const getClients = db.prepare('SELECT * FROM clients ORDER BY display_order ASC, id ASC');
    const clients = await getClients.all();

    // Optimize: Only call getFileUrl if data exists
    const clientsWithUrls = clients.map(client => {
      const result = {
        id: client.id,
        name: client.name,
        logo: null,
        display_order: client.display_order || 0
      };

      if (client.logo_filename) {
        result.logo = getFileUrl(client.logo_filename);
      }

      return result;
    });

    res.json({
      success: true,
      clients: clientsWithUrls
    });
  } catch (error) {
    console.error('Error fetching clients:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new client (admin only)
app.post('/api/clients', authenticateToken, requireAdmin, upload.single('logo'), async (req, res) => {
  try {
    // Handle file upload or URL - uploads to Cloudinary if configured
    const logoUrl = await handleFileOrUrl(req, 'acdc-images/clients');

    // Get other fields from request body
    const { name, display_order } = req.body || {};

    // Trim and validate name
    const trimmedName = name ? name.trim() : '';

    if (!trimmedName) {
      return res.status(400).json({
        success: false,
        message: 'Client name is required'
      });
    }

    // Check if client with same name already exists
    const checkClient = db.prepare('SELECT * FROM clients WHERE LOWER(name) = LOWER(?)');
    const existing = await checkClient.get(trimmedName);

    if (existing) {
      return res.status(400).json({
        success: false,
        message: 'A client with this name already exists'
      });
    }
    const displayOrder = display_order ? parseInt(display_order) : 0;

    const insertClient = db.prepare(`
      INSERT INTO clients (name, logo_filename, display_order, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?)
    `);

    const result = await insertClient.run(
      trimmedName,
      logoUrl,
      displayOrder,
      req.user.id,
      req.user.id
    );

    const client = {
      id: result.lastInsertRowid,
      name: trimmedName,
      logo: getFileUrl(logoUrl),
      display_order: displayOrder
    };

    res.json({
      success: true,
      message: 'Client added successfully',
      client: client
    });
  } catch (error) {
    console.error('Error adding client:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Delete client (admin only)
app.delete('/api/clients/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const clientId = parseInt(req.params.id);

    if (!clientId) {
      return res.status(400).json({
        success: false,
        message: 'Invalid client ID'
      });
    }

    // Get client to delete logo file
    const getClient = db.prepare('SELECT * FROM clients WHERE id = ?');
    const client = await getClient.get(clientId);

    if (!client) {
      return res.status(404).json({
        success: false,
        message: 'Client not found'
      });
    }

    // Delete old logo if it exists
    if (client.logo_filename && client.logo_filename.startsWith('http')) {
      // Old logo will be deleted from database
    }

    // Delete client from database
    const deleteClient = db.prepare('DELETE FROM clients WHERE id = ?');
    await deleteClient.run(clientId);

    res.json({
      success: true,
      message: 'Client deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting client:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get all consultance members (public) - Optimized for fast response
app.get('/api/consultance', async (req, res) => {
  try {
    // Disable caching to ensure fresh data after deletions/updates
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const getConsultance = db.prepare('SELECT * FROM consultance ORDER BY display_order ASC, id ASC');
    const members = await getConsultance.all();

    // Optimize: Only call getFileUrl if data exists
    const membersWithUrls = members.map(member => {
      const result = { ...member, imageUrl: null };
      if (member.image) {
        result.imageUrl = getFileUrl(member.image);
      }
      return result;
    });

    res.json({
      success: true,
      members: membersWithUrls
    });
  } catch (error) {
    console.error('Error fetching consultance:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new consultance member (admin only)
app.post('/api/consultance', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    // Handle file upload or URL - uploads to Cloudinary if configured
    const imageUrl = await handleFileOrUrl(req, 'acdc-images/consultance');

    // Get other fields from request body
    const { name, title, display_order, facebook_url, instagram_url, twitter_url, linkedin_url } = req.body;

    // Trim and validate name and title
    const trimmedName = name ? name.trim() : '';
    const trimmedTitle = title ? title.trim() : '';

    if (!trimmedName || !trimmedTitle) {
      return res.status(400).json({
        success: false,
        message: 'Name and title are required'
      });
    }
    const order = display_order ? parseInt(display_order) : 0;

    const insertConsultance = db.prepare(`
      INSERT INTO consultance (name, title, image, facebook_url, instagram_url, twitter_url, linkedin_url, display_order, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertConsultance.run(
      trimmedName,
      trimmedTitle,
      imageUrl,
      facebook_url || null,
      instagram_url || null,
      twitter_url || null,
      linkedin_url || null,
      order,
      req.user.id
    );

    const member = {
      id: result.lastInsertRowid,
      name: trimmedName,
      title: trimmedTitle,
      image: imageUrl,
      imageUrl: getFileUrl(imageUrl),
      facebook_url: facebook_url || null,
      instagram_url: instagram_url || null,
      twitter_url: twitter_url || null,
      linkedin_url: linkedin_url || null,
      display_order: order
    };

    // Get all members to send updated list
    const getConsultance = db.prepare('SELECT * FROM consultance ORDER BY display_order ASC, id ASC');
    const allMembers = await getConsultance.all();
    const membersWithUrls = allMembers.map(m => ({
      ...m,
      imageUrl: m.image ? getFileUrl(m.image) : null
    }));

    emitUpdate('consultance:updated', { action: 'added', members: membersWithUrls });

    res.json({
      success: true,
      message: 'Consultance member added successfully',
      member
    });
  } catch (error) {
    console.error('Error adding consultance member:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update consultance member (admin only)
app.put('/api/consultance/:id', authenticateToken, requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { id } = req.params;

    // Get existing member
    const getMember = db.prepare('SELECT * FROM consultance WHERE id = ?');
    const existing = await getMember.get(parseInt(id));

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: 'Consultance member not found'
      });
    }

    // Handle file upload or URL - uploads to Cloudinary if configured
    const imageUrlFromUpload = await handleFileOrUrl(req, 'acdc-images/consultance');
    const { image } = req.body || {};
    const finalImageUrl = imageUrlFromUpload || (image !== undefined ? image : existing.image);


    // Delete old file if it's being replaced with a new one
    if (imageUrlFromUpload && existing.image && existing.image !== finalImageUrl) {
      await deleteFileIfExists(existing.image);
    }

    // Get other fields from request body
    const { name, title, display_order, facebook_url, instagram_url, twitter_url, linkedin_url } = req.body;

    // Trim name and title if provided
    const trimmedName = name ? name.trim() : existing.name;
    const trimmedTitle = title ? title.trim() : existing.title;
    const updateConsultance = db.prepare(`
      UPDATE consultance 
      SET name = ?, title = ?, image = ?, 
          facebook_url = ?, instagram_url = ?, twitter_url = ?, linkedin_url = ?,
          display_order = ?, 
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `);

    updateConsultance.run(
      trimmedName,
      trimmedTitle,
      finalImageUrl,
      facebook_url !== undefined ? facebook_url : existing.facebook_url,
      instagram_url !== undefined ? instagram_url : existing.instagram_url,
      twitter_url !== undefined ? twitter_url : existing.twitter_url,
      linkedin_url !== undefined ? linkedin_url : existing.linkedin_url,
      display_order !== undefined ? parseInt(display_order) : existing.display_order,
      req.user.id,
      parseInt(id)
    );

    res.json({
      success: true,
      message: 'Consultance member updated successfully'
    });

    // Emit Socket.IO event for live update
    // Get all members to send updated list
    const getConsultance = db.prepare('SELECT * FROM consultance ORDER BY display_order ASC, id ASC');
    const allMembers = await getConsultance.all();
    const membersWithUrls = allMembers.map(m => ({
      ...m,
      imageUrl: m.image ? getFileUrl(m.image) : null
    }));

    emitUpdate('consultance:updated', { action: 'updated', members: membersWithUrls });
  } catch (error) {
    console.error('Error updating consultance member:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete consultance member (admin only)
app.delete('/api/consultance/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get member to check if image needs to be deleted
    const getMember = db.prepare('SELECT * FROM consultance WHERE id = ?');
    const member = await getMember.get(parseInt(id));

    if (!member) {
      return res.status(404).json({
        success: false,
        message: 'Consultance member not found'
      });
    }

    // Delete image file if exists
    await deleteFileIfExists(member.image);

    // Delete member from database
    const deleteConsultance = db.prepare('DELETE FROM consultance WHERE id = ?');
    const deleteResult = await deleteConsultance.run(parseInt(id));

    // Verify deletion was successful
    if (deleteResult.changes === 0) {
      return res.status(404).json({
        success: false,
        message: 'Consultance member not found or already deleted'
      });
    }

    // Get all remaining members to send updated list
    const getConsultance = db.prepare('SELECT * FROM consultance ORDER BY display_order ASC, id ASC');
    const allMembers = await getConsultance.all();
    const membersWithUrls = allMembers.map(m => ({
      ...m,
      imageUrl: m.image ? getFileUrl(m.image) : null
    }));

    emitUpdate('consultance:updated', { action: 'deleted', members: membersWithUrls });

    res.json({
      success: true,
      message: 'Consultance member deleted successfully',
      deletedId: parseInt(id)
    });
  } catch (error) {
    console.error('Error deleting consultance member:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get all services - Optimized for fast response
app.get('/api/services', async (req, res) => {
  try {
    // Disable caching to ensure fresh data after deletions/updates
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const getServices = db.prepare('SELECT * FROM services ORDER BY id ASC');
    const services = await getServices.all();

    // Optimize: Only process URLs if data exists, avoid unnecessary function calls
    const servicesWithUrls = services.map(service => {
      const result = {
        id: service.id,
        title: service.title,
        shortDescription: service.short_description || null,
        description: service.description,
        backgroundImage: null,
        serviceImage: null,
        icon: null,
        keyFeatures: service.key_features || null
      };

      // Only call getFileUrl if data exists (faster)
      if (service.background_image) {
        result.backgroundImage = getFileUrl(service.background_image, req);
      }
      if (service.service_image) {
        result.serviceImage = getFileUrl(service.service_image, req);
      }
      if (service.icon) {
        result.icon = getFileUrl(service.icon, req);
      }

      return result;
    });

    res.json({
      success: true,
      services: servicesWithUrls
    });
  } catch (error) {
    console.error('Error fetching services:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new service (admin only)
app.post('/api/services', authenticateToken, requireAdmin, upload.fields([{ name: 'backgroundImage', maxCount: 1 }, { name: 'serviceImage', maxCount: 1 }, { name: 'icon', maxCount: 1 }]), async (req, res) => {
  try {
    const { title, shortDescription, description, backgroundImage, serviceImage, icon, keyFeatures } = req.body;

    if (!title || !description) {
      return res.status(400).json({
        success: false,
        message: 'Title and description are required'
      });
    }

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['backgroundImage', 'serviceImage', 'icon'], 'acdc-images/services');
    const backgroundImageUrl = files.backgroundImage || backgroundImage || null;
    const serviceImageUrl = files.serviceImage || serviceImage || null;
    const iconUrl = files.icon || icon || null;


    const insertService = db.prepare(`
      INSERT INTO services (title, short_description, description, background_image, service_image, icon, key_features, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertService.run(
      title,
      shortDescription || null,
      description,
      backgroundImageUrl,
      serviceImageUrl,
      iconUrl,
      keyFeatures || null,
      req.user.id,
      req.user.id
    );

    const service = {
      id: result.lastInsertRowid,
      title,
      shortDescription: shortDescription || null,
      description,
      backgroundImage: getFileUrl(backgroundImageUrl),
      serviceImage: getFileUrl(serviceImageUrl),
      icon: getFileUrl(iconUrl),
      keyFeatures: keyFeatures || null
    };

    // Get all services to send updated list
    const getServices = db.prepare('SELECT * FROM services ORDER BY id ASC');
    const allServices = await getServices.all();
    const servicesWithUrls = allServices.map(s => ({
      id: s.id,
      title: s.title,
      shortDescription: s.short_description || null,
      description: s.description,
      backgroundImage: s.background_image ? getFileUrl(s.background_image) : null,
      serviceImage: s.service_image ? getFileUrl(s.service_image) : null,
      icon: s.icon ? getFileUrl(s.icon) : null,
      keyFeatures: s.key_features || null
    }));

    emitUpdate('services:updated', { action: 'added', services: servicesWithUrls });

    res.json({
      success: true,
      message: 'Service added successfully',
      service
    });
  } catch (error) {
    console.error('Error adding service:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update service (admin only)
app.put('/api/services/:id', authenticateToken, requireAdmin, upload.fields([{ name: 'backgroundImage', maxCount: 1 }, { name: 'serviceImage', maxCount: 1 }, { name: 'icon', maxCount: 1 }]), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, shortDescription, description, backgroundImage, serviceImage, icon, keyFeatures } = req.body;

    // Get existing service
    const getService = db.prepare('SELECT * FROM services WHERE id = ?');
    const existing = await getService.get(parseInt(id));

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: 'Service not found'
      });
    }

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['backgroundImage', 'serviceImage', 'icon'], 'acdc-images/services');


    // Handle background image: new file, explicit removal (empty string), or keep existing
    let backgroundImageUrl;
    if (files.backgroundImage) {
      // New file uploaded
      backgroundImageUrl = files.backgroundImage;
      // Delete old file if it exists and is different
      if (existing.background_image && existing.background_image !== backgroundImageUrl) {
        await deleteFileIfExists(existing.background_image);
      }
    } else if (backgroundImage !== undefined) {
      // Explicit value provided (could be empty string for removal)
      if (backgroundImage === '' || backgroundImage === null) {
        // Explicit removal - delete old file and set to null
        if (existing.background_image) {
          await deleteFileIfExists(existing.background_image);
        }
        backgroundImageUrl = null;
      } else {
        backgroundImageUrl = backgroundImage;
      }
    } else {
      // Keep existing
      backgroundImageUrl = existing.background_image;
    }

    // Handle service image: new file, explicit removal (empty string), or keep existing
    let serviceImageUrl;
    if (files.serviceImage) {
      // New file uploaded
      serviceImageUrl = files.serviceImage;
      // Delete old file if it exists and is different
      if (existing.service_image && existing.service_image !== serviceImageUrl) {
        await deleteFileIfExists(existing.service_image);
      }
    } else if (serviceImage !== undefined) {
      // Explicit value provided (could be empty string for removal)
      if (serviceImage === '' || serviceImage === null) {
        // Explicit removal - delete old file and set to null
        if (existing.service_image) {
          await deleteFileIfExists(existing.service_image);
        }
        serviceImageUrl = null;
      } else {
        serviceImageUrl = serviceImage;
      }
    } else {
      // Keep existing
      serviceImageUrl = existing.service_image;
    }

    // Handle icon: new file, explicit removal (empty string), or keep existing
    let iconUrl;
    if (files.icon) {
      // New file uploaded
      iconUrl = files.icon;
      // Delete old file if it exists and is different
      if (existing.icon && existing.icon !== iconUrl) {
        await deleteFileIfExists(existing.icon);
      }
    } else if (icon !== undefined) {
      // Explicit value provided (could be empty string for removal)
      if (icon === '' || icon === null) {
        // Explicit removal - delete old file and set to null
        if (existing.icon) {
          await deleteFileIfExists(existing.icon);
        }
        iconUrl = null;
      } else {
        iconUrl = icon;
      }
    } else {
      // Keep existing
      iconUrl = existing.icon;
    }

    const updateService = db.prepare(`
      UPDATE services 
      SET title = ?, short_description = ?, description = ?, background_image = ?, service_image = ?, icon = ?, key_features = ?,
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `);

    updateService.run(
      title || existing.title,
      shortDescription !== undefined ? shortDescription : existing.short_description,
      description || existing.description,
      backgroundImageUrl,
      serviceImageUrl,
      iconUrl,
      keyFeatures !== undefined ? keyFeatures : existing.key_features,
      req.user.id,
      parseInt(id)
    );

    // Get all services to send updated list
    const getServices = db.prepare('SELECT * FROM services ORDER BY id ASC');
    const allServices = await getServices.all();
    const servicesWithUrls = allServices.map(s => ({
      id: s.id,
      title: s.title,
      shortDescription: s.short_description || null,
      description: s.description,
      backgroundImage: s.background_image ? getFileUrl(s.background_image) : null,
      serviceImage: s.service_image ? getFileUrl(s.service_image) : null,
      icon: s.icon ? getFileUrl(s.icon) : null,
      keyFeatures: s.key_features || null
    }));

    emitUpdate('services:updated', { action: 'updated', services: servicesWithUrls });

    res.json({
      success: true,
      message: 'Service updated successfully'
    });
  } catch (error) {
    console.error('Error updating service:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete service (admin only)
app.delete('/api/services/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get service to check if image needs to be deleted
    const getService = db.prepare('SELECT * FROM services WHERE id = ?');
    const service = await getService.get(parseInt(id));

    if (!service) {
      return res.status(404).json({
        success: false,
        message: 'Service not found'
      });
    }

    // Delete files from disk/Cloudinary if they exist
    await deleteFileIfExists(service.background_image);
    await deleteFileIfExists(service.service_image);
    await deleteFileIfExists(service.icon);

    // Delete service from database
    const deleteService = db.prepare('DELETE FROM services WHERE id = ?');
    const deleteResult = await deleteService.run(parseInt(id));

    // Verify deletion was successful
    if (deleteResult.changes === 0) {
      return res.status(404).json({
        success: false,
        message: 'Service not found or already deleted'
      });
    }

    // Get all remaining services to send updated list
    const getServices = db.prepare('SELECT * FROM services ORDER BY id ASC');
    const allServices = await getServices.all();
    const servicesWithUrls = allServices.map(s => ({
      id: s.id,
      title: s.title,
      description: s.description,
      backgroundImage: s.background_image ? getFileUrl(s.background_image) : null,
      serviceImage: s.service_image ? getFileUrl(s.service_image) : null
    }));

    emitUpdate('services:updated', { action: 'deleted', services: servicesWithUrls });

    res.json({
      success: true,
      message: 'Service deleted successfully',
      deletedId: parseInt(id)
    });
  } catch (error) {
    console.error('Error deleting service:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get all products - Optimized for fast response
app.get('/api/products', async (req, res) => {
  try {
    // Disable caching to ensure fresh data after deletions/updates
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    // Ensure applications column exists before querying
    await safeAddColumn('products', 'applications', 'TEXT');

    const getProducts = db.prepare('SELECT * FROM products ORDER BY id ASC');
    const products = await getProducts.all();

    // Optimize: Only process URLs if data exists, avoid unnecessary function calls
    const productsWithUrls = products.map(product => {
      const result = {
        id: product.id,
        title: product.title,
        description: product.description,
        image: null,
        icon: null,
        backgroundImage: null,
        whyItMatters: product.why_it_matters || '',
        keyFeatures: (() => {
          try {
            return product.key_features ? JSON.parse(product.key_features) : [];
          } catch (e) {
            // If JSON parsing fails, return as array with the string value
            return product.key_features ? [product.key_features] : [];
          }
        })(),
        applications: (() => {
          try {
            return (product.applications && product.applications.trim() !== '') ? JSON.parse(product.applications) : [];
          } catch (e) {
            // If JSON parsing fails, return as array with the string value
            return product.applications && product.applications.trim() !== '' ? [product.applications] : [];
          }
        })(),
        buttonText: product.button_text || 'Book a Free Consultation'
      };

      // Only call getFileUrl if data exists (faster)
      if (product.image) {
        result.image = getFileUrl(product.image, req);
      }
      if (product.icon) {
        result.icon = getFileUrl(product.icon, req);
      }
      if (product.background_image) {
        result.backgroundImage = getFileUrl(product.background_image, req);
      }

      return result;
    });

    res.json({
      success: true,
      products: productsWithUrls
    });
  } catch (error) {
    console.error('Error fetching products:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new product (admin only)
app.post('/api/products', authenticateToken, requireAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'icon', maxCount: 1 }, { name: 'backgroundImage', maxCount: 1 }]), async (req, res) => {
  try {
    console.log('📦 Received product creation request');
    console.log('Files received:', req.files ? Object.keys(req.files) : 'none');
    console.log('Body fields:', Object.keys(req.body || {}));
    
    const { title, description, whyItMatters, keyFeatures, applications, buttonText, image, icon, backgroundImage } = req.body;

    // Validate required fields
    if (!title || title.trim() === '') {
      return res.status(400).json({
        success: false,
        message: 'Title is required'
      });
    }

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['image', 'icon', 'backgroundImage'], 'acdc-images/products');
    const imageUrl = files.image || image || null;
    const iconUrl = files.icon || icon || null;
    const backgroundImageUrl = files.backgroundImage || backgroundImage || null;


    // Parse keyFeatures and applications from JSON strings (FormData sends them as strings)
    let keyFeaturesJson = JSON.stringify([]);
    let applicationsJson = JSON.stringify([]);

    try {
      if (keyFeatures) {
        const parsed = typeof keyFeatures === 'string' ? JSON.parse(keyFeatures) : keyFeatures;
        keyFeaturesJson = JSON.stringify(Array.isArray(parsed) ? parsed : []);
      }
    } catch (e) {
      console.error('Error parsing keyFeatures:', e);
      keyFeaturesJson = JSON.stringify([]);
    }

    try {
      if (applications) {
        const parsed = typeof applications === 'string' ? JSON.parse(applications) : applications;
        applicationsJson = JSON.stringify(Array.isArray(parsed) ? parsed : []);
      }
    } catch (e) {
      console.error('Error parsing applications:', e);
      applicationsJson = JSON.stringify([]);
    }

    // Ensure icon, applications, and background_image columns exist, if not add them
    await safeAddColumn('products', 'icon', 'TEXT');
    await safeAddColumn('products', 'applications', 'TEXT');
    await safeAddColumn('products', 'background_image', 'TEXT');

    // Log applications data for debugging
    console.log('Creating product with applications:', applicationsJson);
    console.log('Product data:', {
      title,
      description,
      whyItMatters,
      keyFeaturesJson,
      applicationsJson,
      imageUrl,
      iconUrl,
      userId: req.user.id
    });

    // Ensure all required columns exist
    await safeAddColumn('products', 'why_it_matters', 'TEXT');
    await safeAddColumn('products', 'key_features', 'TEXT');
    await safeAddColumn('products', 'button_text', 'TEXT');
    await safeAddColumn('products', 'icon', 'TEXT');
    await safeAddColumn('products', 'applications', 'TEXT');
    await safeAddColumn('products', 'background_image', 'TEXT');

    console.log('💾 Inserting product with background_image:', backgroundImageUrl ? `Yes (${backgroundImageUrl.substring(0, 50)}...)` : 'No');
    console.log('📋 Insert values:', {
      title: title.trim(),
      imageUrl: imageUrl ? 'provided' : 'null',
      iconUrl: iconUrl ? 'provided' : 'null',
      backgroundImageUrl: backgroundImageUrl ? 'provided' : 'null'
    });

    const insertProduct = db.prepare(`
      INSERT INTO products (title, description, image, icon, background_image, why_it_matters, key_features, applications, button_text, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertProduct.run(
      title.trim(),
      description ? description.trim() : '',
      imageUrl,
      iconUrl,
      backgroundImageUrl,
      whyItMatters ? whyItMatters.trim() : '',
      keyFeaturesJson,
      applicationsJson,
      buttonText || 'Book a Free Consultation',
      req.user.id,
      req.user.id
    );

    console.log('✅ Product inserted with ID:', result.lastInsertRowid);

    const product = {
      id: result.lastInsertRowid,
      title,
      description,
      image: getFileUrl(imageUrl),
      icon: getFileUrl(iconUrl),
      backgroundImage: getFileUrl(backgroundImageUrl),
      whyItMatters: whyItMatters || '',
      keyFeatures: JSON.parse(keyFeaturesJson),
      applications: JSON.parse(applicationsJson),
      buttonText: buttonText || 'Book a Free Consultation'
    };

    // Get all products to send updated list
    const getProducts = db.prepare('SELECT * FROM products ORDER BY id ASC');
    const allProducts = await getProducts.all();
    const productsWithUrls = allProducts.map(p => ({
      id: p.id,
      title: p.title,
      description: p.description,
      image: p.image ? getFileUrl(p.image) : null,
      icon: p.icon ? getFileUrl(p.icon) : null,
      backgroundImage: p.background_image ? getFileUrl(p.background_image) : null,
      whyItMatters: p.why_it_matters || '',
      keyFeatures: p.key_features ? JSON.parse(p.key_features) : [],
      applications: p.applications ? JSON.parse(p.applications) : [],
      buttonText: p.button_text || 'Book a Free Consultation'
    }));

    emitUpdate('products:updated', { action: 'added', products: productsWithUrls });

    res.json({
      success: true,
      message: 'Product added successfully',
      product
    });
  } catch (error) {
    console.error('Error adding product:', error);
    console.error('Error details:', {
      message: error.message,
      stack: error.stack,
      body: req.body
    });
    res.status(500).json({
      success: false,
      message: error.message || 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Update product (admin only)
app.put('/api/products/:id', authenticateToken, requireAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'icon', maxCount: 1 }, { name: 'backgroundImage', maxCount: 1 }]), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, whyItMatters, keyFeatures, applications, buttonText, image, icon, backgroundImage } = req.body;

    // Get existing product
    const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
    const existing = await getProduct.get(parseInt(id));

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Parse keyFeatures and applications from JSON strings (FormData sends them as strings)
    let keyFeaturesJson = existing.key_features || JSON.stringify([]);
    let applicationsJson = existing.applications || JSON.stringify([]);

    try {
      if (keyFeatures !== undefined) {
        const parsed = typeof keyFeatures === 'string' ? JSON.parse(keyFeatures) : keyFeatures;
        keyFeaturesJson = JSON.stringify(Array.isArray(parsed) ? parsed : []);
      }
    } catch (e) {
      console.error('Error parsing keyFeatures:', e);
      // Keep existing value on error
    }

    try {
      if (applications !== undefined) {
        const parsed = typeof applications === 'string' ? JSON.parse(applications) : applications;
        applicationsJson = JSON.stringify(Array.isArray(parsed) ? parsed : []);
      }
    } catch (e) {
      console.error('Error parsing applications:', e);
      // Keep existing value on error
    }

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['image', 'icon', 'backgroundImage'], 'acdc-images/products');
    const imageUrl = files.image || (image !== undefined ? image : existing.image);
    const iconUrl = files.icon || (icon !== undefined ? icon : existing.icon);
    const backgroundImageUrl = files.backgroundImage || (backgroundImage !== undefined ? backgroundImage : existing.background_image);


    // Delete old files if they're being replaced with new ones
    if (files.image && existing.image && existing.image !== imageUrl) {
      await deleteFileIfExists(existing.image);
    }
    if (files.icon && existing.icon && existing.icon !== iconUrl) {
      await deleteFileIfExists(existing.icon);
    }
    if (files.backgroundImage && existing.background_image && existing.background_image !== backgroundImageUrl) {
      await deleteFileIfExists(existing.background_image);
    }

    // Ensure icon, applications, and background_image columns exist, if not add them
    await safeAddColumn('products', 'icon', 'TEXT');
    await safeAddColumn('products', 'applications', 'TEXT');
    await safeAddColumn('products', 'background_image', 'TEXT');

    // Log applications data for debugging
    console.log('Updating product with applications:', applicationsJson);

    const updateProduct = db.prepare(`
      UPDATE products 
      SET title = ?, description = ?, image = ?, icon = ?, background_image = ?, why_it_matters = ?, key_features = ?, applications = ?, button_text = ?,
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `);

    updateProduct.run(
      title || existing.title,
      description || existing.description,
      imageUrl,
      iconUrl,
      backgroundImageUrl,
      whyItMatters !== undefined ? whyItMatters : existing.why_it_matters,
      keyFeaturesJson,
      applicationsJson,
      buttonText !== undefined ? buttonText : existing.button_text,
      req.user.id,
      parseInt(id)
    );

    // Get all products to send updated list
    const getProducts = db.prepare('SELECT * FROM products ORDER BY id ASC');
    const allProducts = await getProducts.all();
    const productsWithUrls = allProducts.map(p => ({
      id: p.id,
      title: p.title,
      description: p.description,
      image: p.image ? getFileUrl(p.image) : null,
      icon: p.icon ? getFileUrl(p.icon) : null,
      backgroundImage: p.background_image ? getFileUrl(p.background_image) : null,
      whyItMatters: p.why_it_matters || '',
      keyFeatures: p.key_features ? JSON.parse(p.key_features) : [],
      applications: p.applications ? JSON.parse(p.applications) : [],
      buttonText: p.button_text || 'Book a Free Consultation'
    }));

    emitUpdate('products:updated', { action: 'updated', products: productsWithUrls });

    res.json({
      success: true,
      message: 'Product updated successfully'
    });
  } catch (error) {
    console.error('Error updating product:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete product (admin only)
app.delete('/api/products/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get product to check if image needs to be deleted
    const getProduct = db.prepare('SELECT * FROM products WHERE id = ?');
    const product = await getProduct.get(parseInt(id));

    if (!product) {
      return res.status(404).json({
        success: false,
        message: 'Product not found'
      });
    }

    // Delete files from disk/Cloudinary if they exist
    await deleteFileIfExists(product.image);
    await deleteFileIfExists(product.icon);

    // Delete product from database
    const deleteProduct = db.prepare('DELETE FROM products WHERE id = ?');
    const deleteResult = await deleteProduct.run(parseInt(id));

    // Verify deletion was successful
    if (deleteResult.changes === 0) {
      return res.status(404).json({
        success: false,
        message: 'Product not found or already deleted'
      });
    }

    // Get all remaining products to send updated list
    const getProducts = db.prepare('SELECT * FROM products ORDER BY id ASC');
    const allProducts = await getProducts.all();
    const productsWithUrls = allProducts.map(p => ({
      id: p.id,
      title: p.title,
      description: p.description,
      image: p.image ? `getFileUrl(p.image)` : null,
      whyItMatters: p.why_it_matters || '',
      keyFeatures: p.key_features ? JSON.parse(p.key_features) : [],
      buttonText: p.button_text || 'Book a Free Consultation'
    }));

    emitUpdate('products:updated', { action: 'deleted', products: productsWithUrls });

    res.json({
      success: true,
      message: 'Product deleted successfully',
      deletedId: parseInt(id)
    });
  } catch (error) {
    console.error('Error deleting product:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get all blogs - Optimized for fast response
app.get('/api/blogs', async (req, res) => {
  try {
    // Disable caching to ensure fresh data after deletions/updates
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    const getBlogs = db.prepare('SELECT * FROM blogs ORDER BY id DESC');
    const blogs = await getBlogs.all();

    // Optimize: Only process URLs if data exists, avoid unnecessary function calls
    const blogsWithUrls = blogs.map(blog => {
      const result = {
        id: blog.id,
        title: blog.title,
        description: blog.description,
        image: null,
        video: null,
        youtube_url: blog.youtube_url || null,
        date: blog.date || '',
        location: blog.location || ''
      };

      // Only call getFileUrl if data exists (faster)
      if (blog.image) {
        result.image = getFileUrl(blog.image, req);
      }
      if (blog.video) {
        result.video = getFileUrl(blog.video, req);
      }

      return result;
    });

    res.json({
      success: true,
      blogs: blogsWithUrls
    });
  } catch (error) {
    console.error('Error fetching blogs:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new blog (admin only)
app.post('/api/blogs', authenticateToken, requireAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
  try {
    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['image', 'video'], 'acdc-images/blogs');
    let imageUrl = files.image || null;
    let videoUrl = files.video || null;


    // Get all fields from request body (multer parses FormData text fields into req.body)
    const { title, description, date, location, youtube_url, image, video } = req.body || {};

    // If no files were uploaded, use URLs from request body
    if (!imageUrl) {
      imageUrl = image || null;
    }
    if (!videoUrl) {
      videoUrl = video || null;
    }

    // Trim and validate title and description
    const trimmedTitle = title ? title.trim() : '';
    const trimmedDescription = description ? description.trim() : '';

    if (!trimmedTitle || !trimmedDescription) {
      return res.status(400).json({
        success: false,
        message: 'Title and description are required'
      });
    }

    const insertBlog = db.prepare(`
      INSERT INTO blogs (title, description, image, video, youtube_url, date, location, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertBlog.run(
      trimmedTitle,
      trimmedDescription,
      imageUrl,
      videoUrl,
      youtube_url || null,
      date || new Date().toISOString().split('T')[0],
      location || '',
      req.user.id,
      req.user.id
    );

    const blog = {
      id: result.lastInsertRowid,
      title: trimmedTitle,
      description: trimmedDescription,
      image: getFileUrl(imageUrl),
      video: getFileUrl(videoUrl),
      youtube_url: youtube_url || null,
      date: date || new Date().toISOString().split('T')[0],
      location: location || ''
    };

    // Get all blogs to send updated list
    const getBlogs = db.prepare('SELECT * FROM blogs ORDER BY id DESC');
    const allBlogs = await getBlogs.all();
    const blogsWithUrls = allBlogs.map(b => ({
      id: b.id,
      title: b.title,
      description: b.description,
      image: b.image ? getFileUrl(b.image) : null,
      video: b.video ? getFileUrl(b.video) : null,
      youtube_url: b.youtube_url || null,
      date: b.date || '',
      location: b.location || ''
    }));

    emitUpdate('blogs:updated', { action: 'added', blogs: blogsWithUrls });

    res.json({
      success: true,
      message: 'Blog added successfully',
      blog
    });
  } catch (error) {
    console.error('Error adding blog:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update blog (admin only)
app.put('/api/blogs/:id', authenticateToken, requireAdmin, upload.fields([{ name: 'image', maxCount: 1 }, { name: 'video', maxCount: 1 }]), async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description, date, location, youtube_url, image, video } = req.body;

    // Get existing blog
    const getBlog = db.prepare('SELECT * FROM blogs WHERE id = ?');
    const existing = await getBlog.get(parseInt(id));

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: 'Blog not found'
      });
    }

    // Handle file uploads or URLs - uploads to Cloudinary if configured
    const files = await handleFilesOrUrls(req, ['image', 'video'], 'acdc-images/blogs');
    const imageUrl = files.image || (image !== undefined ? image : existing.image);
    const videoUrl = files.video || (video !== undefined ? video : existing.video);


    // Delete old files if they're being replaced with new ones
    if (files.image && existing.image && existing.image !== imageUrl) {
      await deleteFileIfExists(existing.image);
    }
    if (files.video && existing.video && existing.video !== videoUrl) {
      await deleteFileIfExists(existing.video);
    }

    const updateBlog = db.prepare(`
      UPDATE blogs 
      SET title = ?, description = ?, image = ?, video = ?, youtube_url = ?, date = ?, location = ?,
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `);

    await updateBlog.run(
      title || existing.title,
      description || existing.description,
      imageUrl,
      videoUrl,
      youtube_url !== undefined ? (youtube_url || null) : existing.youtube_url,
      date !== undefined ? date : existing.date,
      location !== undefined ? location : existing.location,
      req.user.id,
      parseInt(id)
    );

    // Get all blogs to send updated list
    const getBlogs = db.prepare('SELECT * FROM blogs ORDER BY id DESC');
    const allBlogs = await getBlogs.all();
    const blogsWithUrls = allBlogs.map(b => ({
      id: b.id,
      title: b.title,
      description: b.description,
      image: b.image ? `getFileUrl(b.image)` : null,
      video: b.video ? `getFileUrl(b.video)` : null,
      youtube_url: b.youtube_url || null,
      date: b.date || '',
      location: b.location || ''
    }));

    emitUpdate('blogs:updated', { action: 'updated', blogs: blogsWithUrls });

    res.json({
      success: true,
      message: 'Blog updated successfully'
    });
  } catch (error) {
    console.error('Error updating blog:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete blog (admin only)
app.delete('/api/blogs/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get blog to check if image needs to be deleted
    const getBlog = db.prepare('SELECT * FROM blogs WHERE id = ?');
    const blog = await getBlog.get(parseInt(id));

    if (!blog) {
      return res.status(404).json({
        success: false,
        message: 'Blog not found'
      });
    }

    // Delete files from disk/Cloudinary if they exist
    await deleteFileIfExists(blog.image);
    await deleteFileIfExists(blog.video);

    // Delete blog from database
    const deleteBlog = db.prepare('DELETE FROM blogs WHERE id = ?');
    const deleteResult = await deleteBlog.run(parseInt(id));

    // Verify deletion was successful
    if (deleteResult.changes === 0) {
      return res.status(404).json({
        success: false,
        message: 'Blog not found or already deleted'
      });
    }

    // Get all remaining blogs to send updated list
    const getBlogs = db.prepare('SELECT * FROM blogs ORDER BY id DESC');
    const allBlogs = await getBlogs.all();
    const blogsWithUrls = allBlogs.map(b => {
      const result = {
        id: b.id,
        title: b.title,
        description: b.description,
        image: null,
        video: null,
        youtube_url: b.youtube_url || null,
        date: b.date || '',
        location: b.location || ''
      };

      // Only call getFileUrl if data exists (faster)
      if (b.image) {
        result.image = getFileUrl(b.image);
      }
      if (b.video) {
        result.video = getFileUrl(b.video);
      }

      return result;
    });

    emitUpdate('blogs:updated', { action: 'deleted', blogs: blogsWithUrls });

    res.json({
      success: true,
      message: 'Blog deleted successfully',
      deletedId: parseInt(id)
    });
  } catch (error) {
    console.error('Error deleting blog:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// ========== CAREER CONTENT ENDPOINTS ==========

// Get career content (public) - Optimized for fast response
app.get('/api/content/career', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('career');

    if (!content) {
      // Return default content
      return res.json({
        success: true,
        content: {
          title: 'Empowered by Purpose. United by Mission.',
          subtitle: 'When you join ACDC Tech, you\'re not just stepping into a job— you\'re stepping into a mission-driven company where purpose is at the heart of everything we do.',
          description: 'Our mission—to empower every person and every organization on the planet to achieve more—isn\'t just words. It\'s our foundation. It\'s what sets us apart.',
          sectionTitle: 'Open Positions',
          sectionDescription: 'Explore exciting career opportunities and be part of our innovative journey',
          videoUrl: null
        }
      });
    }

    // Parse JSON content if stored as JSON string
    let contentData = {};
    try {
      if (typeof content.subtitle === 'string' && content.subtitle.startsWith('{')) {
        contentData = JSON.parse(content.subtitle);
      } else {
        // Legacy format - convert to new format
        contentData = {
          title: content.title || 'Empowered by Purpose. United by Mission.',
          subtitle: content.subtitle || 'When you join ACDC Tech, you\'re not just stepping into a job— you\'re stepping into a mission-driven company where purpose is at the heart of everything we do.',
          description: content.description || 'Our mission—to empower every person and every organization on the planet to achieve more—isn\'t just words. It\'s our foundation. It\'s what sets us apart.',
          sectionTitle: content.button_text || 'Open Positions',
          sectionDescription: content.description || 'Explore exciting career opportunities and be part of our innovative journey',
          videoUrl: null
        };
      }
      // Ensure videoUrl exists
      if (!contentData.videoUrl) {
        contentData.videoUrl = null;
      }
    } catch (e) {
      contentData = {
        title: content.title || 'Empowered by Purpose. United by Mission.',
        subtitle: content.subtitle || 'When you join ACDC Tech, you\'re not just stepping into a job— you\'re stepping into a mission-driven company where purpose is at the heart of everything we do.',
        description: content.description || 'Our mission—to empower every person and every organization on the planet to achieve more—isn\'t just words. It\'s our foundation. It\'s what sets us apart.',
        sectionTitle: content.button_text || 'Open Positions',
        sectionDescription: content.description || 'Explore exciting career opportunities and be part of our innovative journey',
        videoUrl: null
      };
    }

    res.json({
      success: true,
      content: contentData
    });
  } catch (error) {
    console.error('Error fetching career content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update career content (admin only)
app.put('/api/content/career', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { title, subtitle, description, sectionTitle, sectionDescription, videoUrl } = req.body;

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await getContent.get('career');

    const contentData = {
      title: title || 'Empowered by Purpose. United by Mission.',
      subtitle: subtitle || '',
      description: description || '',
      sectionTitle: sectionTitle || 'Open Positions',
      sectionDescription: sectionDescription || '',
      videoUrl: videoUrl || null
    };

    // Store videoUrl in subtitle as JSON if needed, or use a separate approach
    // For now, we'll store all content as JSON in subtitle field for flexibility
    const contentJson = JSON.stringify(contentData);

    if (existing) {
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, description = ?, button_text = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(
        contentData.title,
        contentJson,
        contentData.description,
        contentData.sectionTitle,
        req.user.id,
        'career'
      );
    } else {
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, description, button_text, updated_by)
        VALUES (?, ?, ?, ?, ?, ?)
      `);
      await insertContent.run(
        'career',
        contentData.title,
        contentJson,
        contentData.description,
        contentData.sectionTitle,
        req.user.id
      );
    }

    emitUpdate('career:content:updated', { content: contentData });

    res.json({
      success: true,
      message: 'Career content updated successfully',
      content: contentData
    });
  } catch (error) {
    console.error('Error updating career content:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// ========== POSITIONS ENDPOINTS ==========

// Get all positions (public) - Only active positions - Optimized for fast response
app.get('/api/positions', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    // Only return active positions for public endpoint
    // Handle NULL values as active (for positions created before active column was added)
    const getPositions = db.prepare('SELECT * FROM positions WHERE (active = true OR active IS NULL) ORDER BY display_order ASC, id DESC');
    const positions = await getPositions.all();

    console.log(`Fetched ${positions.length} active positions from database`);

    res.json({
      success: true,
      positions: positions
    });
  } catch (error) {
    console.error('Error fetching positions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get all positions including inactive (admin only)
app.get('/api/positions/all', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const getPositions = db.prepare('SELECT * FROM positions ORDER BY display_order ASC, id DESC');
    const positions = await getPositions.all();

    res.json({
      success: true,
      positions: positions
    });
  } catch (error) {
    console.error('Error fetching all positions:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Add new position (admin only)
app.post('/api/positions', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { title, location, jobtype, positions_count, experience, skills_required, education, description } = req.body;

    if (!title || !jobtype) {
      return res.status(400).json({
        success: false,
        message: 'Title and jobtype are required'
      });
    }

    // Ensure location is always a string (not null or undefined) to satisfy NOT NULL constraint
    const locationValue = (location !== undefined && location !== null) ? String(location) : '';

    // Get max display_order
    const getMaxOrder = db.prepare('SELECT MAX(display_order) as max_order FROM positions');
    const maxOrder = await getMaxOrder.get();
    const nextOrder = (maxOrder?.max_order ?? -1) + 1;

    const insertPosition = db.prepare(`
      INSERT INTO positions (title, location, jobtype, positions_count, experience, skills_required, education, description, display_order, active, created_by, updated_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertPosition.run(
      title,
      locationValue,
      jobtype,
      positions_count || null,
      experience || null,
      skills_required || null,
      education || null,
      description || null,
      nextOrder,
      true, // active = true by default
      req.user.id,
      req.user.id
    );

    const position = {
      id: result.lastInsertRowid,
      title,
      location: locationValue,
      jobtype,
      positions_count: positions_count || null,
      experience: experience || null,
      skills_required: skills_required || null,
      education: education || null,
      description: description || null
    };

    // Get all positions to send updated list
    const getPositions = db.prepare('SELECT * FROM positions ORDER BY display_order ASC, id DESC');
    const allPositions = await getPositions.all();

    emitUpdate('positions:updated', { action: 'added', positions: allPositions });

    res.json({
      success: true,
      message: 'Position added successfully',
      position
    });
  } catch (error) {
    console.error('Error adding position:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update position (admin only)
app.put('/api/positions/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, location, jobtype, positions_count, experience, skills_required, education, description } = req.body;

    // Get existing position
    const getPosition = db.prepare('SELECT * FROM positions WHERE id = ?');
    const existing = await getPosition.get(parseInt(id));

    if (!existing) {
      return res.status(404).json({
        success: false,
        message: 'Position not found'
      });
    }

    const updatePosition = db.prepare(`
      UPDATE positions 
      SET title = ?, location = ?, jobtype = ?, positions_count = ?, experience = ?, skills_required = ?, education = ?, description = ?,
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `);

    // Ensure location is always a string (not null or undefined) to satisfy NOT NULL constraint
    const locationValue = location !== undefined
      ? ((location !== null) ? String(location) : '')
      : (existing.location || '');

    updatePosition.run(
      title !== undefined ? title : existing.title,
      locationValue,
      jobtype !== undefined ? jobtype : existing.jobtype,
      positions_count !== undefined ? (positions_count || null) : existing.positions_count,
      experience !== undefined ? (experience || null) : existing.experience,
      skills_required !== undefined ? (skills_required || null) : existing.skills_required,
      education !== undefined ? (education || null) : existing.education,
      description !== undefined ? (description || null) : existing.description,
      req.user.id,
      parseInt(id)
    );

    // Get all positions to send updated list
    const getPositions = db.prepare('SELECT * FROM positions ORDER BY display_order ASC, id DESC');
    const allPositions = await getPositions.all();

    emitUpdate('positions:updated', { action: 'updated', positions: allPositions });

    res.json({
      success: true,
      message: 'Position updated successfully'
    });
  } catch (error) {
    console.error('Error updating position:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Toggle position active/inactive status (admin only) - replaces delete
app.put('/api/positions/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { active } = req.body;

    // Get position to verify it exists
    const getPosition = db.prepare('SELECT * FROM positions WHERE id = ?');
    const position = await getPosition.get(parseInt(id));

    if (!position) {
      return res.status(404).json({
        success: false,
        message: 'Position not found'
      });
    }

    // Validate active status
    if (typeof active !== 'boolean') {
      return res.status(400).json({
        success: false,
        message: 'Active status must be a boolean value'
      });
    }

    // Update active status
    const updateStatus = db.prepare('UPDATE positions SET active = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE id = ?');
    await updateStatus.run(active, req.user.id, parseInt(id));

    // Get all positions to send updated list
    const getPositions = db.prepare('SELECT * FROM positions ORDER BY display_order ASC, id DESC');
    const allPositions = await getPositions.all();

    emitUpdate('positions:updated', { action: active ? 'activated' : 'deactivated', positions: allPositions });

    res.json({
      success: true,
      message: `Position ${active ? 'activated' : 'deactivated'} successfully`,
      position: { ...position, active }
    });
  } catch (error) {
    console.error('Error updating position status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});
// Submit job application - FIXED VERSION
app.post('/api/applications', upload.single('resume'), async (req, res) => {
  try {
    let resumePath = null;

    console.log('📝 Processing job application...');
    console.log('File received:', req.file ? {
      originalname: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      hasBuffer: !!req.file.buffer,
      bufferLength: req.file.buffer?.length
    } : 'No file');

    // Handle file upload - ALWAYS upload to Supabase Storage for resume (no Cloudinary fallback)
    if (req.file) {
      // Check if Supabase is configured - REQUIRED for resume uploads
      if (!isSupabaseConfigured()) {
        console.error('❌ Supabase not configured! resume must be stored in Supabase Storage.');
        console.error('   Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in environment variables');
        return res.status(500).json({
          success: false,
          message: 'Resume storage not configured. Please configure Supabase Storage.',
          error: 'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are required for resume uploads'
        });
      }

      try {
        // Validate file exists and has content
        if (!req.file.buffer) {
          throw new Error('File buffer is missing');
        }

        if (req.file.buffer.length === 0) {
          throw new Error('File buffer is empty (0 bytes)');
        }

        console.log(`📤 Preparing Supabase upload: ${req.file.size} bytes`);

        // Get first_name and last_name from request body for filename
        const firstName = (req.body?.first_name || '').trim().replace(/[^a-zA-Z0-9]/g, '_') || 'firstname';
        const lastName = (req.body?.last_name || '').trim().replace(/[^a-zA-Z0-9]/g, '_') || 'lastname';
        
        // Generate filename as firstname_lastname with original extension
        const originalName = req.file.originalname || 'resume';
        const ext = path.extname(originalName) || '.pdf';
        
        // Create filename: firstname_lastname.ext
        const filename = `${firstName}_${lastName}${ext}`;
        
        // Create file path in Supabase Storage: resume/firstname_lastname.ext
        const filePath = `resume/${filename}`;

        console.log(`📁 Upload filename: ${filePath}`);

        // Upload to Supabase Storage
        const supabaseResult = await uploadToSupabase(req.file.buffer, 'resume', filePath);
        
        // Store Supabase path in database (resume/firstname_lastname.ext)
        resumePath = supabaseResult.path;
        
        console.log(`✅ Resume uploaded to Supabase successfully`);
        console.log(`   Path: ${supabaseResult.path}`);
        console.log(`   URL: ${supabaseResult.url}`);
      } catch (error) {
        console.error('❌ Supabase upload failed:', error.message);
        console.error('   Stack:', error.stack);
        
        // Return detailed error to help debug
        return res.status(500).json({
          success: false,
          message: 'Failed to upload resume to Supabase Storage',
          error: error.message,
          details: process.env.NODE_ENV === 'development' ? {
            fileSize: req.file?.size,
            hasBuffer: !!req.file?.buffer,
            bufferLength: req.file?.buffer?.length,
            supabaseConfigured: isSupabaseConfigured(),
            supabaseUrl: process.env.SUPABASE_URL ? 'Set' : 'Missing',
            supabaseKey: process.env.SUPABASE_SERVICE_ROLE_KEY ? 'Set' : 'Missing'
          } : undefined
        });
      }
    } else {
      // Check for URL in request body (for backward compatibility)
      const { fileUrl } = req.body || {};
      if (fileUrl) {
        resumePath = fileUrl;
        console.log('📎 Using provided file URL:', fileUrl.substring(0, 50) + '...');
      } else {
        return res.status(400).json({
          success: false,
          message: 'Resume file is required'
        });
      }
    }

    // Get all fields from request body (multer parses FormData text fields into req.body)
    const { position_id, first_name, last_name, contact_number, email, about_yourself } = req.body || {};

    // Trim and validate required fields
    const trimmedFirstName = first_name ? first_name.trim() : '';
    const trimmedLastName = last_name ? last_name.trim() : '';
    const trimmedContactNumber = contact_number ? contact_number.trim() : '';
    const trimmedEmail = email ? email.trim() : '';
    const trimmedAboutYourself = about_yourself ? about_yourself.trim() : '';

    if (!position_id || !trimmedFirstName || !trimmedLastName || !trimmedContactNumber || !trimmedEmail || !trimmedAboutYourself) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Verify position exists
    const getPosition = db.prepare('SELECT * FROM positions WHERE id = ?');
    const position = await getPosition.get(parseInt(position_id));

    if (!position) {
      return res.status(404).json({
        success: false,
        message: 'Position not found'
      });
    }

    // Insert application with IST timestamp
    // Store Supabase path in resume_filename field
    const insertApplication = db.prepare(`
      INSERT INTO job_applications (position_id, first_name, last_name, contact_number, email, about_yourself, resume_filename, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = await insertApplication.run(
      parseInt(position_id),
      trimmedFirstName,
      trimmedLastName,
      trimmedContactNumber,
      trimmedEmail,
      trimmedAboutYourself,
      resumePath, // Store Supabase path (e.g., resume/firstname_lastname.pdf)
      getISTTimestamp()
    );

    console.log(`✅ Application submitted successfully (ID: ${result.lastInsertRowid})`);

    res.json({
      success: true,
      message: 'Application submitted successfully',
      applicationId: result.lastInsertRowid
    });
  } catch (error) {
    console.error('❌ Error submitting application:', error);
    console.error('   Stack:', error.stack);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: process.env.NODE_ENV === 'development' ? error.message : 'An error occurred while processing your application'
    });
  }
});
//Get all applications (admin only)
app.get('/api/applications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const getApplications = db.prepare(`
      SELECT 
        ja.*,
        p.title as position_title
      FROM job_applications ja
      LEFT JOIN positions p ON ja.position_id = p.id
      ORDER BY ja.created_at DESC
    `);

    const applications = await getApplications.all();
    console.log(`Fetched ${applications.length} applications from database`);

    // Process resume - handle Supabase paths, Dropbox paths, Cloudinary URLs, Base64, and local files
    const applicationsWithResumeUrls = await Promise.all(applications.map(async (app) => {
      let resumeUrl = null;
      if (app.resume_filename) {
        // Check if it's already a full URL (http/https)
        if (app.resume_filename.startsWith('http://') || app.resume_filename.startsWith('https://')) {
          // Already a URL, use it directly
          resumeUrl = app.resume_filename;
        }
        // Check if it's a Supabase path (starts with 'resume/')
        else if (isSupabaseConfigured() && app.resume_filename.startsWith('resume/')) {
          try {
            resumeUrl = getSupabaseUrl(app.resume_filename, 'resume');
            if (!resumeUrl) {
              throw new Error('Failed to get Supabase URL');
            }
          } catch (error) {
            console.error('Error getting Supabase URL:', error.message);
            // Fallback to API endpoint
            resumeUrl = `${getApiUrl()}/applications/${app.id}/resume`;
          }
        }
        // Check if it's a Dropbox path (starts with /) - for backward compatibility
        else if (isDropboxConfigured() && app.resume_filename.startsWith('/')) {
          try {
            const { getSharedLink } = require('./utils/dropbox');
            resumeUrl = await getSharedLink(app.resume_filename);
          } catch (error) {
            console.error('Error getting Dropbox shared link:', error.message);
            // Don't fallback to path - use API endpoint instead
            resumeUrl = `${getApiUrl()}/applications/${app.id}/resume`;
          }
        } else {
          // Use existing getFileUrl for Cloudinary URLs, Base64, or local files
          resumeUrl = getFileUrl(app.resume_filename, req);
        }
      }
      return {
        ...app,
        resume_url: resumeUrl
      };
    }));

    res.json({
      success: true,
      applications: applicationsWithResumeUrls
    });
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete application (admin only)
app.delete('/api/applications/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Get application to verify it exists
    const getApplication = db.prepare('SELECT * FROM job_applications WHERE id = ?');
    const application = await getApplication.get(parseInt(id));

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    // Delete resume file from storage (Supabase, Dropbox, Cloudinary, or local)
    if (application.resume_filename) {
      // Check if it's a Supabase path
      if (isSupabaseConfigured() && application.resume_filename.startsWith('resume/')) {
        try {
          await deleteFromSupabase(application.resume_filename, 'resume');
        } catch (error) {
          console.error('Error deleting resume from Supabase:', error);
          // Continue with deletion even if Supabase deletion fails
        }
      }
      // Check if it's a Dropbox path (for backward compatibility)
      else if (isDropboxConfigured() && application.resume_filename.startsWith('/')) {
        try {
          await deleteFromDropbox(application.resume_filename);
        } catch (error) {
          console.error('Error deleting resume from Dropbox:', error);
          // Continue with deletion even if Dropbox deletion fails
        }
      }
      // Check if it's a Cloudinary URL
      else if (application.resume_filename.includes('cloudinary.com')) {
        try {
          // deleteFromCloudinary handles URL extraction internally
          await deleteFromCloudinary(application.resume_filename);
        } catch (error) {
          console.error('Error deleting resume from Cloudinary:', error);
          // Continue with deletion even if Cloudinary deletion fails
        }
      }
      // Local files are handled by the file system cleanup (if needed)
    }

    // Delete application from database
    const deleteApplication = db.prepare('DELETE FROM job_applications WHERE id = ?');
    const deleteResult = await deleteApplication.run(parseInt(id));

    if (deleteResult.changes === 0) {
      return res.status(404).json({
        success: false,
        message: 'Application not found or already deleted'
      });
    }

    res.json({
      success: true,
      message: 'Application deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting application:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Update application status and notes (admin only)
app.put('/api/applications/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes } = req.body;

    if (!status || !['pending', 'accepted', 'rejected'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Valid status is required (pending, accepted, rejected)'
      });
    }

    // Get application to verify it exists
    const getApplication = db.prepare('SELECT * FROM job_applications WHERE id = ?');
    const application = await getApplication.get(parseInt(id));

    if (!application) {
      return res.status(404).json({
        success: false,
        message: 'Application not found'
      });
    }

    // Ensure status and notes columns exist
    await safeAddColumn('job_applications', 'status', 'TEXT DEFAULT "pending"');
    await safeAddColumn('job_applications', 'notes', 'TEXT');

    // Update status and notes (notes is optional)
    const updateStatus = db.prepare(`
      UPDATE job_applications
      SET status = ?, notes = ?
      WHERE id = ?
    `);

    await updateStatus.run(status, notes || null, parseInt(id));

    res.json({
      success: true,
      message: 'Status and notes updated successfully'
    });
  } catch (error) {
    console.error('Error updating application status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Get resume file for an application (admin only)
app.get('/api/applications/:id/resume', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { download } = req.query; // Check if download parameter is present
    const getApplication = db.prepare('SELECT resume_filename, first_name, last_name FROM job_applications WHERE id = ?');
    const application = await getApplication.get(parseInt(id));

    if (!application || !application.resume_filename) {
      return res.status(404).json({
        success: false,
        message: 'Resume not found'
      });
    }

    const resumeData = application.resume_filename;
    const firstName = application.first_name || 'firstname';
    const lastName = application.last_name || 'lastname';
    const downloadFilename = `${firstName}_${lastName}.pdf`;

    // Check if it's already a full URL (http/https)
    if (resumeData.startsWith('http://') || resumeData.startsWith('https://')) {
      // Validate it's not a folder URL
      if (resumeData.includes('/home/')) {
        return res.status(400).json({
          success: false,
          message: 'Invalid resume URL: folder URL detected'
        });
      }
      
      // If download is requested and it's a Supabase URL, download from Supabase Storage
      if (download === 'true' && resumeData.includes('supabase.co')) {
        try {
          // Extract the file path from Supabase URL
          // Supabase URLs format: https://project.supabase.co/storage/v1/object/public/bucket/path
          const urlMatch = resumeData.match(/\/storage\/v1\/object\/public\/([^\/]+)\/(.+)$/);
          if (urlMatch) {
            const bucketName = urlMatch[1];
            const filePath = decodeURIComponent(urlMatch[2]);
            
            // Download from Supabase Storage
            const { downloadFromSupabase } = require('./utils/supabase');
            const fileBuffer = await downloadFromSupabase(filePath, bucketName);
            
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
            res.send(fileBuffer);
            return;
          }
        } catch (error) {
          console.error('Error downloading from Supabase URL:', error.message);
          // Fallback to redirect with download header
        }
      }
      
      // If download is requested, set Content-Disposition header and redirect
      if (download === 'true') {
        res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
        return res.redirect(resumeData);
      }
      
      // Redirect directly to the URL (for viewing)
      return res.redirect(resumeData);
    }

    // Check if it's a Supabase path (starts with 'resume/')
    if (isSupabaseConfigured() && resumeData.startsWith('resume/')) {
      try {
        const { downloadFromSupabase } = require('./utils/supabase');
        
        // If download is requested, fetch file and serve with download headers
        if (download === 'true') {
          try {
            const fileBuffer = await downloadFromSupabase(resumeData, 'resume');
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
            res.send(fileBuffer);
            return;
          } catch (downloadError) {
            console.error('Error downloading from Supabase:', downloadError.message);
            // Fallback to redirect if download fails
            const supabaseUrl = getSupabaseUrl(resumeData, 'resume');
            if (supabaseUrl) {
              res.setHeader('Content-Disposition', `attachment; filename="${downloadFilename}"`);
              return res.redirect(supabaseUrl);
            }
            throw downloadError;
          }
        }
        
        // For viewing, get public URL and redirect
        const supabaseUrl = getSupabaseUrl(resumeData, 'resume');
        if (!supabaseUrl) {
          throw new Error('Failed to get Supabase URL');
        }
        
        // Redirect to Supabase public URL
        return res.redirect(supabaseUrl);
      } catch (error) {
        console.error('Error getting Supabase URL:', error.message);
        return res.status(500).json({
          success: false,
          message: 'Error accessing resume from Supabase: ' + error.message
        });
      }
    }

    // Check if it's a Dropbox path (starts with /) - for backward compatibility
    if (isDropboxConfigured() && resumeData.startsWith('/')) {
      try {
        const { getSharedLink } = require('./utils/dropbox');
        const dropboxUrl = await getSharedLink(resumeData);
        // Validate it's not a folder URL before redirecting
        if (dropboxUrl.includes('/home/')) {
          return res.status(500).json({
            success: false,
            message: 'Error: Got folder URL instead of file URL'
          });
        }
        // Redirect to Dropbox download URL
        return res.redirect(dropboxUrl);
      } catch (error) {
        console.error('Error getting Dropbox shared link:', error.message);
        return res.status(500).json({
          success: false,
          message: 'Error accessing resume from Dropbox: ' + error.message
        });
      }
    }

    // Check if it's a Base64 data URI
    if (resumeData.startsWith('data:')) {
      // Extract Base64 data and MIME type
      const matches = resumeData.match(/^data:([^;]+);base64,(.+)$/);
      if (matches) {
        const mimeType = matches[1];
        const base64Data = matches[2];
        const buffer = Buffer.from(base64Data, 'base64');

        res.setHeader('Content-Type', mimeType);
        res.setHeader('Content-Disposition', `inline; filename="resume-${id}.pdf"`);
        res.send(buffer);
        return;
      }
    }

    // Check if it's Base64 without data URI prefix
    if (resumeData.length > 100 && !resumeData.includes(' ') && !resumeData.includes('\n') && !resumeData.includes('/') && !resumeData.includes('\\')) {
      // Likely Base64 string, decode and serve as PDF
      try {
        const buffer = Buffer.from(resumeData, 'base64');
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="resume-${id}.pdf"`);
        res.send(buffer);
        return;
      } catch (error) {
        console.error('Error decoding Base64 resume:', error);
      }
    }

    // If it's a URL, redirect to it
    if (resumeData.startsWith('http://') || resumeData.startsWith('https://')) {
      return res.redirect(resumeData);
    }

    // Legacy filename - try to read from uploads directory
    try {
      const filePath = path.join(__dirname, 'uploads', 'resume', resumeData);
      if (fs.existsSync(filePath)) {
        const fileBuffer = fs.readFileSync(filePath);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="${resumeData}"`);
        res.send(fileBuffer);
        return;
      }
    } catch (error) {
      console.error('Error reading legacy resume file:', error);
    }

    res.status(404).json({
      success: false,
      message: 'Resume file not found'
    });
  } catch (error) {
    console.error('Error fetching resume:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Prepare statement once for better performance (reused across requests)
let insertContactMessage;
try {
  insertContactMessage = db.prepare(`
    INSERT INTO contact_messages (name, email, message)
    VALUES (?, ?, ?)
  `);
  console.log('Contact message insert statement prepared successfully');
} catch (error) {
  console.error('Error preparing contact message statement:', error);
}

// Helper function to retry database operations
const retryDbOperation = async (operation, maxRetries = 5, delay = 100) => {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await operation();
    } catch (error) {
      // PostgreSQL error codes: 40001 = serialization_failure, 40P01 = deadlock_detected, 55P03 = lock_not_available
      if ((error.code === '40001' || error.code === '40P01' || error.code === '55P03') && attempt < maxRetries) {
        // Exponential backoff: 100ms, 200ms, 400ms, 800ms, 1600ms
        const waitTime = delay * Math.pow(2, attempt - 1);
        console.log(`Database busy, retrying in ${waitTime}ms (attempt ${attempt}/${maxRetries})`);
        await new Promise(resolve => setTimeout(resolve, waitTime));
        continue;
      }
      throw error;
    }
  }
};

// Submit contact message (public)
app.post('/api/contact-messages', async (req, res) => {
  try {
    const { name, email, message } = req.body;

    // Validate required fields
    if (!name || !email || !message) {
      return res.status(400).json({
        success: false,
        message: 'Name, email, and message are required'
      });
    }

    // Ensure prepared statement exists
    if (!insertContactMessage) {
      try {
        insertContactMessage = db.prepare(`
          INSERT INTO contact_messages (name, email, message)
          VALUES (?, ?, ?)
        `);
      } catch (prepError) {
        console.error('Error preparing statement:', prepError);
        return res.status(500).json({
          success: false,
          message: 'Database initialization error'
        });
      }
    }

    // Execute with retry logic
    const result = await retryDbOperation(async () => {
      return await insertContactMessage.run(
        String(name).trim(),
        String(email).trim(),
        String(message).trim()
      );
    });

    console.log('Contact message inserted successfully. ID:', result.lastInsertRowid);

    res.json({
      success: true,
      message: 'Message sent successfully',
      messageId: result.lastInsertRowid
    });
  } catch (error) {
    console.error('Error submitting contact message:', error);
    console.error('Error details:', {
      code: error.code,
      message: error.message
    });
    res.status(500).json({
      success: false,
      message: (error.code === '40001' || error.code === '40P01' || error.code === '55P03')
        ? 'Database is busy. Please try again in a moment.'
        : 'Failed to send message. Please try again.'
    });
  }
});

// Get all contact messages (admin only) - Optimized for fast response
app.get('/api/contact-messages', authenticateToken, requireAdmin, async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=30'); // Cache for 30 seconds (shorter for admin data)

    const getMessages = db.prepare(`
      SELECT * FROM contact_messages
      ORDER BY created_at DESC
    `);

    const messages = await getMessages.all();
    console.log(`Fetched ${messages.length} contact messages from database`);

    res.json({
      success: true,
      messages
    });
  } catch (error) {
    console.error('Error fetching contact messages:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get YouTube video URL (public) - Optimized for fast response
app.get('/api/content/youtube-video', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('youtube-video');

    let videoUrl = null;

    if (content && content.subtitle) {
      try {
        const parsed = JSON.parse(content.subtitle);
        videoUrl = parsed.videoUrl || null;
      } catch (e) {
        // If parsing fails, use null
      }
    }

    res.json({
      success: true,
      videoUrl: videoUrl
    });
  } catch (error) {
    console.error('Error fetching YouTube video URL:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update YouTube video URL (admin only)
// Get section headings (public) - Optimized for fast response
app.get('/api/content/section-headings', async (req, res) => {
  try {
    // Set cache headers for better performance
    res.setHeader('Cache-Control', 'public, max-age=60'); // Cache for 1 minute

    const getContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const content = await getContent.get('section-headings');

    if (!content) {
      const defaultHeadings = {
        welcomeTitle: 'Welcome to',
        meetConsultants: 'MEET WITH OUR CONSULTANTS',
        ourServices: 'OUR SERVICES',
        ourProducts: 'OUR PRODUCTS',
        ourBlog: 'OUR BLOG',
        trustedClientsTitle: 'Our Trusted Clients',
        trustedClientsSubtitle: 'Proud to work with industry leaders',
        joinTeamTitle: 'Join Our Team',
        joinTeamDescription: 'We\'re always looking for talented individuals to join our team. Explore exciting career opportunities and be part of our innovative journey.'
      };

      return res.json({
        success: true,
        headings: defaultHeadings
      });
    }

    const headings = content.subtitle ? JSON.parse(content.subtitle) : {};

    res.json({
      success: true,
      headings
    });
  } catch (error) {
    console.error('Error fetching section headings:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update section headings (admin only)
app.put('/api/content/section-headings', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const headings = req.body;

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('section-headings');

    if (existing) {
      // Update existing content - ensure title is never null
      const titleValue = existing.title || 'Section Headings';
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET title = ?, subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(titleValue, JSON.stringify(headings), req.user.id, 'section-headings');
    } else {
      // Create new content
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('section-headings', 'Section Headings', JSON.stringify(headings), req.user.id);
    }

    res.json({
      success: true,
      message: 'Section headings updated successfully',
      headings
    });

    // Emit Socket.IO event for live update
    emitUpdate('section-headings:updated', { headings });
  } catch (error) {
    console.error('Error updating section headings:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

app.put('/api/content/youtube-video', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { videoUrl } = req.body;

    // Check if content exists
    const checkContent = db.prepare('SELECT * FROM page_content WHERE page_key = ?');
    const existing = await checkContent.get('youtube-video');

    const videoData = {
      videoUrl: videoUrl || null
    };

    if (existing) {
      // Update existing content
      const updateContent = db.prepare(`
        UPDATE page_content 
        SET subtitle = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE page_key = ?
      `);
      await updateContent.run(JSON.stringify(videoData), req.user.id, 'youtube-video');
    } else {
      // Create new content
      const insertContent = db.prepare(`
        INSERT INTO page_content (page_key, title, subtitle, updated_by)
        VALUES (?, ?, ?, ?)
      `);
      await insertContent.run('youtube-video', 'YouTube Video', JSON.stringify(videoData), req.user.id);
    }

    res.json({
      success: true,
      message: 'YouTube video URL updated successfully',
      videoUrl: videoUrl
    });
  } catch (error) {
    console.error('Error updating YouTube video URL:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error',
      error: error.message
    });
  }
});

// Update contact message status (admin only)
app.put('/api/contact-messages/:id/status', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { status } = req.body;

    if (!status || !['unread', 'read', 'replied'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: 'Valid status is required (unread, read, replied)'
      });
    }

    const updateStatus = db.prepare(`
      UPDATE contact_messages
      SET status = ?
      WHERE id = ?
    `);

    await updateStatus.run(status, parseInt(id));

    res.json({
      success: true,
      message: 'Status updated successfully'
    });
  } catch (error) {
    console.error('Error updating message status:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get theme settings
app.get('/api/theme', async (req, res) => {
  try {
    const getTheme = db.prepare('SELECT * FROM theme_settings WHERE id = 1');
    const theme = await getTheme.get();

    if (!theme) {
      // Create default theme if it doesn't exist
      const insertTheme = db.prepare(`
        INSERT INTO theme_settings (id, button_color, section_shade_color)
        VALUES (1, ?, ?)
      `);
      await insertTheme.run('#e0f7fa', '#f3a158');

      const getNewTheme = db.prepare('SELECT * FROM theme_settings WHERE id = 1');
      const newTheme = await getNewTheme.get();

      return res.json({
        success: true,
        theme: {
          buttonColor: newTheme.button_color,
          sectionShadeColor: newTheme.section_shade_color,
          fontFamily: newTheme.font_family || 'Arial, sans-serif'
        }
      });
    }

    res.json({
      success: true,
      theme: {
        buttonColor: theme.button_color,
        sectionShadeColor: theme.section_shade_color,
        fontFamily: theme.font_family || 'Arial, sans-serif'
      }
    });
  } catch (error) {
    console.error('Error fetching theme settings:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Update theme settings (admin only)
app.put('/api/theme', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { buttonColor, sectionShadeColor, fontFamily } = req.body;

    if (!buttonColor || !sectionShadeColor) {
      return res.status(400).json({
        success: false,
        message: 'Both buttonColor and sectionShadeColor are required'
      });
    }

    // Validate hex colors
    const hexColorRegex = /^#[0-9A-F]{6}$/i;
    if (!hexColorRegex.test(buttonColor) || !hexColorRegex.test(sectionShadeColor)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid color format. Colors must be in hex format (e.g., #e0f7fa)'
      });
    }

    // Validate font family (optional, but if provided should be a string)
    const validFontFamily = fontFamily && typeof fontFamily === 'string' ? fontFamily.trim() : 'Arial, sans-serif';

    // Check if theme exists
    const getTheme = db.prepare('SELECT * FROM theme_settings WHERE id = 1');
    const existingTheme = await getTheme.get();

    if (!existingTheme) {
      // Create theme if it doesn't exist
      const insertTheme = db.prepare(`
        INSERT INTO theme_settings (id, button_color, section_shade_color, font_family, updated_by)
        VALUES (1, ?, ?, ?, ?)
      `);
      await insertTheme.run(buttonColor, sectionShadeColor, validFontFamily, req.user.id);
    } else {
      // Update existing theme
      const updateTheme = db.prepare(`
        UPDATE theme_settings
        SET button_color = ?, section_shade_color = ?, font_family = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ?
        WHERE id = 1
      `);
      await updateTheme.run(buttonColor, sectionShadeColor, validFontFamily, req.user.id);
    }

    // Get updated theme
    const getUpdatedTheme = db.prepare('SELECT * FROM theme_settings WHERE id = 1');
    const updatedTheme = await getUpdatedTheme.get();

    res.json({
      success: true,
      message: 'Theme settings updated successfully',
      theme: {
        buttonColor: updatedTheme.button_color,
        sectionShadeColor: updatedTheme.section_shade_color,
        fontFamily: updatedTheme.font_family || 'Arial, sans-serif'
      }
    });
  } catch (error) {
    console.error('Error updating theme settings:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Subscribe to newsletter
app.post('/api/newsletter', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: 'Email is required'
      });
    }

    // Check if email already exists
    const checkEmail = db.prepare('SELECT * FROM newsletter_subscribers WHERE email = ?');
    const existing = await checkEmail.get(email);

    if (existing) {
      return res.json({
        success: true,
        message: 'You are already subscribed to our newsletter'
      });
    }

    const insertSubscriber = db.prepare(`
      INSERT INTO newsletter_subscribers (email)
      VALUES (?)
    `);

    await insertSubscriber.run(email);

    res.json({
      success: true,
      message: 'Successfully subscribed to newsletter'
    });
  } catch (error) {
    console.error('Error subscribing to newsletter:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Get newsletter subscribers (admin only)
app.get('/api/newsletter', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const getSubscribers = db.prepare('SELECT * FROM newsletter_subscribers ORDER BY created_at DESC');
    const subscribers = await getSubscribers.all();
    console.log(`Fetched ${subscribers.length} newsletter subscribers from database`);

    res.json({
      success: true,
      subscribers
    });
  } catch (error) {
    console.error('Error fetching newsletter subscribers:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Delete newsletter subscriber (admin only)
app.delete('/api/newsletter/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const deleteSubscriber = db.prepare('DELETE FROM newsletter_subscribers WHERE id = ?');
    await deleteSubscriber.run(id);

    res.json({
      success: true,
      message: 'Subscriber deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting subscriber:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});

// Start server - Railway Configuration
// Listen on `port` and 0.0.0.0 (as per Railway requirements)
console.log('='.repeat(60));
console.log('🚀 Starting Server (Railway Configuration)...');
console.log(`📍 Host: ${host} ${host === '0.0.0.0' ? '✅ (correct for Railway)' : '❌ (WRONG)'}`);
console.log(`🔌 Port: ${port} ${process.env.PORT ? '✅ (from Railway)' : '⚠️  (default for local dev)'}`);
console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
console.log('='.repeat(60));

server.listen(port, host, function (err) {
  if (err) {
    console.error('❌ CRITICAL: Failed to start server:', err);
    console.error('Error details:', {
      code: err.code,
      message: err.message,
      port: port,
      host: host
    });
    process.exit(1);
  }

  console.log('='.repeat(60));
  console.log('✅ SERVER STARTED SUCCESSFULLY');
  console.log(`✅ Server listening on http://${host}:${port}`);
  console.log(`✅ API endpoints: http://${host}:${port}/api`);
  console.log(`✅ Socket.IO: http://${host}:${port}`);
  console.log('='.repeat(60));

  // Only show local network info in development
  if (process.env.NODE_ENV !== 'production') {
    console.log(`Accessible from any device on your network`);
    const os = require('os');
    const networkInterfaces = os.networkInterfaces();
    const addresses = [];
    for (const interfaceName in networkInterfaces) {
      const interfaces = networkInterfaces[interfaceName];
      for (const iface of interfaces) {
        if (iface.family === 'IPv4' && !iface.internal) {
          addresses.push(`http://${iface.address}:${port}`);
        }
      }
    }
    if (addresses.length > 0) {
      console.log(`Local network access:`);
      addresses.forEach(addr => console.log(`  - ${addr}/api`));
    }
  }

  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Database: ${process.env.DATABASE_URL ? 'Using DATABASE_URL' : 'Using individual connection parameters'}`);

  // Keep-alive mechanism: Ping the backend every 5 minutes to prevent it from going to sleep
  // This is especially useful for free hosting services that put apps to sleep after inactivity
  const keepAliveInterval = 5 * 60 * 1000; // 5 minutes in milliseconds
  const keepAliveUrl = process.env.KEEP_ALIVE_URL || ` https://backendacdc.onrender.com/api/health`;

  console.log('='.repeat(60));
  console.log('🔄 Keep-Alive Mechanism Started');
  console.log(`⏰ Interval: Every 5 minutes`);
  console.log(`🔗 Ping URL: ${keepAliveUrl}`);
  console.log('='.repeat(60));

  // Function to ping the health endpoint
  const pingHealthEndpoint = async () => {
    try {
      const https = require('https');
      const http = require('http');
      const url = require('url');

      const parsedUrl = new URL(keepAliveUrl);
      const client = parsedUrl.protocol === 'https:' ? https : http;

      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname,
        method: 'GET',
        timeout: 5000 // 5 second timeout
      };

      const req = client.request(options, (res) => {
        let data = '';
        res.on('data', (chunk) => {
          data += chunk;
        });
        res.on('end', () => {
          const timestamp = new Date().toISOString();
          if (res.statusCode === 200 || res.statusCode === 503) {
            // 200 = OK, 503 = Server running but DB might be disconnected (still counts as alive)
            console.log(`✅ [${timestamp}] Keep-alive ping successful - Status: ${res.statusCode}`);
          } else {
            console.log(`⚠️  [${timestamp}] Keep-alive ping returned status: ${res.statusCode}`);
          }
        });
      });

      req.on('error', (error) => {
        const timestamp = new Date().toISOString();
        console.error(`❌ [${timestamp}] Keep-alive ping failed:`, error.message);
      });

      req.on('timeout', () => {
        req.destroy();
        const timestamp = new Date().toISOString();
        console.error(`⏱️  [${timestamp}] Keep-alive ping timeout`);
      });

      req.end();
    } catch (error) {
      const timestamp = new Date().toISOString();
      console.error(`❌ [${timestamp}] Keep-alive ping error:`, error.message);
    }
  };

  // Ping immediately on startup (optional, can be removed if not needed)
  // pingHealthEndpoint();

  // Set up interval to ping every 5 minutes
  const keepAliveTimer = setInterval(() => {
    pingHealthEndpoint();
  }, keepAliveInterval);

  // Ping immediately, then every 5 minutes
  pingHealthEndpoint();

  // Cleanup on process exit
  process.on('SIGTERM', () => {
    console.log('🛑 Shutting down keep-alive mechanism...');
    clearInterval(keepAliveTimer);
  });

  process.on('SIGINT', () => {
    console.log('🛑 Shutting down keep-alive mechanism...');
    clearInterval(keepAliveTimer);
  });
});
