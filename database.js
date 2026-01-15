const { Pool } = require('pg');
const bcrypt = require('bcryptjs');

// Create PostgreSQL connection pool
// Railway provides DATABASE_URL, but we also support individual connection parameters
const pool = new Pool(
  process.env.DATABASE_URL
    ? {
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? {
        rejectUnauthorized: false
      } : false
    }
    : {
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 8956,
      database: process.env.DB_NAME || 'acdc',
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || 'postgres',
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000,
    }
);

// Test connection
pool.on('connect', () => {
  console.log('Connected to PostgreSQL database');
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
  // Don't exit - log the error and let the app continue
  // Connection will be retried on next query
});

// Helper function to execute queries
const query = async (text, params) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    if (process.env.NODE_ENV === 'development') {
      console.log('Executed query', { text, duration, rows: res.rowCount });
    }
    return res;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
};

// Helper function to get a single row
const get = async (text, params) => {
  const result = await query(text, params);
  return result.rows[0] || null;
};

// Helper function to get all rows
const all = async (text, params) => {
  const result = await query(text, params);
  return result.rows;
};

// Helper function to execute a query without returning rows
const run = async (text, params) => {
  const result = await query(text, params);
  return {
    lastInsertRowid: result.rows[0]?.id || null,
    changes: result.rowCount || 0
  };
};

// Helper function to execute multiple statements
const exec = async (text) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(text);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
};

// Enable foreign keys (PostgreSQL has them enabled by default, but we can verify)
const enableForeignKeys = async () => {
  try {
    await query('SET session_replication_role = replica');
    await query('SET session_replication_role = DEFAULT');
    console.log('Foreign keys are enabled');
  } catch (e) {
    console.warn('Could not verify foreign keys:', e.message);
  }
};

// Create users table if it doesn't exist
const createUsersTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      role TEXT DEFAULT 'admin',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await exec(createTableQuery);
  console.log('Users table created or already exists');
};

// Create page_content table for dynamic content
const createPageContentTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS page_content (
      id SERIAL PRIMARY KEY,
      page_key TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      subtitle TEXT,
      button_text TEXT,
      background_image TEXT,
      background_video TEXT,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INTEGER,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Page content table created or already exists');

  // Add new columns if they don't exist (for existing databases)
  const columnsToAdd = [
    'background_image',
    'background_video',
    'banner_text',
    'company_name',
    'short_description',
    'full_description',
    'logo_image',
    'description',
    'vision',
    'mission',
    'goal_background_image',
    'use_bullets',
    'vision_icon',
    'mission_icon',
    'bullet_type',
    'subtitle_url'
  ];

  for (const column of columnsToAdd) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='page_content' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        let defaultValue = '';
        if (column === 'use_bullets') {
          defaultValue = 'DEFAULT 0';
        } else if (column === 'bullet_type') {
          defaultValue = 'DEFAULT \'disc\'';
        }
        await exec(`ALTER TABLE page_content ADD COLUMN ${column} TEXT ${defaultValue}`);
        console.log(`Added ${column} column to page_content table`);
      }
    } catch (e) {
      // Column already exists or error
      if (!e.message.includes('already exists')) {
        console.log(`Error adding column ${column}:`, e.message);
      }
    }
  }

  // Migrate existing short_description and full_description to description
  try {
    await query(`
      UPDATE page_content 
      SET description = CASE 
        WHEN short_description IS NOT NULL AND full_description IS NOT NULL THEN 
          short_description || ' ' || full_description
        WHEN short_description IS NOT NULL THEN short_description
        WHEN full_description IS NOT NULL THEN full_description
        ELSE description
      END
      WHERE page_key = 'about' AND (description IS NULL OR description = '')
    `);
    console.log('Migrated short_description and full_description to description');
  } catch (e) {
    console.log('Migration note:', e.message);
  }
};

// Create consultance table for team members
const createConsultanceTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS consultance (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      title TEXT NOT NULL,
      image TEXT,
      facebook_url TEXT,
      instagram_url TEXT,
      twitter_url TEXT,
      linkedin_url TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INTEGER,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Consultance table created or already exists');

  // Add social media columns if they don't exist
  const socialColumns = ['facebook_url', 'instagram_url', 'twitter_url', 'linkedin_url'];
  for (const column of socialColumns) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='consultance' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        await exec(`ALTER TABLE consultance ADD COLUMN ${column} TEXT`);
        console.log(`Added ${column} column to consultance table`);
      }
    } catch (e) {
      // Column already exists
    }
  }

  // Check if there are any consultance members, if not create a default one
  const countResult = await query('SELECT COUNT(*) as count FROM consultance');
  const count = parseInt(countResult.rows[0].count);

  if (count === 0) {
    // Get admin user ID - check if users table has any records
    let adminId = null;
    try {
      const adminResult = await get('SELECT id FROM users WHERE role = $1 LIMIT 1', ['admin']);
      if (adminResult && adminResult.id) {
        adminId = adminResult.id;
      } else {
        // Try to get any user
        const anyUser = await get('SELECT id FROM users LIMIT 1');
        if (anyUser && anyUser.id) {
          adminId = anyUser.id;
        }
      }
    } catch (error) {
      console.log('No users found, using NULL for updated_by');
      adminId = null;
    }

    try {
      const result = await query(`
        INSERT INTO consultance (name, title, display_order, updated_by)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `, ['Consultant Name', 'Consultant', 0, adminId]);
      console.log('Default consultance member created');
    } catch (error) {
      console.log('Error creating default consultance member:', error.message);
      // Try with NULL if foreign key constraint fails
      if (error.code === '23503' || error.message.includes('FOREIGN KEY')) {
        try {
          await query(`
            INSERT INTO consultance (name, title, display_order, updated_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id
          `, ['Consultant Name', 'Consultant', 0, null]);
          console.log('Default consultance member created with NULL updated_by');
        } catch (err) {
          console.log('Failed to create default consultance member. Skipping default record creation.');
        }
      } else {
        console.log('Skipping default consultance member creation due to error');
      }
    }
  }
};

// Create services table
const createServicesTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      background_image TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      updated_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Services table created or already exists');

  // Add service_image column if it doesn't exist (migration)
  const serviceColumns = ['service_image', 'short_description', 'icon', 'key_features'];
  for (const column of serviceColumns) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='services' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        await exec(`ALTER TABLE services ADD COLUMN ${column} TEXT`);
        console.log(`Added ${column} column to services table`);
      }
    } catch (error) {
      console.log(`${column} column may already exist or error adding it:`, error.message);
    }
  }

  // Check if any services exist, if not create a default one
  const countResult = await query('SELECT COUNT(*) as count FROM services');
  const count = parseInt(countResult.rows[0].count);

  if (count === 0) {
    // Get admin user ID - check if users table has any records
    let adminId = null;
    try {
      const adminResult = await get('SELECT id FROM users WHERE role = $1 LIMIT 1', ['admin']);
      if (adminResult && adminResult.id) {
        adminId = adminResult.id;
      } else {
        // Try to get any user
        const anyUser = await get('SELECT id FROM users LIMIT 1');
        if (anyUser && anyUser.id) {
          adminId = anyUser.id;
        }
      }
    } catch (error) {
      console.log('No users found, using NULL for created_by/updated_by');
      adminId = null;
    }

    try {
      await query(`
        INSERT INTO services (title, description, created_by, updated_by)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `, ['Default Service', 'This is a default service. Edit or add more services using the admin panel.', adminId, adminId]);
      console.log('Default service created');
    } catch (error) {
      console.log('Error creating default service:', error.message);
      // Try with NULL if foreign key constraint fails
      if (error.code === '23503' || error.message.includes('FOREIGN KEY')) {
        try {
          await query(`
            INSERT INTO services (title, description, created_by, updated_by)
            VALUES ($1, $2, $3, $4)
            RETURNING id
          `, ['Default Service', 'This is a default service. Edit or add more services using the admin panel.', null, null]);
          console.log('Default service created with NULL created_by/updated_by');
        } catch (err) {
          console.log('Failed to create default service. Skipping default record creation.');
        }
      } else {
        console.log('Skipping default service creation due to error');
      }
    }
  }
};

// Create products table
const createProductsTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      image TEXT,
      why_it_matters TEXT,
      key_features TEXT,
      button_text TEXT DEFAULT 'Book a Free Consultation',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      updated_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Products table created or already exists');

  // Add missing columns if they don't exist (migration for existing databases)
  const productColumns = ['why_it_matters', 'button_text', 'icon', 'applications', 'background_image'];
  for (const column of productColumns) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='products' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        let defaultValue = '';
        if (column === 'button_text') {
          defaultValue = "DEFAULT 'Book a Free Consultation'";
        }
        await exec(`ALTER TABLE products ADD COLUMN ${column} TEXT ${defaultValue}`);
        console.log(`Added ${column} column to products table`);
      }
    } catch (e) {
      // Column already exists, ignore error
      if (!e.message || (!e.message.includes('already exists') && !e.message.includes('duplicate'))) {
        console.log(`Note: ${column} column may already exist or error occurred:`, e.message);
      }
    }
  }

  // Check if any products exist, if not create a default one
  const countResult = await query('SELECT COUNT(*) as count FROM products');
  const count = parseInt(countResult.rows[0].count);

  if (count === 0) {
    // Get admin user ID - check if users table has any records
    let adminId = null;
    try {
      const adminResult = await get('SELECT id FROM users WHERE role = $1 LIMIT 1', ['admin']);
      if (adminResult && adminResult.id) {
        adminId = adminResult.id;
      } else {
        // Try to get any user
        const anyUser = await get('SELECT id FROM users LIMIT 1');
        if (anyUser && anyUser.id) {
          adminId = anyUser.id;
        }
      }
    } catch (error) {
      console.log('No users found, using NULL for created_by/updated_by');
      adminId = null;
    }

    const defaultFeatures = JSON.stringify([
      'Market Research & Competitive Analysis',
      'Business Planning & Goal Setting',
      'Strategic Roadmap Development',
      'Risk Assessment & Mitigation',
      'Performance Tracking & KPIs'
    ]);

    try {
      await query(`
        INSERT INTO products (title, description, why_it_matters, key_features, created_by, updated_by)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING id
      `, [
        'Business Strategy',
        'A well-crafted business strategy provides clarity, reduces uncertainty, and positions your organization to seize opportunities in a competitive landscape. It ensures that your team is aligned, your resources are optimized, and your growth trajectory is sustainable.',
        'A well-crafted business strategy provides clarity, reduces uncertainty, and positions your organization to seize opportunities in a competitive landscape. It ensures that your team is aligned, your resources are optimized, and your growth trajectory is sustainable.',
        defaultFeatures,
        adminId,
        adminId
      ]);
      console.log('Default product created');
    } catch (error) {
      console.log('Error creating default product:', error.message);
      // Try with NULL if foreign key constraint fails
      if (error.code === '23503' || error.message.includes('FOREIGN KEY')) {
        try {
          await query(`
            INSERT INTO products (title, description, why_it_matters, key_features, created_by, updated_by)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING id
          `, [
            'Business Strategy',
            'A well-crafted business strategy provides clarity, reduces uncertainty, and positions your organization to seize opportunities in a competitive landscape. It ensures that your team is aligned, your resources are optimized, and your growth trajectory is sustainable.',
            'A well-crafted business strategy provides clarity, reduces uncertainty, and positions your organization to seize opportunities in a competitive landscape. It ensures that your team is aligned, your resources are optimized, and your growth trajectory is sustainable.',
            defaultFeatures,
            null,
            null
          ]);
          console.log('Default product created with NULL created_by/updated_by');
        } catch (err) {
          console.log('Failed to create default product. Skipping default record creation.');
        }
      } else {
        console.log('Skipping default product creation due to error');
      }
    }
  }
};

// Create blogs table
const createBlogsTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS blogs (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      image TEXT,
      video TEXT,
      youtube_url TEXT,
      date TEXT NOT NULL,
      location TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      updated_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Blogs table created or already exists');

  // Add video and youtube_url columns if they don't exist (for existing databases)
  const blogColumns = ['video', 'youtube_url'];
  for (const column of blogColumns) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='blogs' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        await exec(`ALTER TABLE blogs ADD COLUMN ${column} TEXT`);
        console.log(`Added ${column} column to blogs table`);
      }
    } catch (e) {
      // Column already exists
    }
  }
};

// Create positions table for career page
const createPositionsTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS positions (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      location TEXT,
      jobtype TEXT NOT NULL,
      positions_count TEXT,
      experience TEXT,
      skills_required TEXT,
      education TEXT,
      description TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      updated_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Positions table created or already exists');

  // Add new columns if they don't exist (for existing databases)
  const positionColumns = ['positions_count', 'experience', 'skills_required', 'education', 'description', 'active'];
  for (const column of positionColumns) {
    try {
      const columnExists = await query(`
        SELECT column_name 
        FROM information_schema.columns 
        WHERE table_name='positions' AND column_name=$1
      `, [column]);

      if (columnExists.rows.length === 0) {
        if (column === 'active') {
          // Add active column with default value true (boolean)
          await exec(`ALTER TABLE positions ADD COLUMN active BOOLEAN DEFAULT true`);
          // Update existing rows to be active by default
          await query(`UPDATE positions SET active = true WHERE active IS NULL`);
        } else {
        await exec(`ALTER TABLE positions ADD COLUMN ${column} TEXT`);
        }
        console.log(`Added ${column} column to positions table`);
      }
    } catch (e) {
      // Column already exists
    }
  }
};

// Create job applications table
const createApplicationsTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS job_applications (
      id SERIAL PRIMARY KEY,
      position_id INTEGER NOT NULL,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      contact_number TEXT NOT NULL,
      email TEXT NOT NULL,
      about_yourself TEXT NOT NULL,
      resume_filename TEXT,
      status TEXT DEFAULT 'pending',
      notes TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (position_id) REFERENCES positions(id) ON DELETE CASCADE
    )
  `;

  await exec(createTableQuery);
  console.log('Job applications table created or already exists');

  // Add notes column if it doesn't exist (for existing databases)
  try {
    const columnExists = await query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name='job_applications' AND column_name='notes'
    `);

    if (columnExists.rows.length === 0) {
      await exec(`ALTER TABLE job_applications ADD COLUMN notes TEXT`);
      console.log('Notes column added to job_applications table');
    }
  } catch (e) {
    // Column already exists or error
    console.log('Notes column check:', e.message);
  }
};

// Create contact messages table
const createContactMessagesTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS contact_messages (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      message TEXT NOT NULL,
      status TEXT DEFAULT 'unread',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `;

  await exec(createTableQuery);
  console.log('Contact messages table created or already exists');
};

// Create Dropbox OAuth tokens table
const createDropboxTokensTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS dropbox_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      access_token TEXT NOT NULL,
      refresh_token TEXT,
      token_type TEXT DEFAULT 'bearer',
      expires_at TIMESTAMP,
      account_id TEXT,
      account_email TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
      UNIQUE(user_id)
    )
  `;

  await exec(createTableQuery);
  console.log('Dropbox tokens table created or already exists');
};

// Create theme settings table
const createThemeTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS theme_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      button_color TEXT DEFAULT '#e0f7fa',
      section_shade_color TEXT DEFAULT '#f3a158',
      font_family TEXT DEFAULT 'Arial, sans-serif',
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_by INTEGER,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL,
      CHECK (id = 1)
    )
  `;

  await exec(createTableQuery);
  console.log('Theme settings table created or already exists');

  // Add font_family column if it doesn't exist (for existing databases)
  try {
    const columnExists = await query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name='theme_settings' AND column_name='font_family'
    `);

    if (columnExists.rows.length === 0) {
      await exec(`ALTER TABLE theme_settings ADD COLUMN font_family TEXT DEFAULT 'Arial, sans-serif'`);
      console.log('Font family column added to theme_settings table');
    }
  } catch (e) {
    // Column already exists
  }
};

// Create background_images table for welcome page multiple images
const createBackgroundImagesTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS background_images (
      id SERIAL PRIMARY KEY,
      page_key TEXT NOT NULL,
      image_filename TEXT NOT NULL,
      title TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Background images table created or already exists');

  // Add title column if it doesn't exist (for existing databases)
  try {
    const columnExists = await query(`
      SELECT column_name 
      FROM information_schema.columns 
      WHERE table_name='background_images' AND column_name='title'
    `);

    if (columnExists.rows.length === 0) {
      await exec(`ALTER TABLE background_images ADD COLUMN title TEXT`);
      console.log('Title column added to background_images table');
    }
  } catch (e) {
    // Column already exists or error
    console.log('Title column check:', e.message);
  }
};

// Create clients table for client logos
const createClientsTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS clients (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      logo_filename TEXT,
      display_order INTEGER DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      created_by INTEGER,
      updated_by INTEGER,
      FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL,
      FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
    )
  `;

  await exec(createTableQuery);
  console.log('Clients table created or already exists');
};

// Create newsletter subscribers table
const createNewsletterTable = async () => {
  const createTableQuery = `
    CREATE TABLE IF NOT EXISTS newsletter_subscribers (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      status TEXT DEFAULT 'active'
    )
  `;

  await exec(createTableQuery);
  console.log('Newsletter subscribers table created or already exists');
};

// Initialize database
const initDatabase = async () => {
  try {
    await enableForeignKeys();
    await createUsersTable();
    await createPageContentTable();
    await createBackgroundImagesTable();
    await createConsultanceTable();
    await createServicesTable();
    await createProductsTable();
    await createBlogsTable();
    await createPositionsTable();
    await createApplicationsTable();
    await createContactMessagesTable();
    await createThemeTable();
    await createDropboxTokensTable();
    await createClientsTable();
    await createNewsletterTable();

    // Initialize default theme if it doesn't exist
    const existingTheme = await get('SELECT * FROM theme_settings WHERE id = $1', [1]);
    if (!existingTheme) {
      await query(`
        INSERT INTO theme_settings (id, button_color, section_shade_color, font_family)
        VALUES ($1, $2, $3, $4)
      `, [1, '#e0f7fa', '#f3a158', 'Arial, sans-serif']);
      console.log('Default theme settings created');
    } else {
      // Update existing theme to include font_family if it's null
      if (!existingTheme.font_family) {
        await query(`
          UPDATE theme_settings
          SET font_family = $1
          WHERE id = 1
        `, ['Arial, sans-serif']);
        console.log('Font family added to existing theme settings');
      }
    }

    // Check if admin user exists, if not create one
    const admin = await get('SELECT * FROM users WHERE username = $1', ['admin']);

    let adminId = null;
    if (!admin) {
      // Create default admin user (password: admin123)
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      const result = await query(`
        INSERT INTO users (username, password, email, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id
      `, ['admin', hashedPassword, 'admin@example.com', 'admin']);

      adminId = result.rows[0].id;
      console.log('Default admin user created (username: admin, password: admin123)');
    } else {
      adminId = admin.id;
    }

    // Initialize default welcome content if it doesn't exist
    const welcomeContent = await get('SELECT * FROM page_content WHERE page_key = $1', ['welcome']);

    if (!welcomeContent) {
      await query(`
        INSERT INTO page_content (page_key, title, subtitle, button_text, updated_by)
        VALUES ($1, $2, $3, $4, $5)
      `, [
        'welcome',
        'Welcome to Our Website',
        'We are team of talented designers making websites with Bootstrap',
        'Get Started',
        adminId
      ]);
      console.log('Default welcome content created');
    }
  } catch (error) {
    console.error('Error initializing database:', error);
    throw error;
  }
};

// Initialize on load - don't block server startup
// Run initialization asynchronously without blocking
setTimeout(() => {
  initDatabase().catch(err => {
    console.error('Failed to initialize database:', err);
    console.error('Database connection error details:', {
      message: err.message,
      code: err.code,
      hasDatabaseUrl: !!process.env.DATABASE_URL,
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'backend'
    });
    // Don't exit - let the app start and retry connection
    // The app will handle database errors gracefully in route handlers
  });
}, 100); // Small delay to ensure server starts first

// Export database methods compatible with better-sqlite3 API
module.exports = {
  query,
  get,
  all,
  run,
  exec,
  pool,
  // For backward compatibility, create a prepare-like interface
  prepare: (sql) => {
    // Convert SQLite placeholders (?) to PostgreSQL placeholders ($1, $2, etc.)
    let paramIndex = 1;
    let convertedSql = sql.replace(/\?/g, () => `$${paramIndex++}`);

    // For INSERT statements, add RETURNING id if not already present
    const isInsert = /^\s*INSERT\s+INTO/i.test(convertedSql.trim());
    if (isInsert && !/RETURNING/i.test(convertedSql)) {
      // Add RETURNING id before semicolon or at the end
      convertedSql = convertedSql.replace(/;?\s*$/, ' RETURNING id;');
    }

    return {
      get: async (...params) => {
        const result = await query(convertedSql, params);
        return result.rows[0] || null;
      },
      all: async (...params) => {
        const result = await query(convertedSql, params);
        return result.rows;
      },
      run: async (...params) => {
        const result = await query(convertedSql, params);
        return {
          lastInsertRowid: result.rows[0]?.id || null,
          changes: result.rowCount || 0
        };
      }
    };
  }
};
