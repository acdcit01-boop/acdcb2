# Backend API Server

Node.js backend with SQLite database for user authentication.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Create a `.env` file by copying `.env.example`:
```bash
cp .env.example .env
```

Or create `.env` manually with:
```
HOST=0.0.0.0
PORT=2004
JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-12345
FRONTEND_URL=http://192.168.29.151:2003
```

**Configuration:**
- `HOST=0.0.0.0` - Makes server accessible from any device on your network
- `PORT=2004` - Server port number
- `JWT_SECRET` - Secret key for JWT tokens (change in production)
- `FRONTEND_URL` - Frontend application URL

3. Start the server:
```bash
npm start
```

Or for development with auto-reload:
```bash
npm run dev
```

The server will display your local IP address so you can access it from other devices on your network.

## Default Admin User

The database automatically creates a default admin user:
- **Username:** admin
- **Email:** admin@example.com
- **Password:** admin123

## API Endpoints

### POST /api/login
Login with email and password.

**Request:**
```json
{
  "email": "admin@example.com",
  "password": "admin123"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "token": "jwt-token-here",
  "user": {
    "id": 1,
    "username": "admin",
    "email": "admin@example.com",
    "role": "admin"
  }
}
```

### POST /api/register
Register a new user.

**Request:**
```json
{
  "username": "newuser",
  "email": "user@example.com",
  "password": "password123",
  "role": "admin"
}
```

### GET /api/verify
Verify JWT token (requires Authorization header).

### GET /api/users
Get all users (for admin).

### GET /api/health
Health check endpoint.

## Database

The database file `database.sqlite` is automatically created. The users table structure:

- id (INTEGER PRIMARY KEY)
- username (TEXT UNIQUE)
- password (TEXT - hashed with bcrypt)
- email (TEXT UNIQUE)
- role (TEXT - default 'admin')
- created_at (DATETIME)

