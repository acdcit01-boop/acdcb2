# Image Encryption - Quick Usage Guide

## How to Use Image Encryption Process

This guide explains how the image encryption process works in your application.

## ✅ Features Implemented

- ✅ **Encrypt images once at upload** - Images are automatically encrypted after upload
- ✅ **Never decrypt on every view** - Encrypted images are served directly without decryption
- ✅ **Serve images via CDN** - Encrypted images are CDN-friendly with proper cache headers
- ✅ **Use symmetric encryption (AES)** - AES-256-GCM encryption is used
- ✅ **Do encryption in background / async** - Encryption happens asynchronously without blocking uploads

## Setup

### 1. Generate Encryption Key

First, generate a secure encryption key:

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 2. Configure Environment

Add the encryption key to your `.env` file:

```env
ENCRYPTION_KEY=your-64-character-hex-encryption-key-here
```

**⚠️ Important**: 
- Keep this key secure and backed up
- Never commit it to version control
- If you lose the key, encrypted images cannot be decrypted

### 3. Restart Server

After setting the encryption key, restart your backend server:

```bash
npm start
# or
npm run dev
```

## How It Works

### Upload Flow

1. **Image is uploaded** → Saved to `uploads/` directory
2. **Response sent immediately** → Client gets success response right away
3. **Encryption happens in background** → Image is encrypted asynchronously
4. **Original file replaced** → Encrypted version replaces original (same filename)

### Serving Flow

1. **Client requests image** → `GET /api/files/image-name.jpg`
2. **Server reads encrypted file** → File is already encrypted on disk
3. **Served directly** → Encrypted binary data streamed to client
4. **CDN caches** → Encrypted image cached at edge locations

### Encryption Details

- **Algorithm**: AES-256-GCM
- **Key Size**: 32 bytes (64 hex characters)
- **IV**: 16 bytes (random, per file)
- **Auth Tag**: 16 bytes (for integrity)
- **File Format**: `[IV][AuthTag][EncryptedData]`

## Automatic Encryption

Images are automatically encrypted when uploaded through these endpoints:

- ✅ `/api/content/welcome/upload` - Background images
- ✅ `/api/blogs` - Blog post images
- ✅ `/api/blogs/:id` (PUT) - Blog image updates
- ✅ `/api/products` - Product images and icons
- ✅ `/api/products/:id` (PUT) - Product image updates
- ✅ `/api/services` - Service images and icons
- ✅ `/api/services/:id` (PUT) - Service image updates
- ✅ `/api/consultance` - Consultance member images
- ✅ `/api/consultance/:id` (PUT) - Consultance image updates

## CDN Integration

Encrypted images work perfectly with CDNs because:

1. **Cache Headers**: `Cache-Control: public, max-age=31536000` (1 year)
2. **CORS Enabled**: `Access-Control-Allow-Origin: *`
3. **Binary Data**: Served as binary stream (CDN-friendly)
4. **No Server Load**: No decryption overhead on server

### CDN Configuration

Set your CDN URL in `.env`:

```env
IMAGE_BASE_URL=https://your-cdn-domain.com
```

Or use the default:

```env
BASE_URL=https://your-backend-domain.com
```

## Example Usage

### Upload Image (Automatic Encryption)

```javascript
// Frontend - Upload image
const formData = new FormData();
formData.append('image', fileInput.files[0]);

fetch('/api/blogs', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${token}`
  },
  body: formData
})
.then(res => res.json())
.then(data => {
  console.log('Image uploaded:', data.image);
  // Image URL is returned immediately
  // Encryption happens in background
});
```

### Serve Encrypted Image

```html
<!-- Frontend - Display image -->
<img src="/api/files/blog-image-1234567890.jpg" alt="Blog Image" />
<!-- Encrypted image is served directly -->
```

## Performance

- **Upload**: Non-blocking - response sent immediately
- **Encryption**: Background process - doesn't block requests
- **Serving**: Fast - direct file streaming, no decryption
- **CDN**: Optimal - encrypted files cached at edge locations
- **Storage**: ~32 bytes overhead per image (IV + AuthTag)

## Security Notes

1. **Key Management**: Store encryption keys securely (environment variables, secrets management)
2. **Key Rotation**: If rotating keys, decrypt old images and re-encrypt with new key
3. **Backup**: Keep backups of encryption keys in secure locations
4. **Access Control**: Ensure only authorized users can upload images
5. **File Validation**: Validate file types and sizes before encryption

## Troubleshooting

### Images not encrypting

1. Check `ENCRYPTION_KEY` is set in `.env`
2. Verify file uploads are going to `uploads/` directory
3. Check server logs for encryption errors
4. Ensure `utils/imageEncryption.js` exists

### Cannot serve images

1. Verify file exists in `uploads/` directory
2. Check file permissions
3. Verify `/api/files/:filename` endpoint is working
4. Check CORS headers are set correctly

### CDN not caching

1. Verify `Cache-Control` headers are being set
2. Check CDN configuration allows caching of binary data
3. Ensure CORS headers are properly configured
4. Verify `IMAGE_BASE_URL` or `BASE_URL` is set correctly

## API Endpoints

### Upload Image (Auto-Encrypt)
```
POST /api/content/welcome/upload
POST /api/blogs
POST /api/products
POST /api/services
POST /api/consultance
```

### Serve Encrypted Image
```
GET /api/files/:filename
```

**Response Headers:**
- `Content-Type`: Image MIME type or `application/octet-stream`
- `X-Image-Encrypted`: `true` (if encrypted)
- `Cache-Control`: `public, max-age=31536000`
- `Access-Control-Allow-Origin`: `*`

## Testing

### Test Encryption

1. Upload an image through any upload endpoint
2. Check server logs for: `✅ Image encrypted successfully: filename.jpg`
3. Request the image: `GET /api/files/filename.jpg`
4. Check response header: `X-Image-Encrypted: true`

### Verify Encryption

```javascript
const { isEncrypted } = require('./utils/imageEncryption');

const encrypted = await isEncrypted('path/to/image.jpg');
console.log('Is encrypted:', encrypted); // true or false
```

## Notes

- Encrypted images replace original files (no separate encrypted copy)
- Encryption happens asynchronously, so there's a brief window where unencrypted images exist
- For production, consider encrypting synchronously before saving to ensure no unencrypted data persists
- The system is backward compatible - old unencrypted images will still be served

## Support

For more details, see:
- `backend/IMAGE_ENCRYPTION_README.md` - Full documentation
- `backend/utils/imageEncryption.js` - Encryption implementation

