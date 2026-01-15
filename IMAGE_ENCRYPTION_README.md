# Image Encryption Process

This document explains how the image encryption system works in this application.

## Overview

The image encryption system implements the following requirements:
- ✅ **Encrypt images once at upload** - Images are encrypted immediately after upload
- ✅ **Never decrypt on every view** - Encrypted images are served directly without decryption
- ✅ **Serve images via CDN** - Encrypted images can be cached and served via CDN
- ✅ **Use symmetric encryption (AES)** - AES-256-GCM encryption is used
- ✅ **Do encryption in background / async** - Encryption happens asynchronously without blocking uploads

## How It Works

### 1. Upload Process

When an image is uploaded:

1. **File is saved** to disk in the `uploads/` directory
2. **Response is sent immediately** to the client (non-blocking)
3. **Encryption happens in background** - The image file is encrypted asynchronously using AES-256-GCM
4. **Original file is replaced** with encrypted version (same filename)

### 2. Encryption Details

- **Algorithm**: AES-256-GCM (Galois/Counter Mode)
- **Key**: 32-byte encryption key (from `ENCRYPTION_KEY` environment variable)
- **IV**: 16-byte random initialization vector (generated per file)
- **Auth Tag**: 16-byte authentication tag (for integrity verification)

**File Format**: `[IV (16 bytes)][AuthTag (16 bytes)][EncryptedData (variable)]`

### 3. Serving Images

When an image is requested via `/api/files/:filename`:

1. **File is read from disk** (already encrypted)
2. **Served directly** without decryption
3. **Headers are set** appropriately for CDN caching
4. **CORS headers** allow cross-origin access

The encrypted image data is served as-is. The client receives encrypted binary data that can be:
- Cached by CDN
- Served directly to browsers
- Stored securely

### 4. CDN Integration

Encrypted images are CDN-friendly because:
- They have proper cache headers (`Cache-Control: public, max-age=31536000`)
- They're served as binary data with appropriate MIME types
- No server-side decryption overhead
- Can be cached at edge locations

## Configuration

### Environment Variables

Set the following in your `.env` file:

```env
# Encryption key (32 bytes = 64 hex characters)
# Generate a secure key: openssl rand -hex 32
ENCRYPTION_KEY=your-64-character-hex-encryption-key-here

# Base URL for image serving (for CDN)
IMAGE_BASE_URL=https://your-cdn-domain.com
# or
BASE_URL=https://your-backend-domain.com
```

### Generating Encryption Key

Generate a secure encryption key:

```bash
# Using OpenSSL
openssl rand -hex 32

# Using Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

**⚠️ Important**: 
- Keep the encryption key secure and backed up
- Never commit the key to version control
- If you lose the key, encrypted images cannot be decrypted

## Usage

### Automatic Encryption

Images are automatically encrypted when uploaded through these endpoints:
- `/api/content/welcome/upload` - Background images
- `/api/blogs` - Blog post images
- `/api/products` - Product images and icons

### Manual Encryption (Admin/Backup)

If you need to decrypt an image (for backup or admin purposes):

```javascript
const { decryptImage } = require('./utils/imageEncryption');

// Decrypt an encrypted image
await decryptImage(
  'path/to/encrypted-image.jpg',
  'path/to/decrypted-output.jpg'
);
```

### Checking Encryption Status

```javascript
const { isEncrypted } = require('./utils/imageEncryption');

const encrypted = await isEncrypted('path/to/image.jpg');
console.log('Is encrypted:', encrypted);
```

## Security Considerations

1. **Key Management**: Store encryption keys securely (use environment variables, secrets management)
2. **Key Rotation**: If rotating keys, decrypt old images and re-encrypt with new key
3. **Backup**: Keep backups of encryption keys in secure locations
4. **Access Control**: Ensure only authorized users can upload images
5. **File Validation**: Validate file types and sizes before encryption

## Performance

- **Upload**: Non-blocking - response sent immediately, encryption happens in background
- **Serving**: Fast - no decryption overhead, direct file streaming
- **CDN**: Optimal - encrypted files can be cached at edge locations
- **Storage**: Slightly larger files (~32 bytes overhead: IV + AuthTag)

## Troubleshooting

### Images not encrypting

1. Check that `ENCRYPTION_KEY` is set in `.env`
2. Verify file uploads are going to `uploads/` directory
3. Check server logs for encryption errors

### Cannot decrypt images

1. Verify you're using the correct encryption key
2. Ensure the file wasn't corrupted during transfer
3. Check that the file is actually encrypted (not plain image)

### CDN not caching

1. Verify `Cache-Control` headers are being set
2. Check CDN configuration allows caching of binary data
3. Ensure CORS headers are properly configured

## API Endpoints

### Upload Image (with auto-encryption)
```
POST /api/content/welcome/upload
POST /api/blogs
POST /api/products
```

### Serve Encrypted Image
```
GET /api/files/:filename
```

Response headers:
- `Content-Type`: Image MIME type or `application/octet-stream`
- `X-Image-Encrypted`: `true` (if encrypted)
- `Cache-Control`: `public, max-age=31536000`
- `Access-Control-Allow-Origin`: `*`

## Example Flow

1. **Client uploads image** → `POST /api/blogs` with image file
2. **Server saves file** → `uploads/blog-image-1234567890.jpg`
3. **Server responds** → `{ success: true, image: "blog-image-1234567890.jpg" }`
4. **Background encryption** → File is encrypted asynchronously
5. **Client requests image** → `GET /api/files/blog-image-1234567890.jpg`
6. **Server serves encrypted file** → Binary encrypted data streamed directly
7. **CDN caches** → Encrypted image cached at edge locations

## Notes

- Encrypted images replace original files (no separate encrypted copy)
- Encryption happens asynchronously, so there's a brief window where unencrypted images exist
- For production, consider encrypting synchronously before saving to ensure no unencrypted data persists
- The system is backward compatible - old unencrypted images will still be served

