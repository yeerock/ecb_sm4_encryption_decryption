# SM4-ECB Encryption Tool Documentation

## Overview

This is a web-based implementation of the SM4 encryption algorithm in ECB (Electronic Codebook) mode. SM4 is a Chinese national standard block cipher algorithm (GB/T 32907-2016) that uses a 128-bit block size and 128-bit key length.

## Features

- **Encryption/Decryption**: Supports both encryption and decryption operations
- **Hex Input/Output**: Works with hexadecimal formatted data (spaces allowed for readability)
- **Test Case Included**: Comes with a pre-loaded test case to verify correct operation
- **Warning System**: Clearly warns about the security limitations of ECB mode
- **Responsive Design**: Works on both desktop and mobile devices

## Security Note

⚠️ **Important Warning**: This tool uses ECB (Electronic Codebook) mode which is not secure for most real-world applications. ECB reveals patterns in your data as identical plaintext blocks produce identical ciphertext blocks. This implementation should only be used for:
- Educational purposes
- Testing and debugging
- Understanding the SM4 algorithm

## How to Use

### Encryption

1. Enter your plaintext in hex format in the "Plaintext" field (spaces are allowed)
2. Enter a 16-character (128-bit) encryption key
3. Click "Encrypt (SM4-ECB)" button
4. View the encrypted result in hex format
5. The ciphertext is automatically copied to the decryption section

### Decryption

1. Enter your ciphertext in hex format in the "Ciphertext" field (spaces are allowed)
2. Enter the same 16-character (128-bit) key used for encryption
3. Click "Decrypt (SM4-ECB)" button
4. View the decrypted result in hex format

### Test Case

A test case is provided to verify the tool is working correctly:
- **Plaintext**: `8c a3 64 fc 00 00 00 00 7e 32 5f 46 7e 32 5f 02`
- **Key**: `0123456789ABCDEF`
- **Expected Result**: `F01F830BFF4EF82B11579D6EDA5D1AA5`

## Technical Details

### SM4 Algorithm Specifications
- **Block size**: 128 bits
- **Key length**: 128 bits
- **Rounds**: 32
- **S-box**: Uses a fixed 8-bit substitution box (S-box)
- **Key expansion**: Generates 32 round keys from the original key

### Implementation Notes
- Pure JavaScript implementation (no external dependencies)
- Processes data in 16-byte (128-bit) blocks
- Handles hex input with or without spaces
- Includes proper error handling for invalid input

## Limitations

1. ECB mode is not secure for production use
2. Only accepts hex input (no direct text encryption)
3. Requires exact 16-character (128-bit) keys
4. Input must be a multiple of 16 bytes (32 hex characters)

## Browser Compatibility

This tool should work in all modern browsers including:
- Chrome
- Firefox
- Safari
- Edge
- Opera

## Source Code

The complete source code is contained within a single HTML file with:
- HTML structure
- CSS styling
- JavaScript implementation of SM4
- User interface handlers

The code is self-contained with no external dependencies.
