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

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SM4-ECB Encryption Tool</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            background-color: #fafafa;
        }
        h2 {
            color: #3498db;
            margin-top: 0;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: bold;
            color: #555;
        }
        textarea, input[type="text"], input[type="password"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
            box-sizing: border-box;
            font-family: monospace;
        }
        textarea {
            min-height: 100px;
        }
        button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 12px 20px;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            transition: background-color 0.3s;
        }
        button:hover {
            background-color: #2980b9;
        }
        .result {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            margin-top: 15px;
            border: 1px solid #eee;
            word-wrap: break-word;
            font-family: monospace;
        }
        .warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            border: 1px solid #ffeeba;
        }
        .test-case {
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            border: 1px solid #bee5eb;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>SM4-ECB Encryption Tool</h1>
        
        <div class="warning">
            <strong>Warning:</strong> ECB mode is not secure for most real-world applications as it reveals patterns in your data. Use only for testing/educational purposes.
        </div>

        <div class="test-case">
            <strong>Test Case:</strong><br>
            Plaintext: <code>8c a3 64 fc 00 00 00 00 7e 32 5f 46 7e 32 5f 02</code><br>
            Key: <code>0123456789ABCDEF</code><br>
            Expected Result: <code>F01F830BFF4EF82B11579D6EDA5D1AA5</code>
        </div>

        <!-- Encryption Section -->
        <div class="section">
            <h2>Encryption</h2>
            <label for="plaintext">Plaintext (Hex, spaces allowed):</label>
            <textarea id="plaintext" placeholder="Enter hex text to encrypt (e.g., 8c a3 64 fc 00 00 00 00 7e 32 5f 46 7e 32 5f 02)">8c a3 64 fc 00 00 00 00 7e 32 5f 46 7e 32 5f 02</textarea>
            
            <label for="encryptKey">Encryption Key (16 characters):</label>
            <input type="text" id="encryptKey" placeholder="Enter 16-character key (e.g., 0123456789ABCDEF)" value="0123456789ABCDEF" maxlength="16">
            
            <button onclick="encryptText()">Encrypt (SM4-ECB)</button>
            
            <div class="result" id="encryptedResult">
                Encrypted result will appear here...
            </div>
        </div>

        <!-- Decryption Section -->
        <div class="section">
            <h2>Decryption</h2>
            <label for="ciphertext">Ciphertext (Hex, spaces allowed):</label>
            <textarea id="ciphertext" placeholder="Enter encrypted text in hex format..."></textarea>
            
            <label for="decryptKey">Decryption Key (16 characters):</label>
            <input type="text" id="decryptKey" placeholder="Enter 16-character key" maxlength="16">
            
            <button onclick="decryptText()">Decrypt (SM4-ECB)</button>
            
            <div class="result" id="decryptedResult">
                Decrypted result will appear here...
            </div>
        </div>
    </div>

    <script>
        // ==============================================
        // SM4 Implementation
        // ==============================================
        
        const SM4 = (function() {
            // S-box table
            const SBOX = [
                0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
                0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
                0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
                0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
                0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
                0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
                0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
                0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
                0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
                0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
                0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
                0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
                0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
                0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
                0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
                0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
            ];

            // System parameters FK
            const FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc];

            // Fixed parameter CK
            const CK = [
                0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
                0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
                0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
                0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
                0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
                0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
                0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
                0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
            ];

            // Rotate left function
            function rotl(x, n) {
                return ((x << n) | (x >>> (32 - n))) >>> 0;
            }

            // Tau transformation (S-box substitution)
            function tau(a) {
                return (SBOX[(a >>> 24) & 0xff] << 24) |
                       (SBOX[(a >>> 16) & 0xff] << 16) |
                       (SBOX[(a >>> 8) & 0xff] << 8) |
                       SBOX[a & 0xff];
            }

            // L transformation
            function l(b) {
                return b ^ rotl(b, 2) ^ rotl(b, 10) ^ rotl(b, 18) ^ rotl(b, 24);
            }

            // L' transformation
            function l2(b) {
                return b ^ rotl(b, 13) ^ rotl(b, 23);
            }

            // T transformation
            function t(z) {
                return l(tau(z));
            }

            // T' transformation
            function t2(z) {
                return l2(tau(z));
            }

            // Key expansion
            function expandKey(key) {
                const mk = new Uint32Array(4);
                for (let i = 0; i < 4; i++) {
                    mk[i] = ((key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3]) ^ FK[i];
                }

                const rk = new Uint32Array(32);
                const k = new Uint32Array(36);
                for (let i = 0; i < 4; i++) {
                    k[i] = mk[i];
                }

                for (let i = 0; i < 32; i++) {
                    k[i + 4] = k[i] ^ t2(k[i + 1] ^ k[i + 2] ^ k[i + 3] ^ CK[i]);
                    rk[i] = k[i + 4];
                }

                return rk;
            }

            // One round of encryption/decryption
            function round(x, rk) {
                return x[0] ^ t(x[1] ^ x[2] ^ x[3] ^ rk);
            }

            // Main encryption function
            function encrypt(input, key) {
                const rk = expandKey(key);
                const output = new Uint8Array(input.length);
                
                for (let i = 0; i < input.length; i += 16) {
                    const x = new Uint32Array(4);
                    for (let j = 0; j < 4; j++) {
                        x[j] = ((input[i + j * 4] << 24) | 
                                (input[i + j * 4 + 1] << 16) | 
                                (input[i + j * 4 + 2] << 8) | 
                                input[i + j * 4 + 3]);
                    }

                    for (let j = 0; j < 32; j++) {
                        const tmp = round(x, rk[j]);
                        x[0] = x[1];
                        x[1] = x[2];
                        x[2] = x[3];
                        x[3] = tmp;
                    }

                    // Reverse last round
                    const tmp = x[0];
                    x[0] = x[3];
                    x[3] = tmp;
                    const tmp2 = x[1];
                    x[1] = x[2];
                    x[2] = tmp2;

                    for (let j = 0; j < 4; j++) {
                        output[i + j * 4] = (x[j] >>> 24) & 0xff;
                        output[i + j * 4 + 1] = (x[j] >>> 16) & 0xff;
                        output[i + j * 4 + 2] = (x[j] >>> 8) & 0xff;
                        output[i + j * 4 + 3] = x[j] & 0xff;
                    }
                }
                
                return output;
            }

            // Decryption is identical to encryption except reverse key order
            function decrypt(input, key) {
                const rk = expandKey(key);
                const output = new Uint8Array(input.length);
                
                for (let i = 0; i < input.length; i += 16) {
                    const x = new Uint32Array(4);
                    for (let j = 0; j < 4; j++) {
                        x[j] = ((input[i + j * 4] << 24) | 
                                (input[i + j * 4 + 1] << 16) | 
                                (input[i + j * 4 + 2] << 8) | 
                                input[i + j * 4 + 3]);
                    }

                    for (let j = 0; j < 32; j++) {
                        const tmp = round(x, rk[31 - j]);
                        x[0] = x[1];
                        x[1] = x[2];
                        x[2] = x[3];
                        x[3] = tmp;
                    }

                    // Reverse last round
                    const tmp = x[0];
                    x[0] = x[3];
                    x[3] = tmp;
                    const tmp2 = x[1];
                    x[1] = x[2];
                    x[2] = tmp2;

                    for (let j = 0; j < 4; j++) {
                        output[i + j * 4] = (x[j] >>> 24) & 0xff;
                        output[i + j * 4 + 1] = (x[j] >>> 16) & 0xff;
                        output[i + j * 4 + 2] = (x[j] >>> 8) & 0xff;
                        output[i + j * 4 + 3] = x[j] & 0xff;
                    }
                }
                
                return output;
            }

            return {
                encrypt,
                decrypt
            };
        })();

        // ==============================================
        // Utility Functions
        // ==============================================

        function cleanHexString(hex) {
            return hex.replace(/\s+/g, '').toLowerCase();
        }

        function hexStringToBytes(hex) {
            const cleaned = cleanHexString(hex);
            if (cleaned.length % 2 !== 0) {
                throw new Error("Hex string must have even number of characters");
            }
            const bytes = new Uint8Array(cleaned.length / 2);
            for (let i = 0; i < cleaned.length; i += 2) {
                const byte = parseInt(cleaned.substr(i, 2), 16);
                if (isNaN(byte)) {
                    throw new Error("Invalid hex character");
                }
                bytes[i/2] = byte;
            }
            return bytes;
        }

        function bytesToHexString(bytes) {
            return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        }

        function stringToBytes(str) {
            const bytes = new Uint8Array(str.length);
            for (let i = 0; i < str.length; i++) {
                bytes[i] = str.charCodeAt(i) & 0xff;
            }
            return bytes;
        }

        // ==============================================
        // UI Functions
        // ==============================================

        function encryptText() {
            try {
                const plaintextHex = document.getElementById("plaintext").value;
                const key = document.getElementById("encryptKey").value;
                
                if (!plaintextHex) {
                    alert("Please enter hex text to encrypt!");
                    return;
                }
                
                if (!key || key.length !== 16) {
                    alert("Encryption key must be exactly 16 characters!");
                    return;
                }
                
                // Convert hex string to bytes
                const plaintextBytes = hexStringToBytes(plaintextHex);
                const keyBytes = stringToBytes(key);
                
                // Encrypt using SM4-ECB
                const encryptedBytes = SM4.encrypt(plaintextBytes, keyBytes);
                const encryptedHex = bytesToHexString(encryptedBytes);
                
                document.getElementById("encryptedResult").innerText = encryptedHex;
                document.getElementById("ciphertext").value = encryptedHex;
            } catch (error) {
                alert("Encryption failed: " + error.message);
                console.error(error);
            }
        }

        function decryptText() {
            try {
                const ciphertextHex = document.getElementById("ciphertext").value;
                const key = document.getElementById("decryptKey").value;
                
                if (!ciphertextHex) {
                    alert("Please enter hex ciphertext to decrypt!");
                    return;
                }
                
                if (!key || key.length !== 16) {
                    alert("Decryption key must be exactly 16 characters!");
                    return;
                }
                
                // Convert hex string to bytes
                const encryptedBytes = hexStringToBytes(ciphertextHex);
                const keyBytes = stringToBytes(key);
                
                // Decrypt using SM4-ECB
                const decryptedBytes = SM4.decrypt(encryptedBytes, keyBytes);
                const decryptedHex = bytesToHexString(decryptedBytes);
                
                document.getElementById("decryptedResult").innerText = decryptedHex;
            } catch (error) {
                alert("Decryption failed: " + error.message);
                console.error(error);
            }
        }
    </script>
</body>
</html>
