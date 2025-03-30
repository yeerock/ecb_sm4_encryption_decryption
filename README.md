# SM4-ECB Encryption Tool

![SM4 Encryption](https://img.shields.io/badge/Algorithm-SM4-blue)
![ECB Mode](https://img.shields.io/badge/Mode-ECB-yellow)
![Pure JavaScript](https://img.shields.io/badge/Pure-JavaScript-success)

A web-based implementation of the SM4 block cipher in ECB (Electronic Codebook) mode, compliant with the Chinese national standard GB/T 32907-2016.

## Features

- 🔒 SM4 encryption/decryption with 128-bit keys
- 🖥️ Pure JavaScript implementation (no dependencies)
- 🔢 Hex input/output with space formatting support
- ✅ Built-in test case for verification
- 📱 Responsive design works on all devices
- ⚠️ Clear ECB mode security warnings

## Security Notice

**Warning:** ECB mode is not secure for most real-world applications as it reveals patterns in your data. This implementation should only be used for:

- Educational purposes
- Algorithm testing
- Debugging and development

## Installation

No installation required - just open the HTML file in any modern browser:

```bash
git clone https://github.com/yourusername/sm4-ecb-tool.git
cd sm4-ecb-tool
open index.html

Usage
Encryption
Enter plaintext in hex format (spaces allowed)

Enter 16-character (128-bit) encryption key

Click "Encrypt" button

View encrypted result

Decryption
Enter ciphertext in hex format

Enter original 16-character key

Click "Decrypt" button

View decrypted result

Test Case
Verify correct operation with built-in test:

Plaintext: 8c a3 64 fc 00 00 00 00 7e 32 5f 46 7e 32 5f 02

Key: 0123456789ABCDEF

Expected: F01F830BFF4EF82B11579D6EDA5D1AA5

Technical Specifications
Parameter	Value
Algorithm	SM4
Block Size	128 bits
Key Length	128 bits
Rounds	32
Mode	ECB
Standard	GB/T 32907-2016
Browser Support
✅ Chrome
✅ Firefox
✅ Safari
✅ Edge
✅ Opera

Contributing
Contributions are welcome! Please open an issue or pull request for:

Bug fixes

Security improvements

Feature enhancements

License
MIT License - See LICENSE file for details


This README includes:

1. Badges for quick visual identification
2. Clear security warnings upfront
3. Installation and usage instructions
4. Technical specifications table
5. Browser compatibility
6. Contribution guidelines
7. License information

The formatting uses standard GitHub Markdown with:
- Headers and sections
- Code blocks
- Tables
- Lists
- Emojis for visual cues

You can copy this directly into a `README.md` file in your project root. Just replace `yourusername` with your actual GitHub username in the installation instructions.
