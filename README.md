# QR Secure Send

Encrypt and transfer secrets (passwords, keys, tokens) between devices via QR code. Everything runs client-side — no data leaves your browser.

## How It Works

1. **Sender** enters a secret and a shared passphrase, then generates a QR code
2. **Receiver** enters the same passphrase, opens the camera, and scans the QR code
3. The secret is decrypted and displayed on the receiver's device

## Security

- **AES-256-GCM** authenticated encryption via the [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) (browser built-in)
- **PBKDF2** key derivation with 310,000 iterations
- Random salt and IV per encryption — no key reuse
- Fully client-side — zero network requests for your data
- **Zero external dependencies** — QR generation is implemented inline, QR scanning uses the native [BarcodeDetector API](https://developer.mozilla.org/en-US/docs/Web/API/BarcodeDetector). The entire source is in a single HTML file that can be read and audited.

## Browser Support

| Feature | Chrome | Edge | Safari | Firefox |
|---------|--------|------|--------|---------|
| QR Generation | Yes | Yes | Yes | Yes |
| QR Scanning | Yes | Yes | Yes (17.2+) | No* |

\* Firefox does not support the BarcodeDetector API.

## Quick Start

```bash
npm start
```

Opens on [http://localhost:3000](http://localhost:3000).

Or just open `index.html` directly in your browser (camera scanning requires localhost or HTTPS).

### Global install

```bash
npm install -g qr-secure-send
qr-secure-send        # starts on port 3000
qr-secure-send 8080   # custom port
```

### One-time use

```bash
npx qr-secure-send
```

## Dependencies

This project uses **no runtime JavaScript dependencies**. Everything — encryption, QR code generation, and QR scanning — is implemented using browser-native APIs and inline code.

The only dev/CLI dependency is [`serve`](https://www.npmjs.com/package/serve) (fetched on-demand via `npx`) to host the static file locally.

## Disclaimer

This software is provided **"as is"**, without warranty of any kind, express or implied. Use it at your own risk.

While this tool uses standard, well-regarded cryptographic primitives (AES-256-GCM, PBKDF2) via the browser's built-in Web Crypto API, **it has not been independently audited**. The authors are not responsible for any data loss, security breaches, or damages resulting from the use of this software.

Do not rely on this tool as your sole security measure for highly sensitive data. Always follow security best practices.

## License

MIT
