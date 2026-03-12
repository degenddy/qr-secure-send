# QR Secure Send

Encrypt and transfer secrets (passwords, keys, tokens) between devices via QR code. Everything runs client-side — no data leaves your browser.

## How It Works

1. **Sender** enters a secret and a shared passphrase, then generates a QR code
2. **Receiver** enters the same passphrase, opens the camera, and scans the QR code
3. The secret is decrypted and displayed on the receiver's device

## Security

- **AES-256-GCM** authenticated encryption
- **PBKDF2** key derivation with 310,000 iterations
- Random salt and IV per encryption — no key reuse
- Fully client-side — zero network requests for your data

## Quick Start

```bash
npm start
```

Opens on [http://localhost:3000](http://localhost:3000).

> Camera access requires HTTPS or localhost.

## License

MIT
