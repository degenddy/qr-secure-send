# QR Secure Send

Transfer a secret between trusted devices using an encrypted QR code or link. Encryption runs in the browser using Web Crypto. Passwords are optional and recommended. Transfers may use a password, a wallet, both, or neither.

## Run

Use Node.js 22 or later (`nvm use` if you use nvm), then:

```sh
npm start
```

Open **http://127.0.0.1:3000**. The server binds only to loopback, checks the Host header, and serves only the application HTML. An optional port is supported: `node cli.js 8080`.

You can also open `index.html` directly. Camera and clipboard availability depends on browser permissions and secure-context support.

## Send and receive

1. Enter a secret (multiline text is supported; textarea line endings use LF). **Conceal secret length** is checked by default: it pads to the next 128, 256, 512, 1024 or 1536-byte capacity. Uncheck it for an unpadded, smaller QR. You can leave the password blank for a direct camera transfer, enter your own password, or choose **Generate random password**. A password is recommended; save it before leaving the Send tab if you use one.
2. Optionally connect your wallet. Wallet-only transfers work without a password. If both are set, both are needed to decrypt. Creation requests the same signature twice and rejects inconsistent or unsupported signatures.
3. Generate the QR code. If you set a password, share it through a separate trusted channel. For wallet transfers, reveal and securely save the recovery key separately from the QR/link. It substitutes for the wallet; it does not bypass a password.
4. In a trusted receiver copy, scan the QR code, enter the password if one was set, and click **Decrypt**. Scanning alone never requests a wallet signature.
5. Confirm successful decryption on the receiving device before deleting the original secret. Then clear the page and clipboard. Wallet transfers can also be received using the saved recovery key instead of a wallet connection.

Generated QR codes contain a link to the GitHub Pages app. **Deploy version 2.3 before distributing new QR links.** New transfers use version 5 (`QRSEC5` or `QRSECW5`). Version 2.3 still reads versions 1–4 with their original password derivation and signing messages. Older apps cannot read version 5. Existing transfers retain their original padding; re-encrypt to use the new sizing option.

## Security controls

- AES-256-GCM with a new 16-byte random salt and 12-byte random IV per encryption.
- PBKDF2-HMAC-SHA256 with **600,000 iterations** for versions 2–5. Version 1 recovery retains 310,000 iterations. Versions 2–5 also authenticate a protocol label using GCM additional data; there is no automatic downgrade retry.
- Versions 4–5 use Unicode **NFC** password normalization before key derivation; canonically equivalent accents and composed/decomposed keyboard input work interchangeably. Case, whitespace and compatibility characters remain distinct. The secret itself is not normalized. Strength checking assesses the same NFC password form. Legacy formats retain their exact old derivation.
- Version 5 encrypts a one-byte padding mode, a four-byte big-endian UTF-8 length, and up to 1500 secret bytes. Padding is enabled by default and uses the smallest capacity that fits: **128, 256, 512, 1024 or 1536 bytes**, plus the five-byte header. The final step keeps maximum-size wallet transfers within one QR. Unused bytes contain cryptographic randomness. Each padded packet contains 49 bytes of header/salt/IV/tag overhead plus its capacity; compact packets contain 49 bytes plus the actual secret bytes. The receiver authenticates the mode and length before interpreting them, requires the canonical smallest bucket (or exact unpadded length), and rejects unknown modes, oversized lengths and invalid UTF-8. Padding hides the exact length **within a bucket**, not the size range; 12-word versus 24-word phrases can still fall in different buckets. Compact mode exposes the exact UTF-8 byte length to someone inspecting the packet. Wallet mode and protocol version remain visible. Actual camera readability depends on display and camera quality.
- Legacy version 4 retains its fixed 1504-byte envelope and exactly 1548-byte encrypted packet. New transfers use version 5; its different authenticated protocol label prevents relabelling between formats.
- Transfer parsing requires canonical base64 and enough decoded bytes for the salt, IV and authentication tag. Invalid packets are rejected before password derivation; version 4 requires exactly 1548 decoded bytes and version 5 permits only 49–1585 bytes before its authenticated inner structure is checked.
- Generated passwords contain **32 random characters**, always including uppercase letters, lowercase letters, numbers and special characters. They use `crypto.getRandomValues` with unbiased sampling from printable ASCII (no spaces); candidates missing a required character class are regenerated. Typed passwords are checked locally using bundled [zxcvbn 4.4.2](https://github.com/dropbox/zxcvbn), which detects common words, substitutions, sequences, dates and repetition. The app displays manual passwords in orange, using the estimator's 0–4 score on an app scale capped at **4/5** for manual input. Green **5/5** is reserved for an unedited password generated in the current session; it indicates how the password was created, not a guarantee of security. Editing or pasting a password returns it to manual feedback. Estimates are not measured entropy or guaranteed cracking times. Feedback is advisory: a weak password does not block generation. The primarily English dictionaries cannot recognize every weak password. For responsiveness, only the first 100 characters are assessed; the UI says so, and encryption still uses the full password (up to 1024 characters).
- Without a password or wallet, the encryption key is derived from the known empty string: **anyone with the QR code or link can read the secret**. This is suitable only when you accept that exposure. Clearing the display does not expire or revoke captured copies. The app cannot guarantee that a camera, screenshot, browser history or another observer retained nothing.
- Changing the secret, passphrase, wallet option or padding option clears the previous QR/link and recovery key. Encryption locks those controls and checks both their values and an edit counter after asynchronous operations before publishing. Re-enter the secret and generate again after changing settings; an existing QR never silently gains new protection.
- Decrypted values are rendered as text and initially hidden. Leading U+FEFF characters are preserved by the UTF-8 decoder in all formats. Sender plaintext clears after successful encryption; receiver password clears after successful decryption.
- Secret and passphrase fields request no spellchecking, autocorrection or automatic capitalization, including while revealed. The secret uses a visually masked textarea instead of a password field; unsupported masking disables secret entry. Passphrase fields use `autocomplete="one-time-code"` to discourage login-password saving and autofill. These are browser hints, not a guarantee against password managers, keyboard learning or extensions that can read page content. Use trusted browser extensions and keyboards.
- Clear/reset and tab changes remove sensitive fields. Two minutes of inactivity or 30 seconds in the background clears the session. Expiry uses wall-clock and monotonic deadlines, checked before interaction, on foreground/resume/focus, and before pending operations return results. Suspended timers cannot extend the session. Where supported, the freeze event clears the session immediately; otherwise an overdue session clears when execution resumes. Pending operations cannot repopulate a cleared session. Camera permission responses that arrive after stopping are closed.
- Incoming ciphertext is removed from the current URL/history entry and retained in memory. This cannot erase earlier browser history, shared links, screenshots or external copies.
- Clipboard writes require an explicit click. **Clear clipboard** overwrites the current clipboard when permitted, but cannot erase clipboard-manager history or copies synced to other devices. Clipboard contents do not automatically expire.
- Content Security Policy pins the inline application script and blocks ordinary network connections, forms and unapproved scripts. The local server also prevents framing and sends `Cache-Control: no-store`.
- The page starts hidden and only becomes visible after successful top-level initialization. Framed copies abort initialization; frames with scripts disabled remain hidden. This provides a hosted-copy safeguard where HTTP framing headers are unavailable; hosting with `Content-Security-Policy: frame-ancestors 'none'` remains stronger. Incoming link changes require confirmation before replacing an active session, and invalid links leave it intact. Expiry is checked after the confirmation dialog closes. This protects same-page transfer replacement, not forced full-page navigation by another site; browser-level opener isolation requires a `Cross-Origin-Opener-Policy` response header.

### Scanner fingerprint

The fallback scanner, **jsQR 1.4.0**, is bundled directly in `index.html`. Native `BarcodeDetector` is used where available. Both paths work without a scanner download; a downloaded trusted copy can scan offline.

The unchanged 256,885-byte distribution comes from `https://cdn.jsdelivr.net/npm/jsqr@1.4.0/dist/jsQR.js`. Its saved SHA-384 fingerprint is:

```text
sha384-b5Ya4Bq3qCyz39m2ISh+4DxjAIljdeFwK/BsXLuj9gugaNwAcj/ia15fxNZL9Nlx
```

Open **Scanner integrity → Verify bundled scanner** to check it. Web Crypto hashes the exact embedded library source before its initializer is invoked. A mismatch or unavailable verification blocks the fallback scanner and camera acquisition. The app's CSP also pins the complete inline script and allows no external scripts. No dynamic code evaluation is used.

This is a **content fingerprint, not a publisher's digital signature or a safety certification**. A modified app could replace both code and fingerprints. The bundled scanner executes with page privileges; trust the app source and browser environment.

jsQR's [Apache 2.0 license](https://github.com/cozmo/jsQR/blob/master/LICENSE) permits redistribution with its license and applicable notices. The full upstream license is embedded alongside the library, so it travels with the single HTML file. The published 1.4.0 package contains no separate NOTICE file. The library bytes are unchanged; a surrounding initializer keeps its export private and defers initialization until verification.

### Wallet limitations

A wallet signature is used as additional key material, **not as proof of the sender's identity**. Versions 4–5 canonicalize 00/01 and 1b/1c recovery bytes, letter casing, equivalent high-s/low-s signatures, and [ERC-2098 compact signatures](https://eips.ethereum.org/EIPS/eip-2098). Scalar ranges and recovery bytes are checked. This is encoding normalization, not verification of the signer identity. Creation requests the same message twice and blocks differing canonical signatures before encrypting or clearing the original input. Arbitrary smart-contract signatures are unsupported; many MPC wallets cannot provide repeatable signatures. Rejecting these formats does not imply all MPC or contract wallets behave identically.

Two matching signatures cannot guarantee compatibility with another wallet or future software. Save the **transfer-specific recovery key**, and keep your original secret until the receiver successfully decrypts it. The recovery key contains the nonce and canonical signature (not your private key); it is equivalent to this transfer's wallet factor and must be kept separately from the QR/link. Any password remains required. It is masked until explicitly revealed, excluded from the QR/link, and cleared on reset, tab changes and expiry. Receiving by recovery key never contacts a wallet. Real hardware-wallet and mobile-wallet compatibility has not been verified here. Password-only protection with a strong generated password is the simpler, more portable option.

The signing prompt describes the key-disclosure risk. With wallet-only protection, obtaining the signature is enough to decrypt the corresponding transfer. Adding a separate password prevents the signature alone from unlocking it. A malicious page could still request the same signature, and a compromised application could capture both factors. Only approve signing in your trusted copy. Domain wording in a message is not browser-enforced origin binding. Wallet-only transfers, new and legacy, retain this signature-disclosure risk. The app recommends a password but allows you to proceed without one.

## Development and verification

There are no npm dependencies. jsQR 1.4.0 (Apache 2.0) and zxcvbn 4.4.2 (MIT) are bundled inside the HTML with their licenses; checking a password makes no network request. Tests use Node's built-in test runner:

```sh
npm test
npm audit
```

After changing the inline application script, regenerate its CSP hash:

```sh
npm run csp:update
npm test
```

The main suite contains **362 tests**, including **274 added security regression tests** beyond the previous 88. Every table-driven case is individually named; the deterministic malformed-input corpus is counted as one test, not 500. The main suite has no package dependencies and opens a temporary loopback listener for HTTP tests.

| Test file | Coverage |
| --- | --- |
| `security-crypto.test.js` | Independent Node/OpenSSL fixtures for protocol versions 1–3, altered salt/IV/ciphertext/tag, truncation, appended bytes, version relabelling, non-exportable keys, Unicode and randomness sources |
| `security-protocol.test.js` | Valid formats, malformed packets, size boundaries, canonical encoding, deterministic malformed-input corpus, wallet request validation and signature rejection |
| `security-lifecycle.test.js` | Pending-operation cancellation, transfer replacement, byte and password limits, clipboard failures, input privacy and expiry |
| `security-scanner.test.js` | Integrity failures, camera permission and preview races, scan-loop expiry, cancellation and wallet-signing separation |
| `security-server.test.js` | Real HTTP requests covering Host validation, methods, path traversal, source-file disclosure, security headers and denied-response caching |
| `security-v4.test.js` | Independent padded/NFC crypto vectors, signature canonicalization, wallet consistency checks, recovery and lifecycle protections |
| `security-v5.test.js` | Independent padded/compact OpenSSL fixtures, all padding boundaries, authenticated format rejection, BOM preservation, v4 recovery compatibility, stale QR invalidation and pending-input changes |
| `security.test.js`, `test.js` | Earlier cryptography, QR generation, optional-password, integrity, framing and session regressions |

These tests exposed and now cover a decoded-packet length validation gap and camera operations that could continue after a suspended session expired. Camera validity is checked after acquisition, after preview startup and on every scan frame. Valid transfers produced by older versions remain compatible.

### Optional Chrome checks

`browser-security.test.cjs` adds **24 real-browser tests** for input masking/privacy settings, transfer confirmation, inert plaintext rendering, offline QR decoding, maximum-size padded QR decoding, Unicode passwords, recovery-key privacy and decryption, CSP and bundled-scanner integrity enforcement, framing with and without scripts, suspended timers and late camera responses. These are separate from the 362 tests above. New browser regressions cover multiline/BOM preservation, stale-QR invalidation for every sender setting, locked/pending input changes, decoding every padding bucket and compact mode, and the maximum padded wallet QR.

Use a separately installed Playwright package and Chrome, then run:

```sh
QR_TEST_PLAYWRIGHT=/absolute/path/to/playwright npm run test:browser
```

If Playwright is already available through Node's module resolution, `npm run test:browser` is sufficient. No browser-test dependency is included in the shipped application. All browser scenarios use dummy secrets and local pages; the modified scanner response is intercepted locally.

The main suite uses real Web Crypto/OpenSSL for encryption and a small simulated DOM for deterministic lifecycle tests. The Chrome suite exercises the browser itself, but camera responses, suspended time and wallet providers are simulated. Neither suite proves behavior during physical device sleep, across all mobile keyboards/password managers, or with real hardware wallets. The npm audit does **not** cover the bundled scanner or password estimator. A passing test suite is not an independent security audit or a guarantee that the application is unbreakable. An independent review and testing on intended devices remain useful next steps; [OWASP's testing guide](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/) describes broader security testing areas.

Do not update the scanner's fingerprint merely to bypass a mismatch. Review the replacement file and update the bundled bytes, provenance and fingerprint together.

## License

MIT. Provided without warranty. No browser application can protect secrets from a compromised browser, malicious extension with sufficient access, or an untrusted application build. Clearing JavaScript references is not a guarantee of physical memory erasure.

Bundled estimator provenance: `https://cdn.jsdelivr.net/npm/zxcvbn@4.4.2/dist/zxcvbn.js`; original downloaded file SHA-384: `2d7b8ff2592748604e2d59f87f054e97ead647ecce12d671e8217d64b68dea028180b0725380fbf555968d5e3f81e7ea`. The unused source-map reference was removed when embedding it; the app's CSP hash covers the embedded bytes.
