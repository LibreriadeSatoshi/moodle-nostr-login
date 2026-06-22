# auth_nostr — Nostr Authentication for Moodle

A Moodle authentication plugin that lets users log in using their Nostr keypair via a browser extension (NIP-07). No password required. No email required. Just a Nostr key.

Tested on **Moodle 5.1**. Requires **PHP 8.1+** with the **GMP extension**.

---

## How it works

```
Browser                                    Moodle (PHP)
  │                                            │
  │  1. Click "Log in with Nostr"              │
  │───────────────────────────────────────────>│
  │                                            │
  │  2. GET /auth/nostr/login.php?action=challenge
  │<───────────────────────────────────────────│
  │     { nonce: "abc123…", url: "https://…" } │
  │                                            │
  │  3. window.nostr.getPublicKey()            │
  │     (browser extension prompt)             │
  │                                            │
  │  4. WebSocket → relay (kind 0)             │
  │     fetch display name (3s timeout)        │
  │                                            │
  │  5. window.nostr.signEvent({               │
  │       kind: 27235,                         │
  │       tags: [                              │
  │         ["u",         loginUrl],           │
  │         ["method",    "POST"],             │
  │         ["challenge", nonce]               │
  │       ]                                    │
  │     })  ← NIP-98 HTTP Auth event           │
  │                                            │
  │  6. POST /auth/nostr/login.php             │
  │     { event: signedEvent, metadata }       │
  │───────────────────────────────────────────>│
  │                                            │  Validate:
  │                                            │  ✓ kind == 27235
  │                                            │  ✓ |now - created_at| ≤ 60s
  │                                            │  ✓ challenge matches session
  │                                            │  ✓ url tag matches endpoint
  │                                            │  ✓ BIP340 Schnorr signature (GMP)
  │                                            │
  │                                            │  Find or create Moodle user:
  │                                            │  username = nostr_{hex16}
  │                                            │  firstname = kind-0 display_name
  │                                            │
  │  7. { redirect: "/dashboard" }             │
  │<───────────────────────────────────────────│
  │                                            │
  │  8. window.location.href = redirect        │
  │     (Moodle session active)                │
```

### Security properties

- The server never sees a private key — signing happens in the browser extension.
- The challenge nonce is single-use and expires after 120 seconds.
- The signed event's timestamp must be within 60 seconds of the server clock (replay protection).
- Signature verification uses a pure PHP BIP340 Schnorr implementation over secp256k1.

---

## Supported login methods

| Method | Status | Notes |
|---|---|---|
| NIP-07 browser extension | ✅ MVP | Alby, nos2x, Flamingo, Nostore… |
| NIP-46 remote signer (bunker) | 🔜 Planned | Requires persistent WebSocket |
| nsec (private key) | 🔜 Planned | Signs in-browser, key never sent |

---

## Requirements

| Requirement | Version |
|---|---|
| Moodle | 5.1+ |
| PHP | 8.1+ |
| PHP GMP extension | any |

**No Composer, no external dependencies.** The plugin is fully self-contained.

---

## Installation

### Option A — Manual (recommended)

1. Copy the `auth/nostr/` folder into your Moodle installation:
   ```
   cp -r moodle-nostr-login  /path/to/moodle/auth/nostr
   ```

2. Run the Moodle upgrade:
   ```bash
   php admin/cli/upgrade.php --non-interactive
   ```
   Or visit **Site administration → Notifications** in your browser.

3. Enable the plugin:
   **Site administration → Plugins → Authentication → Manage authentication**
   → Enable **Nostr**.

4. Configure the relay (optional):
   **Site administration → Plugins → Authentication → Nostr**
   Default relay: `wss://relay.damus.io`

### Option B — Zip upload

Zip the contents of this repository and upload via
**Site administration → Plugins → Install plugins**.

### PHP GMP extension

GMP is required for BIP340 Schnorr signature verification.

```bash
# Debian / Ubuntu
apt-get install php8.4-gmp   # adjust version to your PHP

# After installing, restart your web server
systemctl restart apache2
# or
systemctl restart php8.4-fpm
```

Verify it is loaded:
```bash
php -m | grep gmp
```

---

## How users are created

On first login with a new Nostr key, Moodle automatically creates an account:

| Field | Value |
|---|---|
| `username` | Full npub — e.g. `npub1e2ywrmv…` |
| `firstname` | `display_name` or `name` from Nostr kind-0 profile, or shortened npub `npub1e2ywrmvx…whnz` as fallback |
| `lastname` | `Nostr` |
| `email` | `{npub}@{your-moodle-domain}` |
| `idnumber` | Full hex pubkey (for future account linking) |
| `nostrpubkey` profile field | Full npub (visible on public profile) |

Auto-creation can be disabled in the plugin settings, allowing only pre-existing accounts to log in via Nostr.

### Linking a Nostr key to an existing account

The install hook creates a custom profile field **"Nostr Public Key (npub)"** (`nostrpubkey`). Users or admins can fill this field to associate any Moodle account with a Nostr public key. Full account-linking logic is planned for a future release.

---

## Admin settings

| Setting | Default | Description |
|---|---|---|
| Relay | `wss://relay.damus.io` | WebSocket relay for fetching kind-0 profile metadata on first login |
| Auto-create accounts | Enabled | Create a Moodle account for any valid Nostr key |

---

## File structure

```
auth/nostr/
├── version.php                   # Plugin metadata (Moodle 5.1+)
├── auth.php                      # Auth plugin class — injects login button
├── login.php                     # Challenge (GET) + verify (POST) endpoint
├── settings.php                  # Admin settings page
├── lang/
│   └── en/
│       └── auth_nostr.php        # English strings
├── classes/
│   ├── schnorr.php               # BIP340 Schnorr verification (pure PHP/GMP)
│   ├── nostr_event.php           # Event ID, signature verification, npub encoding
│   └── privacy/
│       └── provider.php          # Moodle Privacy API
├── db/
│   └── install.php               # Creates "Nostr Identity" profile field
├── tests/
│   ├── test_security.py          # Python security test suite (pytest)
│   └── requirements.txt          # requests, pytest
└── amd/
    ├── src/
    │   └── nostr_login.js        # Source: NIP-07 + NIP-98 client logic
    └── build/
        └── nostr_login.min.js    # Pre-built for production
```

---

## Development

### Prerequisites

- Moodle 5.1 development environment
- PHP 8.1+ with GMP
- A Nostr browser extension for manual testing (Alby, nos2x)
- Node.js + grunt-cli (only if you modify the JavaScript)

### Setup

```bash
# Clone alongside Moodle
cd /path/to/moodle
git clone https://github.com/your-org/moodle-nostr-login auth/nostr

# Run Moodle upgrade
php admin/cli/upgrade.php --non-interactive
```

Enable developer mode in `config.php` to load JS from `amd/src/` directly:
```php
$CFG->debugdeveloper = true;
$CFG->cachejs        = false;
```

### Rebuilding the AMD module

If you modify `amd/src/nostr_login.js`, rebuild the minified file:

```bash
cd /path/to/moodle
npm install
npx grunt amd --plugin=auth_nostr
```

Or manually update `amd/build/nostr_login.min.js` (a single-file define() module).

### Security tests

The test suite hits the live `login.php` endpoint and verifies every rejection path.
No Moodle-specific tooling required — just Python.

```bash
pip install -r tests/requirements.txt
pytest tests/test_security.py -v
```

To run against a non-local instance:

```bash
MOODLE_URL=https://staging.example.com pytest tests/test_security.py -v
```

| Category | Cases |
|---|---|
| Happy path | Valid login, login with kind-0 metadata |
| Replay protection | Nonce reuse, expired event (>60 s), future event |
| Signature verification | Zeroed sig, tampered ID, wrong pubkey, sig from different key |
| Protocol checks | No prior challenge, wrong nonce, wrong URL tag, wrong method/kind, GET on POST endpoint |
| Input validation | Empty body, non-JSON, missing `event` field, missing `sig`/`id` |

The pure-Python BIP340 Schnorr implementation inside the test file has no external
crypto dependencies — `requests` and `pytest` are the only packages required.

---

### Key files for contributors

| File | What to touch |
|---|---|
| `classes/schnorr.php` | Schnorr math — only if BIP340 spec changes |
| `classes/nostr_event.php` | Event serialization / tag parsing |
| `login.php` | Server-side validation logic |
| `amd/src/nostr_login.js` | All client-side UX and NIP protocol logic |
| `auth.php` | Moodle auth integration hooks |

### Adding a new login method (e.g. nsec)

1. Add the client-side signing logic in `amd/src/nostr_login.js` — the `handleLogin` function already receives a signed event, so only the signing step changes.
2. The server-side `login.php` does not need changes — it validates whatever signed event arrives.

### Adding NIP-46 (remote signer / bunker)

NIP-46 requires a persistent WebSocket connection with the bunker. Suggested approach:

1. Add a `bunker_connect.php` endpoint that proxies the NIP-46 handshake.
2. Use a JS `BunkerSigner` class that handles the `connect` / `sign_event` request-response flow.
3. Once the remote signer produces a signed event, the existing `login.php` verify flow handles it without changes.

---

## NIPs implemented

| NIP | Description | Role |
|---|---|---|
| NIP-01 | Basic protocol flow | Event format, ID computation |
| NIP-07 | Browser extension API | `window.nostr.getPublicKey()`, `signEvent()` |
| NIP-98 | HTTP Auth | Kind-27235 signed event as login proof |

---

## License

MIT — see [LICENSE](LICENSE).

---

## Contributing

Pull requests welcome. Please open an issue first for significant changes.

When submitting a PR:
- Run `php -l` on all PHP files.
- Test with at least one NIP-07 extension (Alby recommended).
- If you change `schnorr.php`, add a test vector from the BIP340 spec.
