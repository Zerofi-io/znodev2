# ZNode v3 - Production Setup (Sepolia)

## 1. Requirements

- Linux server or VPS with public IP
- Node.js >= 18
- `monero-wallet-rpc` installed and in `$PATH`
- `git` and `npm`

## 2. Install

- `git clone https://github.com/Zerofi-io/znodev2.git`
- `cd znodev2`
- `npm ci`  (or `npm install`)

## 3. Configure `.env` for production

- `cp .env.example .env`
- Edit `.env` and set for each node:
  - `PRIVATE_KEY=0xYOUR_PRIVATE_KEY_HERE` (unique Ethereum key per node)
  - `RPC_URL=https://ethereum-sepolia-rpc.publicnode.com` (or your own Sepolia RPC)
  - Ensure production flags (already the defaults in `.env.example`):
    - `TEST_MODE=0`
    - `DRY_RUN=0`
  - P2P bootstrap (same on all nodes, update IP/peer ID if needed):
    - `P2P_BOOTSTRAP_PEERS=/ip4/<BOOTSTRAP_IP>/tcp/26005/p2p/<BOOTSTRAP_PEER_ID>`
  - Monero wallet RPC auth (must match what `start-monero-rpc.sh` uses):
    - `MONERO_WALLET_RPC_USER=...`
    - `MONERO_WALLET_RPC_PASSWORD=...`

## 4. Start Monero wallet RPC

From the repo root:

- `./start-monero-rpc.sh`

The script will automatically read `.env` and start `monero-wallet-rpc` on `http://127.0.0.1:18083` with the credentials from `.env`.

## 5. Start the znode (production)

From the repo root:

- `./start`

The node runs in the background and logs to `znode.log`.

To stop it cleanly:

- `./stop`

To watch logs:

- `tail -f znode.log`

---

## Security and Threat Model

### Production Security Requirements

**CRITICAL: The following settings are REQUIRED for production deployments:**

1. **TEST_MODE=0**: Production mode enforces security best practices
   - Disables insecure defaults and test shortcuts
   - Enforces exact ERC-20 approval amounts (no over-approval)
   - Requires explicit configuration of all security-sensitive settings

2. **P2P_REQUIRE_E2E=1**: End-to-end encryption for P2P messages
   - All round payloads are encrypted using ECDH with peer public keys
   - Prevents plaintext exposure of multisig coordination data
   - Identity messages bind ECDH keys to libp2p PeerIds for MITM protection

3. **Monero RPC Authentication**: Always required
   - Set MONERO_WALLET_RPC_USER and MONERO_WALLET_RPC_PASSWORD
   - RPC must bind to 127.0.0.1 (localhost only) in production
   - Never expose wallet RPC to network without TLS/mTLS

4. **Wallet Backup Encryption**: Requires strong passphrase
   - Set WALLET_BACKUP_PASSPHRASE to a strong, unique passphrase
   - Backups use AES-256-CBC with PBKDF2 (100,000 iterations)
   - Never use default or weak passphrases

### Operational Assumptions

**Network Security:**
- Nodes should run behind firewalls with only P2P port (26005) exposed
- Ethereum RPC endpoint should use HTTPS
- Monero wallet RPC should only bind to 127.0.0.1

**Host Security:**
- Single-tenant hosts recommended (one node per VPS)
- File permissions: .env (600), backup files (600), directories (700)
- Regular security updates for OS and dependencies

**Key Management:**
- Ethereum private keys stored in .env (mode 600)
- Monero wallet passwords stored in .env only (not persisted separately)
- Backup passphrases should be stored in secure password manager

### Disabled Features

**SST (Shamir's Secret Sharing) - DISABLED BY DEFAULT:**
- ENABLE_SST=0 in production (default)
- SST fundamentally changes custody model from threshold multisig to threshold key reconstruction
- If enabled, allows colluding subset to reconstruct Monero spend key
- Only enable for testing/demos with explicit understanding of custody implications

### Threat Model

**What ZNode Protects Against:**
- Single node compromise (7-of-11 threshold)
- Up to 3 Byzantine node failures
- Network eavesdropping (E2E encryption)
- Unauthorized wallet access (RPC auth)

**What ZNode Does NOT Protect Against:**
- Threshold collusion (8+ nodes colluding)
- Smart contract vulnerabilities
- Ethereum/Monero protocol vulnerabilities
- Host compromise with keylogger/memory dump
- Social engineering of operators

### Configuration Validation

The config validator checks for common misconfigurations:
- Warns if TEST_MODE=1 in production
- Errors if P2P_REQUIRE_E2E=0 in production
- Errors if Monero RPC binds to non-localhost without TEST_MODE
- Validates all required environment variables

### Monitoring and Incident Response

**Health Monitoring:**
- Heartbeat transactions every 15 minutes (HEARTBEAT_INTERVAL)
- Health snapshots logged every 5 minutes
- Cluster blacklist tracks repeatedly failing clusters

**Incident Response:**
- Review logs for authentication failures
- Check cluster blacklist for coordination issues
- Verify P2P connectivity and peer counts
- Monitor Ethereum gas usage and ZFI balance

### Upgrade and Maintenance

**Before Upgrading:**
- Review changelog for breaking changes
- Test on testnet first
- Backup wallet files and .env configuration

**During Maintenance:**
- Use `./stop` for graceful shutdown (15s timeout)
- Wallet files automatically backed up after multisig operations
- Restore from backups using WALLET_BACKUP_PASSPHRASE

### Support and Documentation

For questions or issues:
- Review logs: `tail -f znode.log`
- Check configuration: node config-validator.js
- Test connectivity: node test-connection.js
- Test P2P: node test-libp2p.js
