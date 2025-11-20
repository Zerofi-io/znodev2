/**
 * Configuration Validator
 * Validates environment configuration on startup
 */

import { execSync } from 'child_process';
import path from 'path';

class ConfigValidator {
  constructor() {
    this.errors = [];
    this.warnings = [];
  }

  validate() {
    this.validateRequiredConfig();
    this.validateSecurityConfig();
    this.validateP2PConfig();
    this.validateMoneroConfig();
    this.validateMoneroRPCBinary();
    this.validateClusterConfig();
    this.validateContractAddresses();
    this.validateSSTConfig();
    this.validateBackupConfig();
    
    return {
      valid: this.errors.length === 0,
      errors: this.errors,
      warnings: this.warnings
    };
  }

  validateRequiredConfig() {
    const TEST_MODE = process.env.TEST_MODE === '1';
    
    if (!process.env.PRIVATE_KEY) {
      this.errors.push('PRIVATE_KEY is required');
    } else if (!process.env.PRIVATE_KEY.startsWith('0x')) {
      this.warnings.push('PRIVATE_KEY should start with 0x');
    } else if (process.env.PRIVATE_KEY.length !== 66) {
      this.warnings.push('PRIVATE_KEY should be 66 characters (0x + 64 hex chars)');
    }

    if (!TEST_MODE && !process.env.RPC_URL && !process.env.ETH_RPC_URL) {
      this.errors.push('RPC_URL or ETH_RPC_URL is required in production mode');
    }

    if (!TEST_MODE && !process.env.MONERO_WALLET_PASSWORD) {
      this.errors.push('MONERO_WALLET_PASSWORD is required in production mode');
    }
  }

  validateSecurityConfig() {
    const TEST_MODE = process.env.TEST_MODE === '1';
    const DRY_RUN = process.env.DRY_RUN !== '0';

    if (TEST_MODE) {
      this.warnings.push('TEST_MODE is enabled - this should NEVER be used in production!');
    }

    if (!DRY_RUN && TEST_MODE) {
      this.errors.push('Invalid configuration: DRY_RUN=0 with TEST_MODE=1 is inconsistent. Set TEST_MODE=0 for production or DRY_RUN=1 for testing.');
    }

    if (process.env.PRIVATE_KEY === '0x0000000000000000000000000000000000000000000000000000000000000000') {
      this.errors.push('PRIVATE_KEY appears to be a placeholder - use a real private key');
    }

    if (process.env.MONERO_WALLET_PASSWORD === 'your_secure_password_here') {
      this.errors.push('MONERO_WALLET_PASSWORD appears to be a placeholder - use a real password');
    }
    
    if (process.env.CHAIN_ID) {
      const chainId = Number(process.env.CHAIN_ID);
      if (isNaN(chainId) || chainId < 1) {
        this.errors.push(`Invalid CHAIN_ID: ${process.env.CHAIN_ID} (must be a positive integer)`);
      }
    }
  }

  validateP2PConfig() {
    const P2P_IMPL = process.env.P2P_IMPL || 'libp2p';
    const TEST_MODE = process.env.TEST_MODE === '1';
    
    if (P2P_IMPL !== 'libp2p') {
      this.errors.push(`P2P_IMPL must be set to "libp2p" - other implementations are not supported (got: ${P2P_IMPL})`);
    }

    if (P2P_IMPL === 'libp2p' && !process.env.P2P_BOOTSTRAP_PEERS && !TEST_MODE) {
      this.warnings.push('P2P_BOOTSTRAP_PEERS not configured - will only discover peers via mDNS (local network)');
    }

    if (process.env.P2P_BOOTSTRAP_PEERS) {
      const peers = process.env.P2P_BOOTSTRAP_PEERS.split(',').filter(Boolean);
      for (const peer of peers) {
        if (!peer.trim().startsWith('/ip4/') && !peer.trim().startsWith('/ip6/') && !peer.trim().startsWith('/dns')) {
          this.warnings.push(`Bootstrap peer may be invalid multiaddr: ${peer.trim()}`);
        }
      }
    }

    if (process.env.P2P_PORT) {
      const port = Number(process.env.P2P_PORT);
      if (isNaN(port) || port < 0 || port > 65535) {
        this.errors.push(`Invalid P2P_PORT: ${process.env.P2P_PORT} (must be 0-65535)`);
      }
    }
    
    if (!TEST_MODE && process.env.P2P_REQUIRE_E2E !== '1') {
      this.errors.push('P2P_REQUIRE_E2E=1 is required in production mode for end-to-end encryption');
    }
  }

  validateMoneroConfig() {
    if (process.env.MONERO_RPC_URL) {
      try {
        new URL(process.env.MONERO_RPC_URL);
      } catch {
        this.errors.push(`Invalid MONERO_RPC_URL: ${process.env.MONERO_RPC_URL}`);
      }
    }

    const hasUser = !!process.env.MONERO_WALLET_RPC_USER;
    const hasPass = !!process.env.MONERO_WALLET_RPC_PASSWORD;
    
    if (hasUser && !hasPass) {
      this.errors.push('MONERO_WALLET_RPC_USER is set but MONERO_WALLET_RPC_PASSWORD is not');
    }
    
    if (!hasUser && hasPass) {
      this.errors.push('MONERO_WALLET_RPC_PASSWORD is set but MONERO_WALLET_RPC_USER is not');
    }

    if (process.env.MONERO_RPC_BIND_IP && process.env.MONERO_RPC_BIND_IP !== '127.0.0.1') {
      if (!hasUser || !hasPass) {
        this.errors.push('MONERO_WALLET_RPC_USER and MONERO_WALLET_RPC_PASSWORD are required when MONERO_RPC_BIND_IP is not 127.0.0.1');
      }
      const TEST_MODE = process.env.TEST_MODE === '1';
      if (!TEST_MODE) {
        this.errors.push('MONERO_RPC_BIND_IP is not 127.0.0.1 in production mode - this exposes RPC to network without HTTPS/mTLS. Set TEST_MODE=1 to acknowledge risk or use 127.0.0.1.');
      } else {
        this.warnings.push('MONERO_RPC_BIND_IP is not 127.0.0.1 - ensure firewall is configured correctly');
      }
    }

    if (process.env.TEST_MODE !== '1' && (!hasUser || !hasPass)) {
      this.errors.push('MONERO_WALLET_RPC_USER and MONERO_WALLET_RPC_PASSWORD are required when TEST_MODE=0');
    }

    if (process.env.MONERO_TRUST_DAEMON === '1') {
      this.warnings.push('MONERO_TRUST_DAEMON is enabled - only use this if you control the daemon');
    }

    if (process.env.AUTO_STAKE === '1' && !process.env.MONERO_FEE_ADDRESS) {
      this.errors.push('AUTO_STAKE is enabled but MONERO_FEE_ADDRESS is not set - this is required for staking');
    }

    if (process.env.MONERO_FEE_ADDRESS) {
      const addr = process.env.MONERO_FEE_ADDRESS;
      const isValidLength = addr.length === 95;
      const isValidPrefix = addr[0] === '4' || addr[0] === '8';
      const isValidBase58 = /^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(addr);
      
      if (!isValidLength || !isValidPrefix || !isValidBase58) {
        this.errors.push(`Invalid MONERO_FEE_ADDRESS: ${addr} (must be a 95-character Monero address starting with 4 or 8, using base58 encoding)`);
      }
    }
  }

  validateMoneroRPCBinary() {
    try {
      execSync('which monero-wallet-rpc', { stdio: 'ignore' });
    } catch {
      this.warnings.push('monero-wallet-rpc binary not found in PATH - ensure Monero wallet RPC is installed');
    }
  }

  validateClusterConfig() {
    const clusterSize = Number(process.env.CLUSTER_SIZE || 11);
    const clusterThreshold = Number(process.env.CLUSTER_THRESHOLD || 7);
    const livenessQuorum = Number(process.env.LIVENESS_QUORUM || clusterSize);

    if (isNaN(clusterSize) || clusterSize < 1) {
      this.errors.push(`Invalid CLUSTER_SIZE: ${process.env.CLUSTER_SIZE} (must be >= 1)`);
    }

    if (isNaN(clusterThreshold) || clusterThreshold < 1) {
      this.errors.push(`Invalid CLUSTER_THRESHOLD: ${process.env.CLUSTER_THRESHOLD} (must be >= 1)`);
    }

    if (clusterThreshold > clusterSize) {
      this.errors.push(`CLUSTER_THRESHOLD (${clusterThreshold}) cannot be greater than CLUSTER_SIZE (${clusterSize})`);
    }

    if (isNaN(livenessQuorum) || livenessQuorum < 1) {
      this.errors.push(`Invalid LIVENESS_QUORUM: ${process.env.LIVENESS_QUORUM} (must be >= 1)`);
    }

    if (livenessQuorum > clusterSize) {
      this.errors.push(`LIVENESS_QUORUM (${livenessQuorum}) cannot be greater than CLUSTER_SIZE (${clusterSize})`);
    }

    const timeouts = [
      { name: 'LIVENESS_TIMEOUT_MS', value: process.env.LIVENESS_TIMEOUT_MS },
      { name: 'ROUND_TIMEOUT_MS', value: process.env.ROUND_TIMEOUT_MS },
      { name: 'HEALTH_LOG_INTERVAL_MS', value: process.env.HEALTH_LOG_INTERVAL_MS },
      { name: 'FINALIZE_FAILOVER_MS', value: process.env.FINALIZE_FAILOVER_MS },
      { name: 'STALE_ROUND_MIN_AGE_MS', value: process.env.STALE_ROUND_MIN_AGE_MS },
      { name: 'P2P_MESSAGE_MAX_AGE_MS', value: process.env.P2P_MESSAGE_MAX_AGE_MS }
    ];

    for (const { name, value } of timeouts) {
      if (value !== undefined) {
        const num = Number(value);
        if (isNaN(num) || num < 0) {
          this.errors.push(`Invalid ${name}: ${value} (must be >= 0)`);
        }
      }
    }

    const intervals = [
      { name: 'HEARTBEAT_INTERVAL', value: process.env.HEARTBEAT_INTERVAL },
      { name: 'MAX_KEY_EXCHANGE_ROUNDS', value: process.env.MAX_KEY_EXCHANGE_ROUNDS },
      { name: 'MAX_REGISTERED_SCAN', value: process.env.MAX_REGISTERED_SCAN },
      { name: 'SELECTION_EPOCH_BLOCKS', value: process.env.SELECTION_EPOCH_BLOCKS },
      { name: 'FAILOVER_COORDINATOR_INDEX', value: process.env.FAILOVER_COORDINATOR_INDEX }
    ];

    for (const { name, value } of intervals) {
      if (value !== undefined) {
        const num = Number(value);
        if (isNaN(num) || num < 0) {
          this.errors.push(`Invalid ${name}: ${value} (must be >= 0)`);
        }
      }
    }
  }

  validateContractAddresses() {
    const addresses = [
      { name: 'REGISTRY_ADDR', value: process.env.REGISTRY_ADDR },
      { name: 'STAKING_ADDR', value: process.env.STAKING_ADDR },
      { name: 'ZFI_ADDR', value: process.env.ZFI_ADDR },
      { name: 'COORDINATOR_ADDR', value: process.env.COORDINATOR_ADDR }
    ];

    for (const { name, value } of addresses) {
      if (value && !value.match(/^0x[a-fA-F0-9]{40}$/)) {
        this.errors.push(`Invalid ${name}: ${value} (must be a valid Ethereum address)`);
      }
    }
  }

  validateSSTConfig() {
    const ENABLE_SST = process.env.ENABLE_SST === '1';
    
    if (!ENABLE_SST) {
      return; // SST disabled, skip validation
    }

    const threshold = Number(process.env.SST_THRESHOLD || 7);
    const totalShares = Number(process.env.SST_TOTAL_SHARES || 11);
    const clusterSize = Number(process.env.CLUSTER_SIZE || 11);

    if (isNaN(threshold) || threshold < 1) {
      this.errors.push(`Invalid SST_THRESHOLD: ${process.env.SST_THRESHOLD} (must be >= 1)`);
    }

    if (isNaN(totalShares) || totalShares < 1) {
      this.errors.push(`Invalid SST_TOTAL_SHARES: ${process.env.SST_TOTAL_SHARES} (must be >= 1)`);
    }

    if (threshold > totalShares) {
      this.errors.push(`SST_THRESHOLD (${threshold}) cannot be greater than SST_TOTAL_SHARES (${totalShares})`);
    }

    if (totalShares !== clusterSize) {
      this.warnings.push(`SST_TOTAL_SHARES (${totalShares}) does not match CLUSTER_SIZE (${clusterSize}) - this may cause issues`);
    }

    const clusterThreshold = Number(process.env.CLUSTER_THRESHOLD || 7);
    if (threshold !== clusterThreshold) {
      this.warnings.push(`SST_THRESHOLD (${threshold}) does not match CLUSTER_THRESHOLD (${clusterThreshold}) - key recovery may fail`);
    }

    const TEST_MODE = process.env.TEST_MODE === '1';
    
    if (!process.env.SST_STORAGE_PASSPHRASE && !process.env.MONERO_WALLET_PASSWORD) {
      this.errors.push('SST enabled but no storage passphrase configured (SST_STORAGE_PASSPHRASE or MONERO_WALLET_PASSWORD required)');
    }
    
    if (!TEST_MODE && !process.env.SST_STORAGE_PASSPHRASE) {
      this.errors.push('SST_STORAGE_PASSPHRASE is required in production mode (do not reuse MONERO_WALLET_PASSWORD)');
    }
    
    if (process.env.SST_STORAGE_PASSPHRASE && process.env.MONERO_WALLET_PASSWORD && 
        process.env.SST_STORAGE_PASSPHRASE === process.env.MONERO_WALLET_PASSWORD) {
      this.warnings.push('SST_STORAGE_PASSPHRASE should be different from MONERO_WALLET_PASSWORD for better security isolation');
    }

    const encScheme = process.env.SST_ENC_SCHEME || 'eth-ecdh-v1';
    if (encScheme !== 'eth-ecdh-v1') {
      this.errors.push(`Invalid SST_ENC_SCHEME: ${encScheme} (only 'eth-ecdh-v1' is supported)`);
    }

    if (process.env.SST_STORAGE_DIR) {
      const dir = process.env.SST_STORAGE_DIR;
      const resolved = path.resolve(dir);
      if (dir.includes('..')) {
        this.errors.push(`SST_STORAGE_DIR contains path traversal: ${dir}`);
      } else if (!dir.startsWith('.') && !dir.startsWith('/')) {
        this.warnings.push(`SST_STORAGE_DIR may be unsafe (relative path): ${dir}`);
      }
    }

    this.warnings.push('SST enabled: Node replacement uses custody transfer (leaving node retains signing capability)');
  }

  validateBackupConfig() {
    const TEST_MODE = process.env.TEST_MODE === '1';
    
    // WALLET_BACKUP_PASSPHRASE is now optional: if unset, the node will
    // generate a strong random passphrase on first startup and store it
    // on disk for use by the auto-backup/auto-restore scripts.
    if (!TEST_MODE && !process.env.WALLET_BACKUP_PASSPHRASE) {
      this.warnings.push('WALLET_BACKUP_PASSPHRASE is not set; a random passphrase will be generated on first run and stored on disk. Back up this file if you rely on automatic wallet backups.');
    }
    
    if (process.env.WALLET_BACKUP_PASSPHRASE) {
      const passphrase = process.env.WALLET_BACKUP_PASSPHRASE;
      if (passphrase.length < 12) {
        this.warnings.push('WALLET_BACKUP_PASSPHRASE is too short (recommended: 20+ characters)');
      }
      if (passphrase === 'your-strong-passphrase-here' || passphrase === 'changeme') {
        if (TEST_MODE) {
          this.warnings.push('WALLET_BACKUP_PASSPHRASE appears to be a placeholder - use a real passphrase for production');
        } else {
          this.errors.push('WALLET_BACKUP_PASSPHRASE appears to be a placeholder - use a real passphrase');
        }
      }
    }
    
    if (process.env.APPROVAL_MULTIPLIER && process.env.APPROVAL_MULTIPLIER !== '1' && !TEST_MODE) {
      this.warnings.push('APPROVAL_MULTIPLIER is ignored in production mode (always uses 1x)');
    }
    
    if (process.env.LIVENESS_QUORUM) {
      const clusterSize = Number(process.env.CLUSTER_SIZE || 11);
      const livenessQuorum = Number(process.env.LIVENESS_QUORUM);
      if (livenessQuorum === clusterSize) {
        this.warnings.push(`LIVENESS_QUORUM equals CLUSTER_SIZE (${clusterSize}) - consider setting to ${clusterSize - 1} to allow 1 transient failure`);
      }
    }
  }

  printResults() {
    if (this.errors.length > 0) {
      console.error('\n❌ Configuration Errors:');
      for (const error of this.errors) {
        console.error(`  - ${error}`);
      }
    }

    if (this.warnings.length > 0) {
      console.warn('\n⚠️  Configuration Warnings:');
      for (const warning of this.warnings) {
        console.warn(`  - ${warning}`);
      }
    }

    if (this.errors.length === 0 && this.warnings.length === 0) {
      console.log('\n✓ Configuration validation passed');
    }
  }
}

export default ConfigValidator;
