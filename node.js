import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import fs from 'fs';
import { execFile } from 'child_process';
import { promisify } from 'util';

const execFileAsync = promisify(execFile);

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const dotenvResult = dotenv.config({ path: __dirname + '/.env' });
if (dotenvResult.error) {
  console.error('❌ Failed to load .env file:', dotenvResult.error.message);
  console.error('Please ensure .env file exists. Run ./setup.sh to create it.\n');
  process.exit(1);
}

// --- Configuration validation ---
import ConfigValidator from './config-validator.js';
const validator = new ConfigValidator();
const validationResult = validator.validate();

if (!validationResult.valid) {
  validator.printResults();
  console.error('\n❌ Configuration validation failed. Please fix the errors above and try again.');
  console.error('See .env.example for configuration documentation.\n');
  process.exit(1);
}

if (validationResult.warnings.length > 0) {
  validator.printResults();
}

const TEST_MODE = process.env.TEST_MODE === '1';
const DRY_RUN = TEST_MODE ? (process.env.DRY_RUN !== '0') : (process.env.DRY_RUN === '1');

if (TEST_MODE) {
  console.warn('⚠️  ═══════════════════════════════════════════════════════════════');
  console.warn('⚠️  WARNING: TEST_MODE is ENABLED');
  console.warn('⚠️  This mode uses insecure defaults and should NEVER be used in production!');
  console.warn('⚠️  Set TEST_MODE=0 for production use.');
  console.warn('⚠️  ═══════════════════════════════════════════════════════════════');
}

if (DRY_RUN) {
  console.log('ℹ️  DRY_RUN mode enabled: on-chain transactions will be simulated but not sent.');
  console.log('ℹ️  Set DRY_RUN=0 to send real transactions.');
  if (!process.env.DRY_RUN) {
    console.warn('⚠️  DRY_RUN defaulted to enabled (not explicitly set). Set DRY_RUN=0 for production.');
  }
}

let EFFECTIVE_RPC_URL;
if (process.env.RPC_URL || process.env.ETH_RPC_URL) {
  EFFECTIVE_RPC_URL = process.env.RPC_URL || process.env.ETH_RPC_URL;
} else if (TEST_MODE) {
  EFFECTIVE_RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/demo';
  console.warn('⚠️  TEST_MODE: Using demo RPC URL (rate-limited, for testing only)');
} else {
  console.error('ERROR: RPC_URL or ETH_RPC_URL is required.');
  console.error('Set RPC_URL=<your-rpc-url> or enable TEST_MODE=1 for testing.');
  process.exit(1);
}

if (!process.env.PRIVATE_KEY) {
  console.error('Environment variable PRIVATE_KEY is required to run znode.');
  process.exit(1);
}

if (!process.env.MONERO_WALLET_PASSWORD) {
  console.error('ERROR: MONERO_WALLET_PASSWORD is required.');
  console.error('Set MONERO_WALLET_PASSWORD=<password> in your .env file.');
  console.error('SECURITY: Never derive passwords from private keys. Use unique, random passwords.');
  process.exit(1);
}
console.log('Using MONERO_WALLET_PASSWORD from environment for Monero wallet.');

import { ethers } from 'ethers';
import MoneroRPC from './monero-rpc.js';
import RPCManager from './rpc-manager.js';
import SSTManager from './sst.js';
import crypto from 'crypto';
import P2PLibp2p from './p2p-libp2p.js';

const P2P_IMPL = process.env.P2P_IMPL || 'libp2p';
let P2PExchange;

if (P2P_IMPL !== 'libp2p') {
  console.error('❌ ERROR: P2P_IMPL must be set to "libp2p"');
  console.error('❌ The legacy TLS P2P implementation has been disabled due to critical security issues:');
  console.error('❌  - Broadcast encryption is non-functional');
  console.error('❌  - MITM vulnerabilities with deterministic TLS certs');
  console.error('❌  - Certificate validation disabled by default');
  console.error('❌ Set P2P_IMPL=libp2p in your .env file');
  process.exit(1);
}

P2PExchange = P2PLibp2p;
console.log('Using LibP2P implementation for P2P networking');

class ZNode {
  constructor() {
    this.provider = new ethers.JsonRpcProvider(EFFECTIVE_RPC_URL);
    this.wallet = new ethers.Wallet(process.env.PRIVATE_KEY, this.provider);
    
    this._clusterOrchestrationLock = false;
    this._clusterBlacklistPath = __dirname + '/.cluster-blacklist.json';
    this._clusterFailures = new Map();
    this._clusterFailMeta = {};
    this._clusterBlacklist = {};
    this._blacklistSavePending = false;
    this._blacklistSaveQueued = false;
    
    this.moneroPassword = process.env.MONERO_WALLET_PASSWORD;

    const registryABI = [
      'function registerNode(bytes32 codeHash) external',
      'function unregisterNode() external',
      'function finalizeCluster(address[] members, string moneroAddress) external returns (bytes32 clusterId)',
      'function clusters(bytes32) external view returns (address[] members, string moneroAddress, uint256 createdAt, bool finalized)',
      'function getRegisteredNodes(uint256 offset, uint256 limit) external view returns (address[] memory)',
      'function canParticipate(address node) external view returns (bool)',
      'function nodes(address) external view returns (bytes32 codeHash, bool registered, bool inCluster)'
    ];

    const stakingABI = [
      'function getNodeInfo(address node) external view returns (uint256,uint256,uint256,bool,uint256,uint256,uint256)',
      'function stake(bytes32 _codeHash, string _moneroFeeAddress) external',
      'function topUpStake() external',
      'function heartbeat() external',
      'function recordP2PHeartbeat(address _node) external',
      'function getActiveNodes() external view returns (address[] memory)',
      'function slashForDowntimeProgressive(address _node) external',
      'function slashForDowntimeWithProof(address _node, uint256 lastHeartbeatTs, bytes calldata sig) external',
      'function checkSlashingStatus(address _node) external view returns (bool needsSlash, uint256 stage, uint256 hoursOffline)',
      'function isBlacklisted(address _node) external view returns (bool)',
      'function heartbeatOracle() external view returns (address)',
      'function owner() external view returns (address)'
    ];

    const zfiABI = [
      'function balanceOf(address) view returns (uint256)',
      'function allowance(address owner, address spender) view returns (uint256)',
      'function approve(address spender, uint256 amount) returns (bool)',
      'function decimals() view returns (uint8)'
    ];

    const exchangeCoordinatorABI = [
      'function submitExchangeInfo(bytes32 clusterId, uint8 round, string exchangeInfo, address[] clusterNodes) external',
      'function getExchangeRoundInfo(bytes32 clusterId, uint8 round, address[] clusterNodes) external view returns (address[] addresses, string[] exchangeInfos)',
      'function getExchangeRoundStatus(bytes32 clusterId, uint8 round) external view returns (bool complete, uint8 submitted)'
    ];

    const KNOWN_DEFAULTS = {
      11155111: {
        REGISTRY_ADDR: '0x82a9E750417EfdC22ff32d7cfF25C283d6C0cd87',
        STAKING_ADDR: '0x1D21b7d6871104b77bca3F50032c3aa75C838a3E',
        ZFI_ADDR: '0x7bdFAE73c17aFAaA2DCCbD115F4CD920e40ad071',
        COORDINATOR_ADDR: '0x6119195691d1C3D5C4D4C91f61015080F879a84c'
      }
    };

    this._knownDefaults = KNOWN_DEFAULTS;
    this._chainIdVerified = false;
    this._registryABI = registryABI;
    this._stakingABI = stakingABI;
    this._zfiABI = zfiABI;
    this._exchangeCoordinatorABI = exchangeCoordinatorABI;

    this.registry = null;
    this.staking = null;
    this.zfi = null;
    this.exchangeCoordinator = null;

    this.monero = new MoneroRPC({
      url: process.env.MONERO_RPC_URL || process.env.MONERO_WALLET_RPC_URL || 'http://127.0.0.1:18083'
    });
    // Initialize RPC manager with the same URL that MoneroRPC resolved
    this.rpcManager = new RPCManager({ url: this.monero.url });
    this._rpcRestartPromise = null;
    this._rpcRestartAttempts = 0;
    this._rpcLastRestartTime = 0;
    this._rpcRestartWindow = [];
    this._rpcCircuitOpen = false;
    this._rpcCircuitOpenUntil = 0;
    this._rpcCircuitHalfOpen = false;
    const _rawCall = this.monero.call.bind(this.monero);
    this.monero.call = async (method, params = {}, timeout) => {
      const waitOnCall = process.env.RPC_CIRCUIT_BREAKER_WAIT_ON_CALL === '1';
      const now = Date.now();
      
      if (this._rpcCircuitOpen && now < this._rpcCircuitOpenUntil) {
        if (waitOnCall) {
          const remaining = Math.ceil((this._rpcCircuitOpenUntil - now) / 1000);
          console.log(`[RPC] Circuit breaker open, wait-through mode: waiting ${remaining}s before retry...`);
          await new Promise(resolve => setTimeout(resolve, this._rpcCircuitOpenUntil - now));
          this._rpcCircuitOpen = false;
          this._rpcCircuitHalfOpen = true;
          console.log('[RPC] Circuit breaker entering half-open state after wait-through...');
        } else {
          const remaining = Math.ceil((this._rpcCircuitOpenUntil - now) / 1000);
          throw new Error(`RPC circuit breaker open: cooldown active for ${remaining}s. Manual intervention may be required.`);
        }
      }
      
      if (this._rpcCircuitOpen && now >= this._rpcCircuitOpenUntil) {
        console.log('[RPC] Circuit breaker entering half-open state, testing recovery...');
        this._rpcCircuitHalfOpen = true;
        this._rpcCircuitOpen = false;
      }
      
      try {
        const result = await _rawCall(method, params, timeout);
        if (this._rpcCircuitHalfOpen) {
          console.log('[RPC] Circuit breaker closed: recovery successful');
          this._rpcCircuitHalfOpen = false;
          this._rpcRestartWindow = [];
          this._rpcRestartAttempts = 0;
        }
        return result;
      } catch (e) {
        const msg = ((e && e.code) || (e && e.message) || '').toString();
        if (/ECONNREFUSED|ETIMEDOUT|ECONNRESET|EHOSTUNREACH|ENETUNREACH|timeout/i.test(msg)) {
          if (this._rpcCircuitHalfOpen) {
            console.error('[RPC] Circuit breaker re-opening: recovery failed');
            this._rpcCircuitOpen = true;
            this._rpcCircuitHalfOpen = false;
            const cooldownMs = Number(process.env.RPC_CIRCUIT_BREAKER_COOLDOWN_MS || 60000);
            this._rpcCircuitOpenUntil = Date.now() + cooldownMs;
            throw new Error(`RPC recovery failed in half-open state. Circuit breaker re-opened for ${cooldownMs/1000}s.`);
          }
          
          if (this._rpcRestartPromise) {
            console.log('[RPC] Restart already in progress, waiting...');
            await this._rpcRestartPromise;
          } else {
            const now = Date.now();
            const windowMs = Number(process.env.RPC_CIRCUIT_BREAKER_WINDOW_MS || 300000);
            const maxFailures = Number(process.env.RPC_CIRCUIT_BREAKER_MAX_FAILURES || 10);
            const cooldownMs = Number(process.env.RPC_CIRCUIT_BREAKER_COOLDOWN_MS || 60000);
            
            this._rpcRestartWindow = this._rpcRestartWindow.filter(t => t > now - windowMs);
            
            if (this._rpcRestartWindow.length >= maxFailures) {
              this._rpcCircuitOpen = true;
              this._rpcCircuitOpenUntil = now + cooldownMs;
              console.error(`[RPC] Circuit breaker OPEN: ${maxFailures} failures in ${windowMs/1000}s. Cooldown for ${cooldownMs/1000}s. Will test recovery after cooldown.`);
              throw new Error(`RPC restart limit exceeded: ${maxFailures} failures in ${windowMs/1000}s. Circuit breaker open for ${cooldownMs/1000}s.`);
            }
            
            this._rpcRestartWindow.push(now);
            const backoffMs = Math.min(1000 * Math.pow(2, this._rpcRestartAttempts), 30000);
            const elapsed = now - this._rpcLastRestartTime;
            if (elapsed < backoffMs) {
              const remaining = backoffMs - elapsed;
              console.log(`[RPC] Backoff active: waiting ${remaining}ms before retry`);
              await new Promise(resolve => setTimeout(resolve, remaining));
            }
            
            this._rpcRestartPromise = this.rpcManager.restart(this.monero, this.monero._lastWallet)
              .then(() => {
                this._rpcRestartAttempts = 0;
                this._rpcLastRestartTime = Date.now();
                console.log(`[RPC] Restart successful (${this._rpcRestartWindow.length} failures in window)`);
              })
              .catch((err) => {
                this._rpcRestartAttempts++;
                this._rpcLastRestartTime = Date.now();
                console.error(`[RPC] Restart failed: ${err.message || err}`);
                throw new Error(`RPC restart failed: ${err.message || err}`);
              })
              .finally(() => { this._rpcRestartPromise = null; });
            await this._rpcRestartPromise;
          }
          return await _rawCall(method, params, timeout);
        }
        throw e;
      }
    };

    this.baseWalletName = `znode_${this.wallet.address.slice(2, 10)}`;
    this.clusterWalletName = null; // Set when joining a cluster
    this.multisigInfo = null;
    this.clusterId = null;
    this._multisigExperimentalEnabled = false;
    
    // P2P Exchange for decentralized coordination
    this.p2p = new P2PExchange(this.wallet.address, this.wallet.privateKey, process.env.PUBLIC_IP);
    
    const ENABLE_SST = process.env.ENABLE_SST === '1';
    this.sst = ENABLE_SST ? new SSTManager({
      enabled: true,
      threshold: Number(process.env.SST_THRESHOLD) || 8,
      totalShares: Number(process.env.SST_TOTAL_SHARES) || 11,
      storageDir: process.env.SST_STORAGE_DIR || './sst-data',
      encScheme: process.env.SST_ENC_SCHEME || 'eth-ecdh-v1',
      storagePassphrase: process.env.SST_STORAGE_PASSPHRASE || this.moneroPassword
    }) : null;
    
    if (ENABLE_SST) {
      console.log('✓ SST (Shamir\'s Secret Sharing) enabled for node replacement');
    }
    
    // Helper to handle different coordinator ABIs
    this.getRoundStatus = async (clusterId, round) => {
      try {
        return await this.exchangeCoordinator.getExchangeRoundStatus(clusterId, round);
      } catch (e) {
        try {
          return await this.exchangeCoordinator.getExchangeRoundStatus(round);
        } catch {
          throw e;
        }
      }
    };
  }

  _loadClusterBlacklist() {
    try {
      if (fs.existsSync(this._clusterBlacklistPath)) {
        const data = fs.readFileSync(this._clusterBlacklistPath, 'utf8');
        const parsed = JSON.parse(data);
        this._clusterFailures = new Map(Object.entries(parsed.failures || {}));
        this._clusterFailMeta = parsed.meta || {};
        this._clusterBlacklist = parsed.blacklist || {};
        
        const now = Date.now();
        const prunedBlacklist = {};
        let activeBlacklists = 0;
        for (const [clusterId, expiryTime] of Object.entries(this._clusterBlacklist)) {
          if (expiryTime > now) {
            prunedBlacklist[clusterId] = expiryTime;
            activeBlacklists++;
          }
        }
        this._clusterBlacklist = prunedBlacklist;
        
        console.log(`[Blacklist] Loaded ${this._clusterFailures.size} cluster failure records from disk`);
        if (activeBlacklists > 0) {
          console.log(`[Blacklist] ${activeBlacklists} active blacklisted clusters`);
        }
      }
    } catch (e) {
      console.warn(`[Blacklist] Failed to load from disk: ${e.message}`);
    }
  }

  _saveClusterBlacklist() {
    if (this._blacklistSavePending) {
      this._blacklistSaveQueued = true;
      return;
    }

    this._blacklistSavePending = true;
    this._blacklistSaveQueued = false;

    setImmediate(() => {
      try {
        const now = Date.now();
        const prunedBlacklist = {};
        for (const [clusterId, expiryTime] of Object.entries(this._clusterBlacklist || {})) {
          if (expiryTime > now) {
            prunedBlacklist[clusterId] = expiryTime;
          }
        }
        
        const MAX_FAILURE_RECORDS = 1000;
        const failureEntries = Array.from(this._clusterFailures.entries());
        if (failureEntries.length > MAX_FAILURE_RECORDS) {
          this._clusterFailures = new Map(failureEntries.slice(-MAX_FAILURE_RECORDS));
        }
        
        const data = {
          failures: Object.fromEntries(this._clusterFailures),
          meta: this._clusterFailMeta,
          blacklist: prunedBlacklist,
          updated: new Date().toISOString()
        };
        
        const tmpPath = this._clusterBlacklistPath + '.tmp';
        fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { mode: 0o600 });
        fs.renameSync(tmpPath, this._clusterBlacklistPath);
      } catch (e) {
        console.warn(`[Blacklist] Failed to save to disk: ${e.message}`);
      } finally {
        this._blacklistSavePending = false;
        if (this._blacklistSaveQueued) {
          this._saveClusterBlacklist();
        }
      }
    });
  }

  async start() {
    console.log('\n═══════════════════════════════════════════════');
    console.log('   ZNode - Monero Multisig (WORKING!)');
    console.log('═══════════════════════════════════════════════\n');
    console.log(`Address: ${this.wallet.address}`);
    
    this._loadClusterBlacklist();
    
    const network = await this.provider.getNetwork();
    const chainIdBigInt = network.chainId;
    
    if (chainIdBigInt > Number.MAX_SAFE_INTEGER) {
      throw new Error(`Chain ID ${chainIdBigInt} exceeds Number.MAX_SAFE_INTEGER. This chain is not supported.`);
    }
    
    this.chainId = Number(chainIdBigInt);
    console.log(`Network: ${network.name} (chainId: ${this.chainId})`);
    
    if (process.env.CHAIN_ID) {
      const envChainId = Number(process.env.CHAIN_ID);
      if (isNaN(envChainId) || envChainId < 1) {
        throw new Error(`Invalid CHAIN_ID in environment: ${process.env.CHAIN_ID}`);
      }
      if (envChainId !== this.chainId) {
        throw new Error(`CHAIN_ID mismatch: env=${envChainId}, provider=${this.chainId}. Please ensure CHAIN_ID matches your RPC endpoint's network.`);
      }
      console.log(`✓ CHAIN_ID validated: ${this.chainId}\n`);
    } else {
      console.log(`⚠️  CHAIN_ID not set, using ${this.chainId} from provider\n`);
      process.env.CHAIN_ID = String(this.chainId);
    }
    
    const defaults = this._knownDefaults[this.chainId];
    if (!process.env.REGISTRY_ADDR && !defaults) {
      throw new Error(`No default contract addresses for chainId ${this.chainId}. Please set REGISTRY_ADDR, STAKING_ADDR, ZFI_ADDR, and COORDINATOR_ADDR explicitly.`);
    }
    this._chainIdVerified = true;

    const REGISTRY_ADDR = process.env.REGISTRY_ADDR || defaults.REGISTRY_ADDR;
    const STAKING_ADDR = process.env.STAKING_ADDR || defaults.STAKING_ADDR;
    const ZFI_ADDR = process.env.ZFI_ADDR || defaults.ZFI_ADDR;
    const COORDINATOR_ADDR = process.env.COORDINATOR_ADDR || defaults.COORDINATOR_ADDR;

    console.log(`Contract Addresses:`);
    console.log(`  Registry: ${REGISTRY_ADDR}`);
    console.log(`  Staking: ${STAKING_ADDR}`);
    console.log(`  ZFI: ${ZFI_ADDR}`);
    console.log(`  Coordinator: ${COORDINATOR_ADDR}\n`);

    this.registry = new ethers.Contract(REGISTRY_ADDR, this._registryABI, this.wallet);
    this.staking = new ethers.Contract(STAKING_ADDR, this._stakingABI, this.wallet);
    this.zfi = new ethers.Contract(ZFI_ADDR, this._zfiABI, this.wallet);
    this.exchangeCoordinator = new ethers.Contract(COORDINATOR_ADDR, this._exchangeCoordinatorABI, this.wallet);

    // Configure P2P heartbeat EIP-712 domain (used for signed heartbeats)
    if (this.p2p && typeof this.p2p.setHeartbeatDomain === 'function') {
      try {
        this.p2p.setHeartbeatDomain(this.chainId, STAKING_ADDR);
      } catch (e) {
        console.warn('⚠️  Failed to configure P2P heartbeat domain:', e.message || String(e));
      }
    }

    try {
      await this.checkRequirements();
      await this.setupMonero();
      await this.startP2P();
      this.startHeartbeatLoop();
      try { 
        this.rpcManager.startHealthWatch(this.monero); 
      } catch (e) {
        console.warn('Failed to start RPC health watch:', e.message || String(e));
      }

      await this.ensureRegistered();
      await this.monitorNetwork();
      this.startSlashingLoop();
    } catch (e) {
      console.error('\n❌ Startup failed:', e.message || String(e));
      console.error('Cleaning up...');
      await this.stop();
      throw e;
    }
  }

  async stop() {
    try {
      // Best-effort on-chain unregister so only live nodes remain eligible
      try {
        if (this.registry && this.wallet && this.registry.nodes) {
          const info = await this.registry.nodes(this.wallet.address);
          let registered = false;
          if (info && info.registered !== undefined) {
            registered = !!info.registered;
          } else if (Array.isArray(info) && info.length >= 2) {
            registered = !!info[1];
          }
          if (registered) {
            console.log('→ Unregistering from network (shutdown)...');
            if (DRY_RUN) {
              console.log('[DRY_RUN] Would send unregisterNode transaction');
            } else {
              try {
                const tx = await this.registry.unregisterNode();
                await tx.wait();
                console.log('✓ Unregistered from network');
              } catch (e) {
                console.log('Unregister on shutdown failed:', e.message || String(e));
              }
            }
          }
        }
      } catch (e) {
        console.log('Deregistration status check failed:', e.message || String(e));
      }

      if (this.p2p && typeof this.p2p.stop === 'function') {
        try {
          await this.p2p.stop();
        } catch (e) {
          console.log('P2P stop error:', e.message || String(e));
        }
      }
      if (this.rpcManager && this.rpcManager._timer) {
        clearInterval(this.rpcManager._timer);
        this.rpcManager._timer = null;
      }
      if (this._heartbeatTimer) {
        clearInterval(this._heartbeatTimer);
        this._heartbeatTimer = null;
      }
      if (this._monitorTimer) {
        clearInterval(this._monitorTimer);
        this._monitorTimer = null;
      }
      console.log('ZNode stopped.');
    } catch (e) {
      console.log('Error during shutdown:', e.message || String(e));
    }
  }


  async checkRequirements() {
    console.log('→ Checking requirements...');

    // Verify network matches expected chain
    const network = await this.provider.getNetwork();
    console.log(`  Network: ${network.name} (chainId: ${network.chainId})`);

    // Ensure we have some ETH for gas
    const ethBalance = await this.provider.getBalance(this.wallet.address);
    if (ethBalance < ethers.parseEther('0.001')) {
      throw new Error('Insufficient ETH for gas (need >= 0.001 ETH)');
    }

    // Check ZFI balance and decimals
    let zfiDecimals;
    try {
      zfiDecimals = await this.zfi.decimals();
      console.log(`  ZFI Decimals: ${zfiDecimals}`);
    } catch (e) {
      if (!TEST_MODE) {
        throw new Error(`Failed to read ZFI decimals from contract. This is required in production mode: ${e.message}`);
      }
      console.warn(`⚠️  Could not read ZFI decimals, assuming 18 (TEST_MODE only): ${e.message}`);
      zfiDecimals = 18;
    }
    
    const zfiBal = await this.zfi.balanceOf(this.wallet.address);
    console.log(`  ZFI Balance: ${ethers.formatUnits(zfiBal, zfiDecimals)}`);

    // Read staking state using getNodeInfo
    let stakedAmt = 0n;
    let active = false;
    let slashingStage = 0n;
    let hoursOffline = 0n;
    try {
      const info = await this.staking.getNodeInfo(this.wallet.address);
      if (!Array.isArray(info) || info.length < 7) {
        console.warn('⚠️  Unexpected getNodeInfo response format, treating as not staked');
        stakedAmt = 0n;
      } else {
        stakedAmt = info[0];
        active = !!info[3];
        slashingStage = info[5];
        hoursOffline = info[6];
      }
    } catch {
      // Fallback if ABI/tuple width differs: treat as not staked
      stakedAmt = 0n;
    }
    console.log(`  ZFI Staked: ${ethers.formatUnits(stakedAmt, zfiDecimals)}`);

    // Check blacklist status (hard fail)
    let isBlacklisted = false;
    try {
      isBlacklisted = await this.staking.isBlacklisted(this.wallet.address);
    } catch (e) {
      console.warn('⚠️  Could not read blacklist status from staking contract:', e.message || String(e));
    }
    if (isBlacklisted) {
      throw new Error('This address has been blacklisted due to slashing. It cannot participate as a node.');
    }

    // Check for pending downtime slashing (informational only; slashing is now permissionless)
    try {
      const res = await this.staking.checkSlashingStatus(this.wallet.address);
      if (Array.isArray(res) && res.length >= 3) {
        const needsSlash = !!res[0];
        const stage = res[1];
        const hoursOfflinePending = res[2];
        if (needsSlash) {
          console.warn(`⚠️  checkSlashingStatus reports pending downtime slash (stage ${stage}, offline ${hoursOfflinePending} hours). Network participants may submit a slashing tx using signed heartbeats.`);
        }
      }
    } catch (e) {
      console.warn('⚠️  Could not read slashing status from staking contract:', e.message || String(e));
    }

    const required = ethers.parseUnits('1000000', zfiDecimals);

    if (stakedAmt >= required) {
      console.log('  Stake already at or above required amount.');
    } else {
      const stakingAddr = this.staking.target || this.staking.address;
      let amountNeeded;
      let actionLabel;

      if (stakedAmt > 0n) {
        amountNeeded = required - stakedAmt;
        actionLabel = 'top up existing stake';
        console.log(`  Detected partial stake. Need to top up by ${ethers.formatUnits(amountNeeded, zfiDecimals)} ZFI to reach 1,000,000.`);
      } else {
        amountNeeded = required;
        actionLabel = 'initial stake';
        console.log('  No existing stake found; will stake full 1,000,000 ZFI.');
      }

      if (zfiBal < amountNeeded) {
        const slashingStageNum = Number(slashingStage || 0n);
        if (slashingStageNum > 0) {
          throw new Error(`This node has been partially slashed (stage ${slashingStageNum}) and does not have enough ZFI to restore the full 1,000,000 ZFI stake. Missing ${ethers.formatUnits(amountNeeded, zfiDecimals)} ZFI.`);
        }
        throw new Error(`Insufficient ZFI to ${actionLabel} by ${ethers.formatUnits(amountNeeded, zfiDecimals)} ZFI`);
      }

      const allowance = await this.zfi.allowance(this.wallet.address, stakingAddr);
      if (allowance < amountNeeded) {
        const TEST_MODE = process.env.TEST_MODE === '1';
        const approvalMultiplier = TEST_MODE ? Number(process.env.APPROVAL_MULTIPLIER || '1') : 1;

        if (approvalMultiplier !== 1 && !TEST_MODE) {
          console.warn('⚠️  APPROVAL_MULTIPLIER ignored in production mode (using 1x)');
        }

        const approvalAmount = amountNeeded * BigInt(approvalMultiplier);

        console.log('  Approving ZFI for staking...');
        console.log(`  → approve(${stakingAddr}, ${ethers.formatUnits(approvalAmount, zfiDecimals)} ZFI)`);
        if (approvalMultiplier > 1) {
          console.log(`  ℹ️  TEST_MODE: Approving ${approvalMultiplier}x required amount`);
        }

        if (DRY_RUN) {
          console.log('  [DRY_RUN] Would send approve transaction');
        } else {
          const txA = await this.zfi.approve(stakingAddr, approvalAmount);
          await txA.wait();
          console.log('  ✓ Approved');
        }
      }

      if (stakedAmt === 0n) {
        // Fresh stake requires Monero fee address
        const moneroFeeAddr = process.env.MONERO_FEE_ADDRESS;
        if (!moneroFeeAddr) {
          throw new Error('MONERO_FEE_ADDRESS is required for staking. Set this to your Monero address for receiving fees.');
        }

        console.log('  Staking 1,000,000 ZFI...');
        const codeHash = ethers.id('znode-v3');
        console.log(`  → stake(${codeHash}, ${moneroFeeAddr})`);
        if (DRY_RUN) {
          console.log('  [DRY_RUN] Would send stake transaction');
        } else {
          const txS = await this.staking.stake(codeHash, moneroFeeAddr);
          await txS.wait();
          console.log('  ✓ Staked');
        }
      } else {
        // Partial stake: top up to full amount
        console.log('  Topping up existing stake to 1,000,000 ZFI...');
        console.log('  → topUpStake()');
        if (DRY_RUN) {
          console.log('  [DRY_RUN] Would send topUpStake transaction');
        } else {
          const txT = await this.staking.topUpStake();
          await txT.wait();
          console.log('  ✓ Top-up complete');
        }
      }
    }

    console.log('✓ Requirements met\n');
  }

  async setupMonero() {
    console.log('→ Setting up Monero with multisig support...');

    // Automatic wallet restore if wallets missing but backups exist
    try {
      const restoreScript = path.join(__dirname, 'auto-restore-wallet.sh');
      if (fs.existsSync(restoreScript)) {
        try {
          fs.accessSync(restoreScript, fs.constants.X_OK);
        } catch {
          console.warn('⚠️  auto-restore-wallet.sh exists but is not executable');
        }
        await execFileAsync(restoreScript, [], { cwd: __dirname, timeout: 30000 });
      }
    } catch (restoreErr) {
      const msg = restoreErr.message || String(restoreErr);
      if (!/exit code 0/i.test(msg)) {
        console.warn('⚠️  Wallet restore script failed:', msg);
      }
    }
    
    for (let i = 1; i <= 10; i++) {
      try {
        await this.monero.openWallet(this.baseWalletName, this.moneroPassword);
        console.log(`✓ Base wallet opened: ${this.baseWalletName}`);
        break;
      } catch (error) {
        if (error.code === 'ECONNREFUSED' && i < 10) {
          console.log(`  Waiting for Monero RPC (attempt ${i}/10)...`);
          await new Promise(r => setTimeout(r, 3000));
          continue;
        }
        
        if (error.code === 'ECONNREFUSED') {
          throw new Error('Monero RPC not available');
        }
        
        console.log('  Creating wallet with password...');
        try {
          await this.monero.createWallet(this.baseWalletName, this.moneroPassword);
          console.log(`✓ Base wallet created: ${this.baseWalletName}`);

          // Backup base wallet immediately after creation
          try {
            const backupScript = path.join(__dirname, 'auto-backup-wallet.sh');
            if (fs.existsSync(backupScript)) {
              try {
                fs.accessSync(backupScript, fs.constants.X_OK);
              } catch {
                throw new Error('auto-backup-wallet.sh exists but is not executable');
              }

              // Ensure we have a strong backup passphrase. If WALLET_BACKUP_PASSPHRASE
              // is not set in the environment, generate one and persist it to disk
              // so that auto-backup and auto-restore can reuse it safely.
              let backupPass = process.env.WALLET_BACKUP_PASSPHRASE;
              try {
                const homeDir = process.env.HOME || process.cwd();
                const defaultPassFile = path.join(homeDir, '.znode-backup', 'wallet_backup_passphrase.txt');
                const passFile = process.env.WALLET_BACKUP_PASSPHRASE_FILE || defaultPassFile;
                const passDir = path.dirname(passFile);
                try {
                  fs.mkdirSync(passDir, { recursive: true, mode: 0o700 });
                } catch { /* best-effort */ }

                if (!backupPass) {
                  if (fs.existsSync(passFile)) {
                    backupPass = fs.readFileSync(passFile, 'utf8').trim();
                    if (!backupPass) {
                      console.warn('⚠️  Wallet backup passphrase file is empty, regenerating a new one');
                    } else {
                      console.log('✓ Loaded existing wallet backup passphrase from disk');
                    }
                  }
                }

                if (!backupPass) {
                  backupPass = crypto.randomBytes(32).toString('hex');
                  fs.writeFileSync(passFile, backupPass + '\n', { mode: 0o600 });
                  console.log(`✓ Generated new wallet backup passphrase and saved to ${passFile}`);
                }
              } catch (passErr) {
                console.warn('⚠️  Failed to initialize wallet backup passphrase:', passErr.message || String(passErr));
              }

              const env = { ...process.env };
              if (backupPass) {
                env.WALLET_BACKUP_PASSPHRASE = backupPass;
              }

              await execFileAsync(backupScript, [], { cwd: __dirname, timeout: 30000, env });
              console.log("✓ Base wallet backed up using auto-backup-wallet.sh");
            } else {
              console.log("⚠️  auto-backup-wallet.sh not found, skipping automatic backup");
            }
          } catch (backupErr) {
            console.log("⚠️  Base wallet backup failed:", backupErr.message || String(backupErr));
          }
        } catch (e2) {
          const msg = (e2 && e2.message) ? e2.message : String(e2);
          // If the wallet already exists or creation timed out (RPC sluggish), try opening it
          if (/already exists/i.test(msg) || /timeout/i.test(msg)) {
            console.log('  Create failed or timed out; attempting to open...');
            try {
              await this.monero.openWallet(this.baseWalletName, this.moneroPassword);
              console.log(`✓ Base wallet opened: ${this.baseWalletName}`);
            } catch (e3) {
              // Could not open - wallet exists but password is wrong or corrupted
              const openMsg = (e3 && e3.message) ? e3.message : String(e3);
              console.error(`  ❌ Wallet exists but cannot open: ${openMsg}`);
              console.error(`  ℹ️  Run ./clean-restart to delete old wallet files and retry`);
              throw new Error(`Wallet ${this.baseWalletName} exists but cannot be opened. Run ./clean-restart to reset.`);
            }
          } else {
            throw e2;
          }
        }
        break;
      }
    }

    // Enable multisig experimental feature
    console.log('  Enabling multisig...');
    try {
      await this.monero.call('set', {
        key: 'enable-multisig-experimental',
        value: 1
      });
      console.log('✓ Multisig enabled\n');
    } catch {
      // May already be enabled or command format different
      console.log('  Multisig enable attempted\n');
    }
  }


  async startP2P() {
    console.log('→ Starting P2P network...');
    
    if (process.env.TEST_MODE !== '1' && process.env.P2P_REQUIRE_E2E !== '1') {
      throw new Error('P2P_REQUIRE_E2E=1 is required in production mode (TEST_MODE=0). Set it in your .env file to enable end-to-end encryption.');
    }
    
    try {
      const p2pPort = Number(process.env.P2P_PORT || 0); // 0 = random port
      await this.p2p.start(p2pPort);
      if (typeof this.p2p.startQueueDiscovery === 'function') {
        await this.p2p.startQueueDiscovery(this.wallet.address);
      }
      console.log('✓ P2P network started\n');
    } catch (error) {
      console.log('⚠️  P2P start failed:', error.message);
      console.log('  Cluster formation and multisig coordination are disabled until P2P is available.\n');
    }
  }

  async initClusterP2P(clusterId, clusterNodes) {
    if (!this.p2p || !this.p2p.node) {
      console.log('⚠️  P2P not available, using smart contract');
      return false;
    }
    
    try {
      console.log('→ Initializing P2P for cluster...');
      await this.p2p.connectToCluster(clusterId, clusterNodes, this.registry);
      // Give peers time to connect
      await new Promise(r => setTimeout(r, 3000));
      console.log('✓ P2P cluster initialized');
      return true;
    } catch (error) {
      console.log('⚠️  P2P cluster init failed:', error.message);
      return false;
    }
  }
  async prepareMultisig() {
    console.log('\n' + '→ Preparing multisig...');
    try {
      const info = await this.monero.prepareMultisig();
      this.multisigInfo = info;
      console.log('✓ Multisig info generated');
      const infoHash = crypto.createHash('sha256').update(this.multisigInfo).digest('hex').slice(0, 10);
      console.log(`  Info hash: ${infoHash}... (length: ${this.multisigInfo.length})`);
      return this.multisigInfo;
    } catch (error) {
      // If wallet is already multisig from previous deployment, create a fresh base wallet with a new name
      if (error.message && error.message.toLowerCase().includes('already multisig')) {
        console.log('  Wallet is already multisig from old deployment. Creating a fresh base wallet...');
        try {
          try { await this.monero.closeWallet(); } catch {}
          await new Promise(r => setTimeout(r, 500));
          // Bump base wallet name to a new suffix to avoid "Already exists"
          const suffix = Math.floor(Date.now()/1000).toString(36).slice(-4);
          this.baseWalletName = `${this.baseWalletName}_b${suffix}`;
          await this.monero.createWallet(this.baseWalletName, this.moneroPassword);
          console.log(`  ✓ New base wallet created: ${this.baseWalletName}`);

          // Backup base wallet immediately after creation
          try {
            const backupScript = path.join(__dirname, 'auto-backup-wallet.sh');
            if (fs.existsSync(backupScript)) {
              try {
                fs.accessSync(backupScript, fs.constants.X_OK);
              } catch {
                throw new Error('auto-backup-wallet.sh exists but is not executable');
              }

              // Ensure we have a strong backup passphrase. If WALLET_BACKUP_PASSPHRASE
              // is not set in the environment, generate one and persist it to disk
              // so that auto-backup and auto-restore can reuse it safely.
              let backupPass = process.env.WALLET_BACKUP_PASSPHRASE;
              try {
                const homeDir = process.env.HOME || process.cwd();
                const defaultPassFile = path.join(homeDir, '.znode-backup', 'wallet_backup_passphrase.txt');
                const passFile = process.env.WALLET_BACKUP_PASSPHRASE_FILE || defaultPassFile;
                const passDir = path.dirname(passFile);
                try {
                  fs.mkdirSync(passDir, { recursive: true, mode: 0o700 });
                } catch { /* best-effort */ }

                if (!backupPass) {
                  if (fs.existsSync(passFile)) {
                    backupPass = fs.readFileSync(passFile, 'utf8').trim();
                    if (!backupPass) {
                      console.warn('⚠️  Wallet backup passphrase file is empty, regenerating a new one');
                    } else {
                      console.log('✓ Loaded existing wallet backup passphrase from disk');
                    }
                  }
                }

                if (!backupPass) {
                  backupPass = crypto.randomBytes(32).toString('hex');
                  fs.writeFileSync(passFile, backupPass + '\n', { mode: 0o600 });
                  console.log(`✓ Generated new wallet backup passphrase and saved to ${passFile}`);
                }
              } catch (passErr) {
                console.warn('⚠️  Failed to initialize wallet backup passphrase:', passErr.message || String(passErr));
              }

              const env = { ...process.env };
              if (backupPass) {
                env.WALLET_BACKUP_PASSPHRASE = backupPass;
              }

              await execFileAsync(backupScript, [], { cwd: __dirname, timeout: 30000, env });
              console.log("✓ Base wallet backed up using auto-backup-wallet.sh");
            } else {
              console.log("⚠️  auto-backup-wallet.sh not found, skipping automatic backup");
            }
          } catch (backupErr) {
            console.log("⚠️  Base wallet backup failed:", backupErr.message || String(backupErr));
          }
          // Now try prepare_multisig again
          const info2 = await this.monero.prepareMultisig();
          this.multisigInfo = info2;
          console.log('✓ Multisig info generated');
          const infoHash2 = crypto.createHash('sha256').update(this.multisigInfo).digest('hex').slice(0, 10);
          console.log(`  Info hash: ${infoHash2}... (length: ${this.multisigInfo.length})`);
          return this.multisigInfo;
        } catch (e) {
          console.error('❌ Failed to create fresh base wallet:', e.message);
          throw e;
        }
      }
      console.error('❌ prepare_multisig failed:', error.message);
      throw error;
    }
  }
  async makeMultisig(multisigInfos, threshold) {
    console.log(`\n→ Creating ${threshold}-of-${multisigInfos.length + 1} multisig...`);
    
    try {
      const result = await this.monero.call('make_multisig', {
        multisig_info: multisigInfos,
        threshold: threshold,
        password: this.moneroPassword
      });
      
      console.log('✓ Multisig wallet created');
      console.log(`  Address: ${result.address}`);
      
      return result;
    } catch (error) {
      console.error('❌ make_multisig failed:', error.message);
      throw error;
    }
  }

  async startClusterMultisigV3(clusterId, members, isCoordinator, threshold = 7) {
    const recordClusterFailure = (reason) => {
      const reachable = this.p2p ? this.p2p.countConnectedPeers() : 0;
      const currentCount = this._clusterFailures.get(clusterId) || 0;
      const newCount = currentCount + 1;
      this._clusterFailures.set(clusterId, newCount);
      this._clusterFailMeta[clusterId] = {
        failures: newCount,
        reachable,
        lastFailureAt: Date.now(),
        reason
      };
      
      if (newCount >= 3) {
        if (!this._clusterBlacklist) this._clusterBlacklist = {};
        const baseCooldownMs = Number(process.env.CLUSTER_BLACKLIST_BASE_COOLDOWN_MS || 600000);
        const cooldownMs = baseCooldownMs * Math.pow(2, Math.min(newCount - 3, 4));
        this._clusterBlacklist[clusterId] = Date.now() + cooldownMs;
        console.log(`⚠️ Cluster ${clusterId.slice(0,10)} blacklisted for ${cooldownMs/60000} minutes (${newCount} failures, adaptive cooldown)`);
      }
      
      this._saveClusterBlacklist();
    };

    const roundTimeoutPrepare = Number(process.env.ROUND_TIMEOUT_PREPARE_MS || 300000);
    const roundTimeoutExchange = Number(process.env.ROUND_TIMEOUT_EXCHANGE_MS || 180000);

    try {
      if (!this.p2p || !this.p2p.node) {
        console.log('⚠️ P2P not available - cannot perform multisig coordination');
        return false;
      }

      // Ensure base multisig info is prepared
      if (!this.multisigInfo) {
        await this.prepareMultisig();
      }

      // Round 0: exchange prepare_multisig payloads via P2P
      console.log('\n→ Round 0: exchanging prepare_multisig info via P2P...');
      await this.p2p.broadcastRoundData(clusterId, 0, this.multisigInfo);
      const complete0 = await this.p2p.waitForRoundCompletion(clusterId, 0, members, roundTimeoutPrepare);
      if (!complete0) {
        console.log('❌ Round 0 incomplete - not all nodes submitted within timeout');
        recordClusterFailure('round0_timeout');
        return false;
      }

      const peers = this.p2p.getPeerPayloads(clusterId, 0, members);
      const expectedPeerCount = members.length - 1; // Exclude self
      if (!Array.isArray(peers) || peers.length < expectedPeerCount) {
        console.log(`❌ Round 0: expected ${expectedPeerCount} peer multisig infos, got ${peers.length}`);
        recordClusterFailure('round0_peers_short');
        return false;
      }

      console.log(`Using base wallet for multisig: ${this.baseWalletName}`);
      
      try {
        await this.monero.call('set', { key: 'enable-multisig-experimental', value: 1 });
        console.log('  ✓ Multisig experimental mode enabled');
      } catch (e) {
        console.log('  ⚠️ Failed to enable multisig experimental mode:', e.message || String(e));
      }

      // Initialize multisig wallet using peers' infos on the same wallet that ran prepare_multisig
      const res = await this.makeMultisig(peers, threshold);
      if (res && (res.multisig_info || res.multisigInfo)) {
        this._pendingR3 = res.multisig_info || res.multisigInfo;
      } else {
        this._pendingR3 = '';
      }

      // Round 3: broadcast R3 payloads
      if (!this._pendingR3 || this._pendingR3.length === 0) {
        console.log('❌ No Round 3 payload available after make_multisig');
        return false;
      }

      console.log('\n→ Round 3: broadcasting key exchange payload via P2P...');
      await this.p2p.broadcastRoundData(clusterId, 3, this._pendingR3);
      const complete3 = await this.p2p.waitForRoundCompletion(clusterId, 3, members, roundTimeoutExchange);
      if (!complete3) {
        console.log('❌ Round 3 incomplete - not all nodes submitted within timeout');
        recordClusterFailure('round3_timeout');
        return false;
      }

      // Round 4+ key exchange rounds
      const { success, lastRound, lastPeerPayloads } = await this.runKeyExchangeRounds(clusterId, members, 4);
      if (!success) {
        console.log(`❌ Key exchange failed at round ${lastRound}`);
        recordClusterFailure('key_exchange_failed');
        return false;
      }

      console.log('  → Finalizing multisig with peer keys...');
      try {
        await this.monero.finalizeMultisig(lastPeerPayloads);
      } catch {
        // Fallback without parameters
        try {
          await this.monero.finalizeMultisig();
        } catch (e2) {
          console.log('  ⚠️  Finalize multisig error:', e2.message || String(e2));
        }
      }

      const finalizeRetries = Number(process.env.FINALIZE_READY_RETRIES || 10);
      const finalizeDelayMs = Number(process.env.FINALIZE_READY_DELAY_MS || 5000);
      
      let info;
      let retries = finalizeRetries;
      while (retries > 0) {
        try {
          info = await this.monero.call('is_multisig');
          if (info && info.ready) {
            break;
          }
          if (retries > 1) {
            console.log(`  ⏳ Multisig not ready yet, waiting ${finalizeDelayMs}ms before retry (${retries - 1} retries left)...`);
            await new Promise(resolve => setTimeout(resolve, finalizeDelayMs));
          }
        } catch (e) {
          console.log('  ⚠️  is_multisig check failed:', e.message || String(e));
          if (retries > 1) {
            await new Promise(resolve => setTimeout(resolve, finalizeDelayMs));
          }
        }
        retries--;
      }

      if (!info || !info.ready) {
        console.log('❌ Multisig still not ready after finalize and retries');
        recordClusterFailure('final_multisig_not_ready');
        return false;
      }

      const getAddrResult = await this.monero.call('get_address');
      const finalAddr = getAddrResult.address;

      // Automatic wallet backup after successful multisig creation
      try {
        const backupScript = path.join(__dirname, 'auto-backup-wallet.sh');
        if (fs.existsSync(backupScript)) {
          await execFileAsync(backupScript, [], { cwd: __dirname, timeout: 30000 });
          console.log("✓ Multisig wallet backed up automatically using auto-backup-wallet.sh");
        } else {
          console.log("⚠️  auto-backup-wallet.sh not found, skipping automatic backup");
        }
      } catch (backupErr) {
        console.log("⚠️  Wallet backup failed:", backupErr.message || String(backupErr));
      }
      console.log(`
✅ Final multisig address: ${finalAddr}`);

      // Cache final address and start time for potential coordinator failover
      this._clusterFinalAddress = finalAddr;
      this._clusterFinalizationStartAt = Date.now();

      if (isCoordinator) {
        const jitterMs = Math.floor(Math.random() * 2000);
        if (jitterMs > 0) {
          console.log(`  → Adding ${jitterMs}ms jitter to reduce coordinator collision`);
          await new Promise(resolve => setTimeout(resolve, jitterMs));
        }
        
        const maxRetries = 3;
        let attempt = 0;
        let finalized = false;
        
        while (attempt < maxRetries && !finalized) {
          attempt++;
          try {
            const alreadyFinalized = await this.isClusterFinalized(clusterId);
            if (alreadyFinalized) {
              console.log('✓ Cluster already finalized on-chain (by another coordinator)');
              finalized = true;
              break;
            }
            
            console.log(`  → Attempt ${attempt}/${maxRetries}: finalizeCluster([${members.length} members], ${finalAddr})`);
            if (DRY_RUN) {
              console.log('  [DRY_RUN] Would send finalizeCluster transaction');
              finalized = true;
            } else {
              const tx = await this.registry.finalizeCluster(members, finalAddr);
              const receipt = await tx.wait();
              console.log('✓ Cluster finalized on-chain (v3)');
              finalized = true;
            }
          } catch (e) {
            const msg = (e && e.message) ? e.message : String(e);
            
            if (/already finalized|already exists|cluster.*finalized/i.test(msg)) {
              console.log('✓ Cluster already finalized on-chain (race condition handled)');
              finalized = true;
              break;
            }
            
            if (/nonce.*too low|replacement.*underpriced|already known/i.test(msg)) {
              console.log(`  ⚠️  Nonce/replacement error (attempt ${attempt}/${maxRetries}): ${msg}`);
              if (attempt < maxRetries) {
                const backoffMs = 1000 * Math.pow(2, attempt - 1);
                console.log(`  → Waiting ${backoffMs}ms before retry...`);
                await new Promise(resolve => setTimeout(resolve, backoffMs));
                continue;
              }
            }
            
            console.log(`  ⚠️  finalizeCluster error (attempt ${attempt}/${maxRetries}): ${msg}`);
            const nowFinalized = await this.isClusterFinalized(clusterId);
            if (nowFinalized) {
              console.log('✓ Cluster finalized despite error (transaction succeeded)');
              finalized = true;
              break;
            }
            
            if (attempt >= maxRetries) {
              console.log('❌ finalizeCluster() failed after all retries');
              return false;
            }
            
            const backoffMs = 1000 * Math.pow(2, attempt - 1);
            console.log(`  → Waiting ${backoffMs}ms before retry...`);
            await new Promise(resolve => setTimeout(resolve, backoffMs));
          }
        }
      } else {
        console.log('⏳ Waiting for coordinator to finalize cluster on-chain...');
      }

      if (this.sst) {
        try {
          console.log('\n→ Starting SST key distribution...');
          await this.distributeSSTKeys(clusterId, members);
          console.log('✓ SST key distribution complete');
        } catch (sstError) {
          console.log('⚠️  SST key distribution failed:', sstError.message);
        }
      }

      return true;
    } catch (e) {
      console.log('❌ Cluster multisig v3 error:', e.message || String(e));
      recordClusterFailure('exception');
      
      if (this.p2p && typeof this.p2p.leaveCluster === 'function') {
        try {
          await this.p2p.leaveCluster(clusterId);
          this.p2p.cleanupOldMessages();
        } catch (cleanupErr) {
          console.log('⚠️  P2P cleanup error:', cleanupErr.message);
        }
      }
      
      return false;
    }
  }

  async distributeSSTKeys(clusterId, members) {
    const roundTimeoutSST = Number(process.env.ROUND_TIMEOUT_SST_MS || 180000);
    
    console.log('  → Round 99: Broadcasting identity (public key)...');
    
    const signingKey = new ethers.SigningKey(this.wallet.privateKey);
    const publicKey = signingKey.publicKey;
    const timestamp = Date.now();
    const nonce = '0x' + crypto.randomBytes(16).toString('hex');
    
    const identityMessage = {
      type: 'sst/identity',
      clusterId,
      address: this.wallet.address,
      publicKey,
      timestamp,
      nonce
    };
    
    const message = `${identityMessage.type}:${clusterId}:${this.wallet.address}:${publicKey}:${nonce}:${timestamp}`;
    const digest = ethers.id(message);
    const identitySignature = signingKey.sign(digest).serialized;
    
    identityMessage.signature = identitySignature;
    
    await this.p2p.broadcastSSTMessage(clusterId, identityMessage);
    
    const identitiesComplete = await this.p2p.waitForSSTIdentities(clusterId, members, roundTimeoutSST);
    if (!identitiesComplete) {
      throw new Error('Identity round incomplete - not all nodes submitted identities');
    }
    
    console.log('  → Extracting Monero private key...');
    let privateKey;
    try {
      privateKey = await this.monero.queryKey('spend_key');
    } catch (e) {
      throw new Error(`Failed to extract Monero private key: ${e.message}`);
    }
    
    console.log('  → Splitting key with Shamir\'s Secret Sharing...');
    const shares = this.sst.splitSecret(privateKey);
    
    console.log('  → Round 100: Broadcasting encrypted shares...');
    const identities = this.p2p.getSSTIdentities(clusterId);
    
    const sortedMembers = members.map(m => m.toLowerCase()).sort();
    
    const sharePromises = sortedMembers.map(async (recipientLower, i) => {
      const recipientIdentity = identities.get(recipientLower);
      
      if (!recipientIdentity) {
        console.log(`  ⚠️  No identity found for ${recipientLower.slice(0, 8)}, skipping`);
        return;
      }
      
      try {
        const recipientPublicKey = recipientIdentity.publicKey;
        const encryptedShare = this.sst.encryptForRecipient(shares[i], recipientPublicKey);
        
        const shareEnvelope = this.sst.createShareEnvelope({
          clusterId,
          ownerAddress: this.wallet.address,
          recipientAddress: recipientLower,
          shareIndex: i + 1,
          encryptedShare,
          privateKey: this.wallet.privateKey,
          timestamp: Date.now()
        });
        
        await this.p2p.broadcastSSTMessage(clusterId, shareEnvelope);
        
        if (recipientLower === this.wallet.address.toLowerCase()) {
          await this.sst.storeShare(clusterId, shareEnvelope);
        }
      } catch (e) {
        console.log(`  ⚠️  Failed to encrypt/broadcast share for ${recipientLower.slice(0, 8)}:`, e.message);
      }
    });
    
    await Promise.all(sharePromises);
    
    console.log('  → Waiting for shares from other nodes...');
    const otherMembers = members.filter(m => m.toLowerCase() !== this.wallet.address.toLowerCase());
    const sharesComplete = await this.p2p.waitForSSTShares(clusterId, otherMembers, this.wallet.address, roundTimeoutSST);
    
    if (!sharesComplete) {
      console.log('  ⚠️  Not all shares received within timeout');
    }
    
    console.log('  → Storing received shares...');
    for (const member of otherMembers) {
      const memberAddr = member.toLowerCase();
      
      const share = this.p2p.getSSTShares(clusterId, memberAddr, this.wallet.address.toLowerCase());
      if (share) {
        try {
          this.sst.verifyShareEnvelope(share);
          await this.sst.storeShare(clusterId, share);
          console.log(`  ✓ Stored share from ${memberAddr.slice(0, 8)}`);
        } catch (e) {
          console.log(`  ⚠️  Failed to verify/store share from ${memberAddr.slice(0, 8)}:`, e.message);
        }
      } else {
        console.log(`  ⚠️  No share received from ${memberAddr.slice(0, 8)}`);
      }
    }
  }

  async runKeyExchangeRounds(clusterId, clusterNodes, startRound = 4) {
    const maxRounds = Number(process.env.MAX_KEY_EXCHANGE_ROUNDS || 7);
    const roundTimeoutExchange = Number(process.env.ROUND_TIMEOUT_EXCHANGE_MS || 180000);
    let round = startRound;
    let prevRound = 3;

    if (!this._multisigExperimentalEnabled) {
      try {
        await this.monero.call('set', { key: 'enable-multisig-experimental', value: 1 });
        this._multisigExperimentalEnabled = true;
        console.log('  ✓ Multisig experimental mode enabled for key exchange');
      } catch (e) {
        console.log('  ⚠️ Failed to enable multisig experimental mode:', e.message || String(e));
      }
    }

    for (let i = 0; i < maxRounds; i++) {
      console.log(`  → Key exchange round ${round} (${i + 1}/${maxRounds})`);

      const peersPrev = this.p2p.getPeerPayloads(clusterId, prevRound, clusterNodes);
      if (!Array.isArray(peersPrev) || peersPrev.length === 0) {
        console.log(`  ⚠️  No peer payloads found for round ${prevRound}; cannot proceed`);
        return { success: false, lastRound: round - 1, lastPeerPayloads: peersPrev || [] };
      }

      console.log(`  ✓ Using ${peersPrev.length} peer payloads from Round ${prevRound}`);

      let myPayload = '';
      try {
        const res = await this.monero.exchangeMultisigKeys(peersPrev, this.moneroPassword);
        if (!res || typeof res !== 'object') {
          console.log(`  ⚠️  exchangeMultisigKeys returned invalid response: ${typeof res}`);
          return { success: false, lastRound: round - 1, lastPeerPayloads: peersPrev };
        }
        if (res.multisig_info) {
          myPayload = res.multisig_info;
        } else if (typeof res === 'string') {
          myPayload = res;
        } else {
          myPayload = '';
        }
      } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        if (/kex is already complete/i.test(msg) || /already complete/i.test(msg)) {
          console.log('  ✓ Multisig key exchange already complete at wallet level');
          try {
            const info = await this.monero.call('is_multisig');
            if (info && info.ready) {
              return { success: true, lastRound: prevRound, lastPeerPayloads: peersPrev };
            }
          } catch {}
          console.log('  ⚠️  Wallet reports exchange complete but multisig not ready');
          return { success: false, lastRound: prevRound, lastPeerPayloads: peersPrev };
        }
        console.log(`  ❌ exchange_multisig_keys error in round ${round}:`, msg);
        return { success: false, lastRound: prevRound, lastPeerPayloads: peersPrev };
      }

      console.log(`  → Broadcasting Round ${round} via P2P...`);
      await this.p2p.broadcastRoundData(clusterId, round, myPayload);
      console.log(`  ✓ Round ${round} broadcast complete`);

      console.log(`  → Waiting for Round ${round} completion...`);
      const complete = await this.p2p.waitForRoundCompletion(clusterId, round, clusterNodes, roundTimeoutExchange);
      if (!complete) {
        console.log(`  ❌ Round ${round} incomplete - not all nodes submitted within timeout`);
        const peersCurrent = this.p2p.getPeerPayloads(clusterId, round, clusterNodes);
        return { success: false, lastRound: round, lastPeerPayloads: peersCurrent };
      }

      const peersCurrent = this.p2p.getPeerPayloads(clusterId, round, clusterNodes);

      try {
        const info = await this.monero.call('is_multisig');
        if (info && info.ready) {
          console.log(`  ✓ Multisig is ready after Round ${round}`);
          return { success: true, lastRound: round, lastPeerPayloads: peersCurrent };
        }
      } catch (e) {
        console.log('  ⚠️  is_multisig check failed:', e.message || String(e));
      }

      prevRound = round;
      round += 1;
    }

    console.log('  ⚠️  Max key exchange rounds reached without ready multisig');
    const lastPayloads = this.p2p.getPeerPayloads(clusterId, prevRound, clusterNodes);
    return { success: false, lastRound: prevRound, lastPeerPayloads: lastPayloads };
  }






  async ensureRegistered() {
    console.log('→ Registering to network (v3)...');

    // Ensure we have multisig info prepared for later P2P coordination
    if (!this.multisigInfo) {
      try {
        await this.prepareMultisig();
      } catch (e) {
        console.log('❌ Failed to prepare multisig during registration:', e.message || String(e));
      }
    }

    let registered = false;
    try {
      const info = await this.registry.nodes(this.wallet.address);
      if (info && info.registered !== undefined) {
        console.log('[Registry] Using named field ABI decoding for nodes()');
        registered = !!info.registered;
      } else if (Array.isArray(info) && info.length >= 2) {
        console.log('[Registry] Using tuple ABI decoding for nodes() (fallback)');
        registered = !!info[1];
      }
    } catch {
      console.log('[Registry] nodes() call failed, assuming not registered');
      registered = false;
    }

    if (registered) {
      console.log('✓ Already registered\n');
      return;
    }

    const codeHash = ethers.id('znode-v3');
    console.log(`  → registerNode(${codeHash})`);
    if (DRY_RUN) {
      console.log('  [DRY_RUN] Would send registerNode transaction');
    } else {
      const tx = await this.registry.registerNode(codeHash);
      await tx.wait();
      console.log('✓ Registered\n');
    }
  }

  async isClusterFinalized(clusterId) {
    try {
      const clusterInfo = await this.registry.clusters(clusterId);
      return !!(clusterInfo && clusterInfo[3]);
    } catch {
      return false;
    }
  }



  startHeartbeatLoop() {
    const intervalSec = Number(process.env.HEARTBEAT_INTERVAL || 900);
    if (this._heartbeatTimer) return;
    
    this._heartbeatFailures = 0;
    this._heartbeatBackoffUntil = 0;
    
    const tick = async () => {
      try {
        const now = Date.now();
        if (now < this._heartbeatBackoffUntil) {
          const remaining = Math.ceil((this._heartbeatBackoffUntil - now) / 1000);
          console.log(`[Heartbeat] Backing off for ${remaining}s after ${this._heartbeatFailures} consecutive failures`);
          return;
        }
        
        if (!this.p2p) return;
        
        if (DRY_RUN) {
          if (!this._hbLogOnce) { console.log('✓ P2P Heartbeat enabled (interval', intervalSec, 's) [DRY_RUN - not sending]'); this._hbLogOnce = true; }
        } else {
          await this.p2p.broadcastHeartbeat();
          this._lastHeartbeatAt = Date.now();
          this._heartbeatFailures = 0;
          this._heartbeatBackoffUntil = 0;
          if (!this._hbLogOnce) { console.log('✓ P2P Heartbeat enabled (interval', intervalSec, 's)'); this._hbLogOnce = true; }
        }
      } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        console.warn('P2P heartbeat() error:', msg);
        this._heartbeatFailures++;
        
        if (this._heartbeatFailures >= 3) {
          const backoffMs = Math.min(60000 * Math.pow(2, this._heartbeatFailures - 3), 3600000);
          this._heartbeatBackoffUntil = Date.now() + backoffMs;
          console.warn(`[Heartbeat] ${this._heartbeatFailures} consecutive failures, backing off for ${backoffMs / 1000}s`);
        }
      }
    };
    this._heartbeatTimer = setInterval(tick, intervalSec * 1000);
    setTimeout(tick, 10_000);
  }

  _currentSlashEpoch(blockTimestamp, epochSec) {
    const ts = typeof blockTimestamp === 'bigint' ? Number(blockTimestamp) : Number(blockTimestamp || 0);
    if (!Number.isFinite(ts) || ts <= 0) return 0;
    return Math.floor(ts / epochSec);
  }

  _selectSlashLeader(activeNodes, targetNode, epoch, salt) {
    if (!activeNodes || activeNodes.length === 0) return null;
    const seed = ethers.keccak256(
      ethers.solidityPacked(
        ['address', 'uint256', 'bytes32'],
        [targetNode, epoch, salt]
      )
    );
    const asBigInt = BigInt(seed);
    const idx = Number(asBigInt % BigInt(activeNodes.length));
    return activeNodes[idx];
  }

  startSlashingLoop() {
    if (this._slashingTimer) return;
    if (!this.staking || !this.provider || !this.p2p) return;

    const epochRaw = process.env.SLASH_EPOCH_SECONDS;
    const epochParsed = epochRaw != null ? Number(epochRaw) : NaN;
    const epochSec = (Number.isFinite(epochParsed) && epochParsed > 0) ? epochParsed : 600; // default 10 minutes

    const offlineRaw = process.env.SLASH_OFFLINE_THRESHOLD_HOURS;
    const offlineParsed = offlineRaw != null ? Number(offlineRaw) : NaN;
    const offlineHours = (Number.isFinite(offlineParsed) && offlineParsed > 0) ? offlineParsed : 48;

    const loopRaw = process.env.SLASH_LOOP_INTERVAL_MS;
    const loopParsed = loopRaw != null ? Number(loopRaw) : NaN;
    const loopMs = (Number.isFinite(loopParsed) && loopParsed > 0) ? loopParsed : 5 * 60 * 1000; // default 5 minutes

    const stakingAddr = (this.staking.target || this.staking.address || '').toString();
    const salt = stakingAddr && stakingAddr !== ethers.ZeroAddress ? stakingAddr : ethers.ZeroHash;

    const selfAddr = this.wallet.address.toLowerCase();

    const tick = async () => {
      try {
        if (!this.staking || !this.provider || !this.p2p) return;

        const latest = await this.provider.getBlock('latest');
        if (!latest || latest.timestamp == null) return;

        const epoch = this._currentSlashEpoch(latest.timestamp, epochSec);
        const activeNodes = await this.staking.getActiveNodes();
        if (!Array.isArray(activeNodes) || activeNodes.length === 0) return;

        const nowSec = Math.floor(Date.now() / 1000);

        for (const nodeAddr of activeNodes) {
          if (!nodeAddr) continue;
          const lower = nodeAddr.toLowerCase();
          if (lower === selfAddr) continue;

          const hb = this.p2p.getLastHeartbeat(nodeAddr);
          if (!hb || hb.timestamp == null) continue;

          const tsSec = Number(hb.timestamp);
          if (!Number.isFinite(tsSec) || tsSec <= 0) continue;

          const ageSec = Math.max(0, nowSec - tsSec);
          const hoursOffline = ageSec / 3600;
          if (hoursOffline < offlineHours) continue;

          const leader = this._selectSlashLeader(activeNodes, nodeAddr, epoch, salt);
          if (!leader || leader.toLowerCase() !== selfAddr) continue;

          // Optional local gas check
          const minGasWeiRaw = process.env.SLASH_MIN_GAS_WEI;
          if (minGasWeiRaw) {
            try {
              const balance = await this.provider.getBalance(this.wallet.address);
              const minGasWei = BigInt(minGasWeiRaw);
              if (balance < minGasWei) {
                continue;
              }
            } catch {
              // If balance check fails, fall through and attempt; node/operator can tune config
            }
          }

          const tsArg = BigInt(tsSec);

          if (DRY_RUN) {
            console.log(`[SLASH-DRY] Would call slashForDowntimeWithProof for ${nodeAddr} (offline ~${hoursOffline.toFixed(2)}h)`);
            continue;
          }

          try {
            const gasLimitRaw = process.env.SLASH_GAS_LIMIT;
            const gasLimitParsed = gasLimitRaw != null ? Number(gasLimitRaw) : NaN;
            const gasOverride = (Number.isFinite(gasLimitParsed) && gasLimitParsed > 0)
              ? { gasLimit: BigInt(Math.floor(gasLimitParsed)) }
              : {};

            const tx = await this.staking.slashForDowntimeWithProof(
              nodeAddr,
              tsArg,
              hb.signature,
              gasOverride
            );
            console.log(`[SLASH] Submitted slashForDowntimeWithProof for ${nodeAddr} (tx: ${tx.hash})`);
            await tx.wait();
            console.log(`[SLASH] SlashForDowntimeWithProof confirmed for ${nodeAddr}`);
          } catch (e) {
            const msg = e && e.message ? e.message : String(e);
            console.warn(`[SLASH] Failed to slash ${nodeAddr}:`, msg);
          }
        }
      } catch (e) {
        const msg = e && e.message ? e.message : String(e);
        console.warn('[SLASH] Slashing loop error:', msg);
      }
    };

    this._slashingTimer = setInterval(tick, loopMs);
    setTimeout(tick, 30_000);
  }



  async monitorNetwork() {
    console.log('→ Monitoring network...');
    console.log('🎉 Monero multisig is WORKING!');
    console.log('Wallet has password and multisig is enabled.\n');

    this._clusterFinalized = this._clusterFinalized || false;

    const selfAddr = this.wallet.address.toLowerCase();

    const rawHealthInterval = process.env.HEALTH_LOG_INTERVAL_MS;
    const parsedHealthInterval = rawHealthInterval != null ? Number(rawHealthInterval) : NaN;
    const healthIntervalMs = (Number.isFinite(parsedHealthInterval) && parsedHealthInterval > 0)
      ? parsedHealthInterval
      : 5 * 60 * 1000;

    const clusterSizeRaw = process.env.CLUSTER_SIZE;
    const clusterSizeParsed = clusterSizeRaw != null ? Number(clusterSizeRaw) : NaN;
    const clusterSize = (Number.isFinite(clusterSizeParsed) && clusterSizeParsed > 0) ? clusterSizeParsed : 11;

    const clusterThresholdRaw = process.env.CLUSTER_THRESHOLD;
    const clusterThresholdParsed = clusterThresholdRaw != null ? Number(clusterThresholdRaw) : NaN;
    const clusterThreshold = (Number.isFinite(clusterThresholdParsed) && clusterThresholdParsed > 0) ? clusterThresholdParsed : 7;

    const computeCandidateCluster = async () => {
      try {
        const maxScanRaw = process.env.MAX_REGISTERED_SCAN;
        const maxScanParsed = maxScanRaw != null ? Number(maxScanRaw) : NaN;
        const maxScan = (Number.isFinite(maxScanParsed) && maxScanParsed > 0) ? maxScanParsed : 256;
        
        const maxPagesRaw = process.env.MAX_REGISTERED_PAGES;
        const maxPagesParsed = maxPagesRaw != null ? Number(maxPagesRaw) : NaN;
        const maxPages = (Number.isFinite(maxPagesParsed) && maxPagesParsed > 0) ? maxPagesParsed : 10;

        const candidates = [];
        let offset = 0;
        let pagesScanned = 0;
        
        while (pagesScanned < maxPages) {
          const page = await this.registry.getRegisteredNodes(offset, maxScan);
          if (!page || page.length === 0) break;
          
          for (const addr of page) {
            if (!addr || addr === ethers.ZeroAddress) continue;
            try {
              const can = await this.registry.canParticipate(addr);
              if (!can) continue;
              candidates.push(addr);
            } catch {
            }
          }
          
          if (page.length < maxScan) break;
          offset += maxScan;
          pagesScanned++;
        }

        if (candidates.length < clusterSize) {
          return null;
        }

        // Epoch-based randomized selection: shuffle candidates deterministically per epoch
        let epochSeed = ethers.ZeroHash;
        try {
          const blockNumber = await this.provider.getBlockNumber();
          const rawSpan = process.env.SELECTION_EPOCH_BLOCKS;
          const parsedSpan = rawSpan != null ? Number(rawSpan) : NaN;
          const epochSpan = (Number.isFinite(parsedSpan) && parsedSpan > 0) ? parsedSpan : 20;
          const epoch = Number(blockNumber) / epochSpan | 0;
          epochSeed = ethers.keccak256(ethers.solidityPacked(['uint256'], [epoch]));
        } catch {
          // Fallback: zero seed (degenerates to lexicographic sort)
        }

        const uniqueCandidates = [...new Set(candidates.map(a => a.toLowerCase()))];
        if (uniqueCandidates.length < clusterSize) {
          return null;
        }

        const scored = uniqueCandidates.map(lower => {
          const score = ethers.keccak256(ethers.solidityPacked(['bytes32','address'], [epochSeed, lower]));
          return { lower, score };
        });

        scored.sort((a, b) => a.score.localeCompare(b.score));
        const chosen = scored.slice(0, clusterSize);
        const membersLower = chosen.map(x => x.lower);
        
        if (membersLower.length !== clusterSize) {
          console.log(`⚠️  Cluster member count mismatch: expected ${clusterSize}, got ${membersLower.length}`);
          return null;
        }
        
        const members = membersLower.map(addr => ethers.getAddress(addr));
        const sortedMembersLower = [...membersLower].sort();
        const addressTypes = Array(clusterSize).fill('address');
        const clusterId = ethers.keccak256(ethers.solidityPacked(addressTypes, sortedMembersLower));

        // Skip blacklisted clusters for a cooldown period
        if (this._clusterBlacklist && this._clusterBlacklist[clusterId] && Date.now() < this._clusterBlacklist[clusterId]) {
          return null;
        }

        try {
          const info = await this.registry.clusters(clusterId);
          const finalized = info && info[3];
          if (finalized) {
            return null;
          }
        } catch {}

        return { members, clusterId };
      } catch (e) {
        console.log('Cluster candidate compute error:', e.message || String(e));
        return null;
      }
    };

    const loop = async () => {
      if (this._monitorLoopRunning) {
        return;
      }
      this._monitorLoopRunning = true;
      
      try {
        if (this._clusterFinalized) {
          return;
        }

        if (this._clusterOrchestrationLock) {
          return;
        }

        // Periodic health snapshot (configurable, default every 5 minutes)
        if (healthIntervalMs > 0 && (!this._lastHealthLogTs || (Date.now() - this._lastHealthLogTs) > healthIntervalMs)) {
          try { this.logClusterHealth(); } catch {}
          this._lastHealthLogTs = Date.now();
        }

        // If we already have an active cluster, track finalization status (with coordinator failover)
        if (this._activeClusterId && this._clusterMembers && this._clusterMembers.length === clusterSize) {
          try {
            const info = await this.registry.clusters(this._activeClusterId);
            const finalized = info && info[3];
            if (finalized) {
              if (!this._clusterFinalized) {
                console.log('✅ Cluster finalized on-chain');
              }
              this._clusterFinalized = true;
            } else {
              // Coordinator failover: if multisig is ready but cluster not finalized, allow secondary coordinator to finalize
              const failoverRaw = process.env.FINALIZE_FAILOVER_MS;
              const failoverParsed = failoverRaw != null ? Number(failoverRaw) : NaN;
              const failoverMs = (Number.isFinite(failoverParsed) && failoverParsed > 0) ? failoverParsed : (15 * 60 * 1000);
              if (!this._clusterFailoverAttempted && this._clusterFinalizationStartAt && this._clusterFinalAddress && failoverMs > 0) {
                const elapsed = Date.now() - this._clusterFinalizationStartAt;
                if (elapsed > failoverMs) {
                  const membersLowerLocal = this._clusterMembers.map(a => a.toLowerCase());
                  const sortedLower = [...membersLowerLocal].sort();
                  const myIndex = sortedLower.indexOf(selfAddr);
                  const failoverIndexRaw = process.env.FAILOVER_COORDINATOR_INDEX;
                  const failoverIndexParsed = failoverIndexRaw != null ? Number(failoverIndexRaw) : NaN;
                  let failoverIndex = (Number.isFinite(failoverIndexParsed) && failoverIndexParsed > 0) ? failoverIndexParsed : 1;
                  
                  if (failoverIndex >= clusterSize) {
                    console.warn(`⚠️  FAILOVER_COORDINATOR_INDEX (${failoverIndex}) >= cluster size (${clusterSize}), using index 1`);
                    failoverIndex = 1;
                  }
                  
                  if (myIndex === failoverIndex) {
                    console.log(`⚠️ Coordinator did not finalize in time; attempting fallback finalizeCluster as coordinator #${failoverIndex}`);
                    try {
                      const clusterInfo = await this.registry.clusters(this._activeClusterId);
                      const alreadyFinalized = clusterInfo && clusterInfo[3];
                      if (alreadyFinalized) {
                        console.log('  ℹ️  Cluster already finalized by another node; skipping failover');
                      } else {
                        console.log(`  → finalizeCluster([${this._clusterMembers.length} members], ${this._clusterFinalAddress})`);
                        if (DRY_RUN) {
                          console.log('  [DRY_RUN] Would send fallback finalizeCluster transaction');
                        } else {
                          const tx = await this.registry.finalizeCluster(this._clusterMembers, this._clusterFinalAddress);
                          await tx.wait();
                          console.log('✓ Cluster finalized on-chain (v3, fallback coordinator)');
                        }
                      }
                    } catch (e2) {
                      console.log('❌ Fallback finalizeCluster() on-chain failed:', e2.message || String(e2));
                    } finally {
                      this._clusterFailoverAttempted = true;
                    }
                  }
                }
              }
            }
            this._clusterStatusErrorCount = 0;
          } catch (e) {
            console.log('Cluster status read error:', e.message || String(e));
            this._clusterStatusErrorCount = (this._clusterStatusErrorCount || 0) + 1;
            if (this._clusterStatusErrorCount > 5) {
              console.log('⚠️ Repeated cluster status errors; resetting active cluster state');
              this._activeClusterId = null;
              this._clusterMembers = null;
              this._clusterStatusErrorCount = 0;
            }
          }
          
          try {
            await this.checkEmergencySweep();
          } catch (e) {
            console.log('[Sweep] Emergency sweep check error:', e.message || String(e));
          }
          
          return;
        }

        // No active cluster yet: attempt to form one
        const candidate = await computeCandidateCluster();

    // Log queue status: registered & eligible vs online (based on staking heartbeat)
    try {
      const clusterSize = Number(process.env.CLUSTER_SIZE || 11);
      const maxScan = Number(process.env.MAX_REGISTERED_SCAN || 256);
      let offset = 0;
      const eligible = [];
      const eligibleSet = new Set();
      while (eligible.length < clusterSize) {
        const page = await this.registry.getRegisteredNodes(offset, maxScan);
        if (!Array.isArray(page) || page.length === 0) break;
        for (const addr of page) {
          if (!addr || addr === ethers.ZeroAddress) continue;
          const addrLower = addr.toLowerCase();
          if (eligibleSet.has(addrLower)) continue;
          try {
            const ok = await this.registry.canParticipate(addr);
            if (ok) {
              eligible.push(addr);
              eligibleSet.add(addrLower);
            }
          } catch {
            // ignore canParticipate errors per-address
          }
        }
        offset += maxScan;
      }

      // On-chain live nodes: eligible (staked/registered) nodes that are also sending
      // recent signed heartbeats over P2P. We intersect the on-chain eligible set with
      // the P2P heartbeat map using a TTL window.
      let onchainOnlineCount = 0;
      if (this.p2p && typeof this.p2p.getHeartbeats === 'function' && eligible.length > 0) {
        try {
          const ttlRaw = process.env.HEARTBEAT_ONLINE_TTL_MS;
          const ttlParsed = ttlRaw != null ? Number(ttlRaw) : NaN;
          const ttlMs = (Number.isFinite(ttlParsed) && ttlParsed > 0) ? ttlParsed : undefined;
          const hbMap = this.p2p.getHeartbeats(ttlMs);
          for (const addr of eligible) {
            if (!addr) continue;
            const rec = hbMap.get(addr.toLowerCase());
            if (rec && rec.timestamp != null) {
              onchainOnlineCount++;
            }
          }
        } catch {
          // if heartbeat inspection fails, fall through and report 0 live on-chain nodes
          onchainOnlineCount = 0;
        }
      }

      if (eligible.length > 0) {
        console.log('Online Members in Queue (on-chain): ' + onchainOnlineCount + '/' + eligible.length);
      } else {
        console.log('Online Members in Queue (on-chain): 0/0');
      }

      // P2P-based online metric: addresses recently seen on P2P queue presence topic (plus self), filtered by registry eligibility
      let p2pOnlineCount = 0;
      if (this.p2p && typeof this.p2p.getQueuePeers === 'function' && eligible.length > 0) {
        const selfAddr = this.wallet.address.toLowerCase();
        const recent = this.p2p.getQueuePeers();
        const addrSet = new Set(recent.map(a => a.toLowerCase()));
        addrSet.add(selfAddr);
        for (const addr of eligible) {
          if (addrSet.has(addr.toLowerCase())) {
            p2pOnlineCount++;
          }
        }
      } else if (eligible.length > 0) {
        // At minimum, count self if we are eligible
        const selfAddr = this.wallet.address.toLowerCase();
        if (eligible.some(a => a.toLowerCase() === selfAddr)) {
          p2pOnlineCount = 1;
        }
      }

      if (eligible.length > 0) {
        console.log('P2P-Online Members in Queue: ' + p2pOnlineCount + '/' + eligible.length);
      } else {
        console.log('P2P-Online Members in Queue: 0/0');
      }
    } catch (e) {
      console.log('Queue status log error:', e.message || String(e));
    }
        if (!candidate) {
          return;
        }

        const { members, clusterId } = candidate;
        const membersLower = members.map(a => a.toLowerCase());
        if (membersLower.length !== clusterSize) {
          console.log(`⚠️ Candidate cluster has ${membersLower.length} members, expected ${clusterSize}; skipping`);
          return;
        }
        if (!membersLower.includes(selfAddr)) {
          // This node is not in the current candidate cluster
          return;
        }

        const sortedMembersLower = [...membersLower].sort();
        const coordinator = sortedMembersLower[0];
        const isCoordinator = (selfAddr === coordinator);
        const myIndex = sortedMembersLower.indexOf(selfAddr);

        console.log('→ New candidate cluster discovered (checking liveness)...');
        console.log(`  ClusterId: ${clusterId}`);
        console.log(`  Members: ${members.length} (myIndex=${myIndex}, coordinator=${coordinator})`);

        const p2pOk = await this.initClusterP2P(clusterId, members);
        if (!p2pOk) {
          console.log('⚠️ P2P init failed for cluster; will retry later');
          return;
        }

        // Liveness ping round: ensure nodes can talk over P2P before binding cluster
        if (!this.p2p || !this.p2p.node) {
          console.log('⚠️ P2P not available for liveness check; skipping candidate cluster');
          return;
        }

        const LIVENESS_ROUND = 9999;
        const liveKeyInitial = `${clusterId}_${LIVENESS_ROUND}`;
        try {
          if (this.p2p.roundData && this.p2p.roundData.has(liveKeyInitial)) {
            this.p2p.roundData.delete(liveKeyInitial);
          }
          if (this.p2p.myData && this.p2p.myData.has(liveKeyInitial)) {
            this.p2p.myData.delete(liveKeyInitial);
          }
        } catch {
          // best-effort cleanup; ignore
        }

        const livenessQuorumRaw = process.env.LIVENESS_QUORUM;
        const livenessQuorumParsed = livenessQuorumRaw != null ? Number(livenessQuorumRaw) : NaN;
        let livenessQuorum = (Number.isFinite(livenessQuorumParsed) && livenessQuorumParsed > 0) ? livenessQuorumParsed : clusterSize;
        
        if (livenessQuorum < clusterSize) {
          console.warn(`⚠️  LIVENESS_QUORUM (${livenessQuorum}) < CLUSTER_SIZE (${clusterSize}). Enforcing full quorum to prevent guaranteed formation failures.`);
          livenessQuorum = clusterSize;
        }
        
        const livenessTimeoutRaw = process.env.LIVENESS_TIMEOUT_MS;
        const livenessTimeoutParsed = livenessTimeoutRaw != null ? Number(livenessTimeoutRaw) : NaN;
        const livenessTimeout = (Number.isFinite(livenessTimeoutParsed) && livenessTimeoutParsed > 0) ? livenessTimeoutParsed : 45000;

        console.log(`  → Pinging candidate cluster nodes for liveness (quorum: ${livenessQuorum}/${clusterSize})...`);
        try {
          await this.p2p.broadcastRoundData(clusterId, LIVENESS_ROUND, 'ping');
          const live = await this.p2p.waitForRoundCompletion(clusterId, LIVENESS_ROUND, members, livenessTimeout);
          
          const liveKeyCheck = `${clusterId}_${LIVENESS_ROUND}`;
          const collected = this.p2p.roundData.get(liveKeyCheck);
          const liveCount = collected ? collected.size : 0;
          
          if (liveCount < livenessQuorum) {
            console.log(`  ❌ Liveness check failed: ${liveCount}/${clusterSize} nodes responded (need ${livenessQuorum}); skipping candidate cluster`);
            return;
          }
          console.log(`  ✓ Liveness check passed for candidate cluster (${liveCount}/${clusterSize} nodes)`);
        } catch (e) {
          console.log('  ⚠️ Liveness ping error:', e.message || String(e));
          return;
        }

        if (this._clusterOrchestrationLock) {
          console.log('⚠️ Cluster orchestration already in progress, skipping');
          return;
        }

        this._clusterOrchestrationLock = true;
        try {
          this._activeClusterId = clusterId;
          this._clusterMembers = members;

          const ok = await this.startClusterMultisigV3(clusterId, members, isCoordinator, clusterThreshold);
          if (!ok) {
            console.log('❌ Cluster multisig flow failed; will retry later');
            this._activeClusterId = null;
            this._clusterMembers = null;
            try {
              if (this.p2p && this.p2p.roundData && this.p2p.roundData.has(liveKeyInitial)) {
                this.p2p.roundData.delete(liveKeyInitial);
              }
            } catch {}
          }
        } finally {
          this._clusterOrchestrationLock = false;
        }
      } catch (e) {
        console.log('Status error:', e.message || String(e));
      } finally {
        this._monitorLoopRunning = false;
      }
    };

    this._monitorTimer = setInterval(loop, 15000);
  }


  async checkEmergencySweep() {
    try {
      const enableSweep = process.env.ENABLE_EMERGENCY_SWEEP !== '0';
      if (!enableSweep) {
        return;
      }
      
      if (!this._activeClusterId || !this._clusterMembers || this._clusterMembers.length === 0) {
        return;
      }
      
      if (this._sweepInProgress) {
        return;
      }
      
      const clusterThresholdRaw = process.env.CLUSTER_THRESHOLD;
      const clusterThresholdParsed = clusterThresholdRaw != null ? Number(clusterThresholdRaw) : NaN;
      const clusterThreshold = (Number.isFinite(clusterThresholdParsed) && clusterThresholdParsed > 0) ? clusterThresholdParsed : 7;
      
      const sweepOfflineMs = Number(process.env.SWEEP_OFFLINE_MS || 172800000);
      const sweepOfflineHours = sweepOfflineMs / 3600000;
      
      let onlineCount = 0;
      let offline48hCount = 0;
      const offlineMembers = [];
      
      for (const member of this._clusterMembers) {
        try {
          const canParticipate = await this.registry.canParticipate(member);
          if (!canParticipate) {
            offline48hCount++;
            offlineMembers.push(member);
            continue;
          }
          
          const info = await this.staking.getNodeInfo(member);
          if (!Array.isArray(info) || info.length < 7) {
            continue;
          }
          
          const active = info[3];
          const hoursOffline = Number(info[6]);
          
          if (!active || hoursOffline >= sweepOfflineHours) {
            offline48hCount++;
            offlineMembers.push(member);
          } else if (active && hoursOffline === 0) {
            onlineCount++;
          }
        } catch (e) {
          console.log(`[Sweep] Error checking member ${member.slice(0, 8)}: ${e.message}`);
        }
      }
      
      const triggerThreshold = clusterThreshold + 1;
      const shouldTrigger = (onlineCount <= triggerThreshold) || (offline48hCount >= 3);
      
      if (!shouldTrigger) {
        return;
      }
      
      console.log(`\n⚠️  EMERGENCY SWEEP CONDITION DETECTED`);
      console.log(`  Online nodes: ${onlineCount}/${this._clusterMembers.length}`);
      console.log(`  Offline 48h+: ${offline48hCount}/${this._clusterMembers.length}`);
      console.log(`  Trigger threshold: ${triggerThreshold} online nodes OR 3+ offline`);
      
      const recoveryAddress = process.env.RECOVERY_SWEEP_ADDRESS;
      if (!recoveryAddress) {
        console.log(`❌ RECOVERY_SWEEP_ADDRESS not configured, cannot perform emergency sweep`);
        return;
      }
      
      console.log(`  → Checking for other live clusters to sweep to...`);
      const otherLiveCluster = await this.findOtherLiveCluster(this._activeClusterId, clusterThreshold);
      
      let destinationAddress;
      let destinationType;
      
      if (otherLiveCluster) {
        destinationAddress = otherLiveCluster.moneroAddress;
        destinationType = 'cluster';
        console.log(`  ✓ Found live cluster ${otherLiveCluster.clusterId.slice(0, 16)}... with ${otherLiveCluster.onlineCount} online nodes`);
        console.log(`  → Will sweep to cluster Monero address: ${destinationAddress.slice(0, 20)}...`);
      } else {
        destinationAddress = recoveryAddress;
        destinationType = 'recovery';
        console.log(`  ℹ️  No other live clusters found`);
        console.log(`  → Will sweep to recovery address: ${destinationAddress.slice(0, 20)}...`);
      }
      
      console.log(`\n[Sweep] Emergency sweep framework ready`);
      console.log(`[Sweep] Destination: ${destinationType} - ${destinationAddress.slice(0, 20)}...`);
      console.log(`[Sweep] Offline members: ${offlineMembers.map(m => m.slice(0, 8)).join(', ')}`);
      console.log(`[Sweep] Note: P2P consensus and multisig signing to be implemented in future iteration`);
      
    } catch (e) {
      console.log(`[Sweep] Emergency sweep check error: ${e.message}`);
    }
  }
  
  async findOtherLiveCluster(currentClusterId, clusterThreshold) {
    try {
      const maxScan = Number(process.env.MAX_REGISTERED_SCAN || 256);
      const registeredNodes = [];
      let offset = 0;
      
      while (registeredNodes.length < 1000) {
        const page = await this.registry.getRegisteredNodes(offset, maxScan);
        if (!Array.isArray(page) || page.length === 0) break;
        
        for (const addr of page) {
          if (addr && addr !== ethers.ZeroAddress) {
            registeredNodes.push(addr);
          }
        }
        
        if (page.length < maxScan) break;
        offset += maxScan;
      }
      
      const eligibleNodes = [];
      for (const addr of registeredNodes) {
        try {
          const canParticipate = await this.registry.canParticipate(addr);
          if (canParticipate) {
            eligibleNodes.push(addr);
          }
        } catch {}
      }
      
      if (eligibleNodes.length < 11) {
        return null;
      }
      
      const clusterCandidates = [];
      const blockNumber = await this.provider.getBlockNumber();
      const rawSpan = process.env.SELECTION_EPOCH_BLOCKS;
      const parsedSpan = rawSpan != null ? Number(rawSpan) : NaN;
      const epochSpan = (Number.isFinite(parsedSpan) && parsedSpan > 0) ? parsedSpan : 20;
      
      for (let epochOffset = 0; epochOffset < 10; epochOffset++) {
        const epoch = (Number(blockNumber) / epochSpan | 0) - epochOffset;
        const epochSeed = ethers.keccak256(ethers.solidityPacked(['uint256'], [epoch]));
        
        const uniqueCandidates = [...new Set(eligibleNodes.map(a => a.toLowerCase()))];
        const scored = uniqueCandidates.map(lower => {
          const score = ethers.keccak256(ethers.solidityPacked(['bytes32','address'], [epochSeed, lower]));
          return { lower, score };
        });
        
        scored.sort((a, b) => a.score.localeCompare(b.score));
        const chosen = scored.slice(0, 11);
        const membersLower = chosen.map(x => x.lower);
        const members = membersLower.map(addr => ethers.getAddress(addr));
        const sortedMembersLower = [...membersLower].sort();
        const addressTypes = Array(11).fill('address');
        const clusterId = ethers.keccak256(ethers.solidityPacked(addressTypes, sortedMembersLower));
        
        if (clusterId === currentClusterId) {
          continue;
        }
        
        try {
          const clusterInfo = await this.registry.clusters(clusterId);
          const finalized = clusterInfo && clusterInfo[3];
          if (!finalized) {
            continue;
          }
          
          const moneroAddress = clusterInfo[1];
          if (!moneroAddress || moneroAddress.length < 20) {
            continue;
          }
          
          let onlineCount = 0;
          for (const member of members) {
            try {
              const info = await this.staking.getNodeInfo(member);
              if (Array.isArray(info) && info.length >= 7) {
                const active = info[3];
                const hoursOffline = Number(info[6]);
                if (active && hoursOffline === 0) {
                  onlineCount++;
                }
              }
            } catch {}
          }
          
          if (onlineCount >= (clusterThreshold + 1)) {
            clusterCandidates.push({
              clusterId,
              moneroAddress,
              onlineCount,
              createdAt: clusterInfo[2],
              members
            });
          }
        } catch {}
      }
      
      if (clusterCandidates.length === 0) {
        return null;
      }
      
      clusterCandidates.sort((a, b) => Number(b.createdAt) - Number(a.createdAt));
      return clusterCandidates[0];
      
    } catch (e) {
      console.log(`[Sweep] Error finding other live clusters: ${e.message}`);
      return null;
    }
  }

  logClusterHealth() {
    try {
      console.log('[health] Cluster state snapshot:');
      console.log(`  Active cluster: ${this._activeClusterId || 'none'}`);
      console.log(`  Active members: ${this._clusterMembers ? this._clusterMembers.length : 0}`);
      console.log(`  Finalized: ${this._clusterFinalized ? 'yes' : 'no'}`);

      const failCount = Object.fromEntries(this._clusterFailures || new Map());
      const failMeta = this._clusterFailMeta || {};
      const blacklist = this._clusterBlacklist || {};
      const now = Date.now();

      const failEntries = Object.entries(failCount);
      if (!failEntries.length) {
        console.log('  Failures: none');
      } else {
        console.log('  Failures:');
        for (const [cid, count] of failEntries) {
          const meta = failMeta[cid] || {};
          const reachable = meta.reachable != null ? meta.reachable : 'unknown';
          const reason = meta.reason || 'unknown';
          console.log(`    ${cid}: ${count} failures (reachable=${reachable}, reason=${reason})`);
        }
      }

      const blEntries = Object.entries(blacklist);
      if (!blEntries.length) {
        console.log('  Blacklist: empty');
      } else {
        console.log('  Blacklist:');
        for (const [cid, until] of blEntries) {
          const remainingMs = until - now;
          const remainingMin = remainingMs > 0 ? Math.round(remainingMs / 60000) : 0;
          console.log(`    ${cid}: ${remainingMin}m remaining`);
        }
      }
    } catch {
      // logging should never throw
    }
  }

  async performKeyRefresh(clusterId, failedNodes, newNodes) {
    try {
      console.log(`\n🔄 Key refresh for ${clusterId}`);
      const cluster = await this.registry.clusters(clusterId);
      const allNodes = (cluster && (cluster.members || cluster[0])) || [];
      const activeNodes = allNodes.filter(n => !failedNodes.map(f => f.toLowerCase()).includes(n.toLowerCase()));
      if (activeNodes.length < 8) {
        console.log(`❌ Insufficient active nodes: ${activeNodes.length} < 8`);
        return false;
      }
      
      if (!this.sst) {
        console.log(`✓ Would refresh with ${activeNodes.length} nodes (SST disabled)`);
        return true;
      }
      
      console.log(`→ SST key reconstruction for ${failedNodes.length} failed nodes`);
      
      for (const failedNode of failedNodes) {
        const failedAddr = failedNode.toLowerCase();
        console.log(`  → Reconstructing key for ${failedAddr.slice(0, 8)}...`);
        
        const shares = [];
        for (const activeNode of activeNodes) {
          const activeAddr = activeNode.toLowerCase();
          if (activeAddr === this.wallet.address.toLowerCase()) {
            const storedShares = await this.sst.loadSharesForOwner(clusterId, failedAddr);
            for (const storedShare of storedShares) {
              try {
                const decrypted = this.sst.decryptForSelf(
                  storedShare,
                  this.wallet.privateKey
                );
                shares.push(decrypted);
                console.log('  ✓ Loaded share from local storage');
              } catch (e) {
                console.log('  ⚠️  Failed to decrypt local share:', e.message);
              }
            }
          }
        }
        
        if (shares.length < this.sst.threshold) {
          console.log(`  ❌ Insufficient shares: ${shares.length} < ${this.sst.threshold}`);
          continue;
        }
        
        console.log(`  → Combining ${shares.length} shares...`);
        const reconstructedKey = this.sst.combineShares(shares);
        
        if (!newNodes || newNodes.length === 0) {
          console.log('  ✓ Key reconstructed (no new nodes to transfer to)');
          continue;
        }
        
        for (const newNode of newNodes) {
          const newAddr = newNode.toLowerCase();
          console.log(`  → Transferring key to new node ${newAddr.slice(0, 8)}...`);
          
          const identities = this.p2p.getSSTIdentities(clusterId);
          const newNodeIdentity = identities.get(newAddr);
          
          if (!newNodeIdentity) {
            console.log('  ⚠️  No identity found for new node, cannot transfer');
            continue;
          }
          
          try {
            const encryptedKey = this.sst.encryptForRecipient(
              reconstructedKey,
              newNodeIdentity.publicKey
            );
            
            const timestamp = Date.now();
            const nonce = '0x' + crypto.randomBytes(16).toString('hex');
            
            const transferMessage = {
              type: 'sst/key-transfer',
              clusterId,
              fromAddress: failedAddr,
              toAddress: newAddr,
              encryptedKey,
              timestamp,
              nonce
            };
            
            const message = `${transferMessage.type}:${clusterId}:${failedAddr}:${newAddr}:${nonce}:${timestamp}`;
            const digest = ethers.id(message);
            const signingKey = new ethers.SigningKey(this.wallet.privateKey);
            const signature = signingKey.sign(digest).serialized;
            
            transferMessage.signature = signature;
            
            await this.p2p.broadcastSSTMessage(clusterId, transferMessage);
            console.log(`  ✓ Key transfer broadcast to ${newAddr.slice(0, 8)}`);
          } catch (e) {
            console.log('  ⚠️  Key transfer failed:', e.message);
          }
        }
      }
      
      console.log('✓ Key refresh complete');
      return true;
    } catch (e) {
      console.log('Key refresh error:', e.message);
      return false;
    }
  }

}

const isMainModule = import.meta.url === `file://${process.argv[1]}`;

if (isMainModule) {
  const node = new ZNode();

  const shutdown = async (signal) => {
    console.log(`\n[signal] ${signal} received, shutting down...`);
    try {
      await node.stop();
    } catch (e) {
      console.error('Shutdown error:', e.message || String(e));
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));

  node.start().catch(error => {
    console.error('\n❌ Fatal error:', error.message);
    process.exit(1);
  });
}

export default ZNode;
