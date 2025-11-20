import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { ethers } from 'ethers';
import P2PLibp2p from './p2p-libp2p.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from the same directory as node.js
const dotenvResult = dotenv.config({ path: __dirname + '/.env' });
if (dotenvResult.error) {
  console.error('❌ Failed to load .env file for heartbeat oracle:', dotenvResult.error.message);
  console.error('Ensure .env exists next to node.js. Run ./setup.sh in the node repo if needed.');
  process.exit(1);
}

const TEST_MODE = process.env.TEST_MODE === '1';
const DRY_RUN = TEST_MODE ? (process.env.DRY_RUN !== '0') : (process.env.DRY_RUN === '1');

if (TEST_MODE) {
  console.warn('⚠️  HEARTBEAT ORACLE: TEST_MODE is ENABLED. Do not use this configuration in production.');
}
if (DRY_RUN) {
  console.log('ℹ️  HEARTBEAT ORACLE: DRY_RUN mode enabled; on-chain transactions will not be sent.');
}

let EFFECTIVE_RPC_URL;
if (process.env.RPC_URL || process.env.ETH_RPC_URL) {
  EFFECTIVE_RPC_URL = process.env.RPC_URL || process.env.ETH_RPC_URL;
} else if (TEST_MODE) {
  EFFECTIVE_RPC_URL = 'https://eth-sepolia.g.alchemy.com/v2/demo';
  console.warn('⚠️  HEARTBEAT ORACLE: TEST_MODE using demo Sepolia RPC URL (rate-limited, for testing only)');
} else {
  console.error('ERROR (HEARTBEAT ORACLE): RPC_URL or ETH_RPC_URL is required.');
  console.error('Set RPC_URL=<your-rpc-url> or enable TEST_MODE=1 for testing.');
  process.exit(1);
}

const ORACLE_PRIVATE_KEY = process.env.HEARTBEAT_ORACLE_PRIVATE_KEY || process.env.PRIVATE_KEY;
if (!ORACLE_PRIVATE_KEY) {
  console.error('ERROR (HEARTBEAT ORACLE): HEARTBEAT_ORACLE_PRIVATE_KEY or PRIVATE_KEY is required.');
  process.exit(1);
}

// Minimal staking ABI used by the oracle
const stakingABI = [
  'function getActiveNodes() external view returns (address[] memory)',
  'function getNodeInfo(address _node) external view returns (uint256 stakedAmount,uint256 stakeTime,uint256 lastHeartbeat,bool active,uint256 nodeVersion,uint256 slashingStage,uint256 hoursOffline)',
  'function recordP2PHeartbeat(address _node) external',
  'function slashForDowntimeProgressive(address _node) external',
  'function checkSlashingStatus(address _node) external view returns (bool needsSlash, uint256 stage, uint256 hoursOffline)',
  'function isBlacklisted(address _node) external view returns (bool)',
  'function heartbeatOracle() external view returns (address)',
  'function owner() external view returns (address)'
];

const KNOWN_DEFAULTS = {
  11155111: {
    STAKING_ADDR: '0x14b00D03EcB5C3cca59e6feCf2Df593aBc6346cd'
  }
};

const OFFLINE_SINCE = new Map(); // addressLower -> firstSeenOfflineMs

const POLL_INTERVAL_MS = Number(process.env.ORACLE_POLL_INTERVAL_MS || 10 * 60 * 1000); // 10 minutes
const ONLINE_TTL_MS = Number(process.env.ORACLE_ONLINE_TTL_MS || 30 * 60 * 1000); // 30 minutes
const OFFLINE_CONFIRM_MS = Number(process.env.ORACLE_OFFLINE_CONFIRM_MS || 6 * 60 * 60 * 1000); // 6 hours
const MIN_HEARTBEAT_PUSH_SEC = Number(process.env.ORACLE_MIN_HEARTBEAT_PUSH_SEC || 3600); // 1 hour
const DOWNTIME_MARGIN_HOURS = BigInt(Number(process.env.ORACLE_DOWNTIME_MARGIN_HOURS || 2)); // extra safety margin

const MAX_HEARTBEAT_TX_PER_TICK = Number(process.env.ORACLE_MAX_HEARTBEAT_TX_PER_TICK || 20);
const MAX_SLASH_TX_PER_TICK = Number(process.env.ORACLE_MAX_SLASH_TX_PER_TICK || 5);

const STAGE_THRESHOLDS = {
  1: 48n,
  2: 72n,
  3: 96n
};

async function createContext() {
  const provider = new ethers.JsonRpcProvider(EFFECTIVE_RPC_URL);
  const network = await provider.getNetwork();
  const chainIdBig = network.chainId;
  const chainId = Number(chainIdBig);

  if (!Number.isFinite(chainId)) {
    console.error('ERROR (HEARTBEAT ORACLE): Invalid chainId from provider:', String(chainIdBig));
    process.exit(1);
  }

  const envChainId = process.env.CHAIN_ID ? Number(process.env.CHAIN_ID) : null;
  if (envChainId != null && Number.isFinite(envChainId) && envChainId !== chainId) {
    console.error(`ERROR (HEARTBEAT ORACLE): CHAIN_ID mismatch: env=${envChainId}, provider=${chainId}.`);
    process.exit(1);
  }

  process.env.CHAIN_ID = String(chainId);

  const wallet = new ethers.Wallet(ORACLE_PRIVATE_KEY, provider);
  console.log('HEARTBEAT ORACLE address:', wallet.address);
  console.log('HEARTBEAT ORACLE chainId:', chainId);

  let stakingAddr = process.env.STAKING_ADDR;
  if (!stakingAddr) {
    const defaults = KNOWN_DEFAULTS[chainId];
    if (!defaults || !defaults.STAKING_ADDR) {
      console.error(`ERROR (HEARTBEAT ORACLE): No default STAKING_ADDR known for chainId ${chainId}. Set STAKING_ADDR in environment.`);
      process.exit(1);
    }
    stakingAddr = defaults.STAKING_ADDR;
  }

  const staking = new ethers.Contract(stakingAddr, stakingABI, wallet);

  // Ensure this wallet is authorized as heartbeatOracle or owner
  let oracleAddr = '0x0000000000000000000000000000000000000000';
  let ownerAddr = '0x0000000000000000000000000000000000000000';
  try {
    oracleAddr = await staking.heartbeatOracle();
  } catch (e) {
    console.warn('⚠️  HEARTBEAT ORACLE: Could not read heartbeatOracle():', e.message || String(e));
  }
  try {
    ownerAddr = await staking.owner();
  } catch (e) {
    console.warn('⚠️  HEARTBEAT ORACLE: Could not read owner():', e.message || String(e));
  }

  const wa = wallet.address.toLowerCase();
  const isOracle = oracleAddr && oracleAddr.toLowerCase && oracleAddr.toLowerCase() === wa;
  const isOwner = ownerAddr && ownerAddr.toLowerCase && ownerAddr.toLowerCase() === wa;

  if (!isOracle && !isOwner) {
    console.error('ERROR (HEARTBEAT ORACLE): Wallet is neither heartbeatOracle nor owner for staking contract.');
    console.error('  heartbeatOracle:', oracleAddr);
    console.error('  owner          :', ownerAddr);
    process.exit(1);
  }

  const p2pPort = Number(process.env.ORACLE_P2P_PORT || process.env.P2P_PORT || 0);
  const p2p = new P2PLibp2p(wallet.address, wallet.privateKey, process.env.PUBLIC_IP);

  console.log('HEARTBEAT ORACLE: starting P2P node...');
  await p2p.start(p2pPort);

  // Subscribe to /znode/heartbeat by sending a single heartbeat once
  try {
    await p2p.broadcastHeartbeat();
    console.log('HEARTBEAT ORACLE: Sent initial P2P heartbeat and subscribed to /znode/heartbeat');
  } catch (e) {
    console.warn('⚠️  HEARTBEAT ORACLE: Failed to send initial P2P heartbeat:', e.message || String(e));
  }

  console.log('HEARTBEAT ORACLE configuration:');
  console.log('  Staking contract :', stakingAddr);
  console.log('  Poll interval    :', POLL_INTERVAL_MS, 'ms');
  console.log('  Online TTL       :', ONLINE_TTL_MS, 'ms');
  console.log('  Offline confirm  :', OFFLINE_CONFIRM_MS, 'ms');
  console.log('  Min HB push age  :', MIN_HEARTBEAT_PUSH_SEC, 'sec');
  console.log('  Downtime margin  :', DOWNTIME_MARGIN_HOURS.toString(), 'hours');
  console.log('  Max HB tx / tick :', MAX_HEARTBEAT_TX_PER_TICK);
  console.log('  Max slash / tick :', MAX_SLASH_TX_PER_TICK);

  return { provider, wallet, staking, p2p };
}

async function oracleTick(staking, p2p) {
  const nowMs = Date.now();
  let heartbeatTxCount = 0;
  let slashTxCount = 0;

  let activeNodes;
  try {
    activeNodes = await staking.getActiveNodes();
  } catch (e) {
    console.error('HEARTBEAT ORACLE: Failed to read active nodes:', e.message || String(e));
    return;
  }

  if (!Array.isArray(activeNodes)) {
    console.warn('HEARTBEAT ORACLE: getActiveNodes() returned non-array, skipping tick');
    return;
  }

  console.log(`HEARTBEAT ORACLE: Tick at ${new Date(nowMs).toISOString()} - active nodes: ${activeNodes.length}`);

  for (const node of activeNodes) {
    if (!node) continue;

    const nodeAddr = node.toString();
    const nodeLower = nodeAddr.toLowerCase();

    try {
      // Skip heavy work if rate limits are already hit
      if (heartbeatTxCount >= MAX_HEARTBEAT_TX_PER_TICK && slashTxCount >= MAX_SLASH_TX_PER_TICK) {
        break;
      }

      // Skip if node is already blacklisted
      let blacklisted = false;
      try {
        blacklisted = await staking.isBlacklisted(nodeAddr);
      } catch (e) {
        console.warn('HEARTBEAT ORACLE: Could not read isBlacklisted for', nodeLower.slice(0, 8), '-', e.message || String(e));
      }
      if (blacklisted) {
        OFFLINE_SINCE.delete(nodeLower);
        continue;
      }

      let stakedAmount = 0n;
      let lastHeartbeat = 0n;
      let active = false;
      let slashingStage = 0n;
      let hoursOfflineOnChain = 0n;

      try {
        const info = await staking.getNodeInfo(nodeAddr);
        if (Array.isArray(info) && info.length >= 7) {
          stakedAmount = info[0];
          lastHeartbeat = info[2];
          active = !!info[3];
          slashingStage = info[5];
          hoursOfflineOnChain = info[6];
        } else {
          console.warn('HEARTBEAT ORACLE: Unexpected getNodeInfo format for', nodeLower.slice(0, 8));
        }
      } catch (e) {
        console.warn('HEARTBEAT ORACLE: getNodeInfo failed for', nodeLower.slice(0, 8), '-', e.message || String(e));
        continue;
      }

      if (!active || stakedAmount === 0n) {
        OFFLINE_SINCE.delete(nodeLower);
        continue;
      }

      const lastP2P = p2p.getLastHeartbeat(nodeAddr);

      if (typeof lastP2P === 'number' && Number.isFinite(lastP2P)) {
        const ageMs = nowMs - lastP2P;
        if (ageMs <= ONLINE_TTL_MS) {
          // Node is considered online by P2P
          OFFLINE_SINCE.delete(nodeLower);

          const onChainAgeSec = Math.max(0, Math.floor(nowMs / 1000 - Number(lastHeartbeat || 0n)));

          if (onChainAgeSec >= MIN_HEARTBEAT_PUSH_SEC && heartbeatTxCount < MAX_HEARTBEAT_TX_PER_TICK) {
            const msgPrefix = `HEARTBEAT ORACLE: recordP2PHeartbeat(${nodeLower.slice(0, 8)})`;
            console.log(`${msgPrefix} - on-chain heartbeat age ~${onChainAgeSec}s, hoursOffline=${hoursOfflineOnChain.toString()}`);

            if (DRY_RUN) {
              console.log('  [DRY_RUN] Would send recordP2PHeartbeat transaction');
            } else {
              try {
                const tx = await staking.recordP2PHeartbeat(nodeAddr);
                console.log('  → Tx hash:', tx.hash);
                await tx.wait();
                console.log('  ✓ recordP2PHeartbeat confirmed');
              } catch (e) {
                console.warn('  ⚠️  recordP2PHeartbeat failed:', e.message || String(e));
              }
            }

            heartbeatTxCount++;
          }

          // No downtime processing when we have fresh P2P evidence
          continue;
        }
      }

      // No recent P2P heartbeat -> candidate offline path
      let firstSeen = OFFLINE_SINCE.get(nodeLower);
      if (!firstSeen) {
        OFFLINE_SINCE.set(nodeLower, nowMs);
        console.log('HEARTBEAT ORACLE: Marking node as potentially offline:', nodeLower.slice(0, 8));
        continue;
      }

      const offlineForMs = nowMs - firstSeen;
      if (offlineForMs < OFFLINE_CONFIRM_MS) {
        // Still in grace period before we even consider slashing
        continue;
      }

      if (slashTxCount >= MAX_SLASH_TX_PER_TICK) {
        continue;
      }

      // Re-check on-chain status using contract's own helper
      let needsSlash = false;
      let pendingStage = 0n;
      let hoursOffline = 0n;

      try {
        const res = await staking.checkSlashingStatus(nodeAddr);
        if (Array.isArray(res) && res.length >= 3) {
          needsSlash = !!res[0];
          pendingStage = res[1];
          hoursOffline = res[2];
        } else {
          console.warn('HEARTBEAT ORACLE: Unexpected checkSlashingStatus format for', nodeLower.slice(0, 8));
          continue;
        }
      } catch (e) {
        console.warn('HEARTBEAT ORACLE: checkSlashingStatus failed for', nodeLower.slice(0, 8), '-', e.message || String(e));
        continue;
      }

      if (!needsSlash) {
        continue;
      }

      const stageNum = Number(pendingStage);
      const baseThreshold = STAGE_THRESHOLDS[stageNum] || 48n;
      const minHours = baseThreshold + DOWNTIME_MARGIN_HOURS;

      if (hoursOffline < minHours) {
        // Extra safety margin not yet reached
        continue;
      }

      const offlineHoursApprox = Math.round(offlineForMs / (60 * 60 * 1000));
      console.log(`HEARTBEAT ORACLE: Downtime slashing candidate ${nodeLower.slice(0, 8)} - stage=${stageNum}, hoursOffline=${hoursOffline.toString()}, offlineFor≈${offlineHoursApprox}h`);

      if (DRY_RUN) {
        console.log('  [DRY_RUN] Would call slashForDowntimeProgressive');
      } else {
        try {
          const tx = await staking.slashForDowntimeProgressive(nodeAddr);
          console.log('  → Tx hash:', tx.hash);
          await tx.wait();
          console.log('  ✓ slashForDowntimeProgressive confirmed');
        } catch (e) {
          console.warn('  ⚠️  slashForDowntimeProgressive failed:', e.message || String(e));
        }
      }

      slashTxCount++;
    } catch (e) {
      console.warn('HEARTBEAT ORACLE: Error while processing node', nodeLower.slice(0, 8), '-', e.message || String(e));
    }
  }
}

async function main() {
  const { staking, p2p } = await createContext();

  const tick = async () => {
    try {
      await oracleTick(staking, p2p);
    } catch (e) {
      console.error('HEARTBEAT ORACLE: Tick error:', e.message || String(e));
    }
  };

  await tick();
  const interval = setInterval(tick, POLL_INTERVAL_MS);

  const shutdown = async (signal) => {
    console.log(`\nHEARTBEAT ORACLE: ${signal} received, shutting down...`);
    clearInterval(interval);
    try {
      if (p2p && typeof p2p.stop === 'function') {
        await p2p.stop();
      }
    } catch (e) {
      console.error('HEARTBEAT ORACLE: Error during shutdown:', e.message || String(e));
    } finally {
      process.exit(0);
    }
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((e) => {
    console.error('HEARTBEAT ORACLE: Fatal error:', e.message || String(e));
    process.exit(1);
  });
}

export default main;
