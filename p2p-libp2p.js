/**
 * LibP2P-based P2P Exchange for Node
 * Uses libp2p with Noise for authenticated encryption, GossipSub for pubsub, and Kad-DHT for discovery
 */

import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { mplex } from '@libp2p/mplex';
import { gossipsub } from '@libp2p/gossipsub';
import { kadDHT } from '@libp2p/kad-dht';
import { ping } from '@libp2p/ping';
import { bootstrap } from '@libp2p/bootstrap';
import { mdns } from '@libp2p/mdns';
import { identify } from '@libp2p/identify';
import { multiaddr } from '@multiformats/multiaddr';
import { ethers } from 'ethers';
import { createEd25519PeerId } from '@libp2p/peer-id-factory';
import crypto from 'crypto';
import elliptic from 'elliptic';
import fs from 'fs';
import os from 'os';
import path from 'path';

const ec = new elliptic.ec('secp256k1');

class LibP2PExchange {
  constructor(ethereumAddress, ethereumPrivateKey, publicIP) {
    this.ethereumAddress = ethereumAddress.toLowerCase();
    this.ethereumPrivateKey = ethereumPrivateKey;
    this.publicIP = publicIP;
    this.node = null;
    this.port = 0;
    this.roundData = new Map();
    this.myData = new Map();
    this.roundTimestamps = new Map();
    this.seenMessages = new Map();
    this.subscriptions = new Map();
    this.clusterMembers = new Map();
    this.sstIdentities = new Map();
    this.sstShares = new Map();
    this.sstHandlers = new Map();
    this.messageRateLimits = new Map();
    this.peerPublicKeys = new Map();
    this.peerIdBindings = new Map();
    this.queuePresence = new Map();
    this.queuePresenceInterval = null;
    this.sweepProposals = new Map();
    this.sweepAcks = new Map();
    this.sweepTxData = new Map();
    this.heartbeats = new Map();
    this.totalPayloadSize = 0;
    const defaultPeerStore = path.join(os.homedir(), '.znode', 'p2p-peers.json');
    this.peerStorePath = process.env.P2P_PEER_STORE || defaultPeerStore;
    this.outboundMessageCount = 0;
    this.outboundMessageWindow = Date.now();
    
    const payloadSizeKB = Number(process.env.P2P_MAX_PAYLOAD_KB || 512);
    this.MAX_PAYLOAD_SIZE = payloadSizeKB * 1024;
    console.log(`[P2P] MAX_PAYLOAD_SIZE: ${this.MAX_PAYLOAD_SIZE} bytes (${payloadSizeKB}KB)`);
    
    this.MAX_TOTAL_MEMORY = 16 * 1024 * 1024;
    this.MAX_OUTBOUND_RATE = 100;
    this.OUTBOUND_RATE_WINDOW = 60000;
    this.MAX_RATE_LIMIT_ENTRIES = 1000;
    this.MAX_SEEN_MESSAGES = 10000;
    
    console.warn('[P2P] Security Notice: Ethereum private key is used for P2P ECDH encryption. Memory exposure compromises Ethereum account.');
  }

  async start(port = 0) {
    const peerId = await this.generatePeerId();
    
    if (!process.env.CHAIN_ID) {
      throw new Error('[P2P] CHAIN_ID must be set for signature verification');
    }
    const chainId = Number(process.env.CHAIN_ID);
    if (!Number.isFinite(chainId) || chainId <= 0) {
      throw new Error(`[P2P] Invalid CHAIN_ID: ${process.env.CHAIN_ID}`);
    }
    console.log(`[P2P] Using CHAIN_ID: ${chainId}`);
    
    this.cleanupInterval = setInterval(() => {
      this.cleanupOldMessages();
    }, 60000);
    
    const rawBootstrapPeers = this.getBootstrapPeers();
    const bootstrapPeers = [];
    for (const addr of rawBootstrapPeers) {
      try {
        const ma = multiaddr(addr);
        bootstrapPeers.push(ma);
      } catch (e) {
        console.log('[P2P] Invalid bootstrap multiaddr, skipping:', addr, '-', e.message || String(e));
      }
    }

    const libp2pConfig = {
      peerId,
      addresses: {
        listen: [
          `/ip4/0.0.0.0/tcp/${port || 0}`
        ]
      },
      transports: [tcp()],
      streamMuxers: [mplex()],
      connectionEncryption: [noise()],
      services: {
        ping: ping(),
        identify: identify(),
        pubsub: gossipsub({
          emitSelf: false,
          canRelayMessage: true,
          allowPublishToZeroTopicPeers: true,
          msgIdFn: (msg) => {
            return crypto.createHash('sha256').update(msg.data).digest();
          }
        }),
        dht: kadDHT({
          clientMode: false
        })
      }
    };
    
    if (this.publicIP && port > 0) {
      libp2pConfig.addresses.announce = [
        `/ip4/${this.publicIP}/tcp/${port}`
      ];
    }

    if (bootstrapPeers.length > 0) {
      libp2pConfig.peerDiscovery = [
        bootstrap({ list: bootstrapPeers }),
        mdns()
      ];
    } else {
      libp2pConfig.peerDiscovery = [mdns()];
      console.log('[P2P] No bootstrap peers configured, using mDNS only (local discovery)');
    }

    if (typeof Promise.withResolvers !== 'function') {
      Promise.withResolvers = () => {
        let resolve;
        let reject;
        const promise = new Promise((res, rej) => {
          resolve = res;
          reject = rej;
        });
        return { promise, resolve, reject };
      };
    }

    this.node = await createLibp2p(libp2pConfig);
    
    await this.node.start();

    // Proactively dial configured bootstrap peers to ensure connectivity
    // NOTE: This manual dial block is disabled; libp2p's bootstrap({ list })
    // already handles connecting to configured peers. Leaving it commented
    // out avoids double-dial and version-specific multiaddr issues.
    // if (bootstrapPeers.length > 0) {
    //   for (const addr of bootstrapPeers) {
    //     try {
    //       const ma = multiaddr(addr);
    //       await this.node.dial(ma);
    //       console.log(`[P2P] Dialed bootstrap peer ${addr}`);
    //     } catch (e) {
    //       console.log('[P2P] Failed to dial bootstrap peer', addr, '-', e.message || String(e));
    //     }
    //   }
    // }

    // Optional one-shot force dial via P2P_FORCE_DIAL (used for debugging/bringup)
    if (process.env.P2P_FORCE_DIAL) {
      const addr = process.env.P2P_FORCE_DIAL;
      try {
        const ma = multiaddr(addr);
        await this.node.dial(ma);
        console.log(`[P2P] Force-dialed peer ${addr}`);
      } catch (e) {
        console.log('[P2P] Failed to force-dial peer', addr, '-', e.message || String(e));
      }
    }

    // Track connected peers to build a local bootstrap cache
    this.node.addEventListener('peer:connect', (evt) => {
      try {
        const conn = evt.detail;
        const peerIdStr = conn.remotePeer && conn.remotePeer.toString ? conn.remotePeer.toString() : undefined;
        const addrStr = conn.remoteAddr && conn.remoteAddr.toString ? conn.remoteAddr.toString() : undefined;
        if (!peerIdStr || !addrStr) return;
        if (!addrStr.includes('/ip4/') || !addrStr.includes('/tcp/')) return;
        this.recordPeerEndpoint(addrStr, peerIdStr);
        console.log(`[P2P] Peer connected: ${peerIdStr.substring(0, 20)}... from ${addrStr}`);
      } catch (err) {
        console.log('[P2P] Warning: failed to record peer endpoint:', err.message);
      }
    });

    const addrs = this.node.getMultiaddrs();
    if (addrs.length > 0) {
      for (const addr of addrs) {
        const addrStr = addr.toString();
        if (addrStr.includes('/tcp/')) {
          this.port = this.extractPort(addrStr);
          if (this.port > 0) break;
        }
      }
      console.log(`[P2P] LibP2P node started on port ${this.port}`);
      console.log(`[P2P] Peer ID: ${this.node.peerId.toString()}`);
      
      if (this.publicIP && this.port > 0) {
        console.log(`[P2P] Public endpoint: ${this.publicIP}:${this.port}`);
      }
    }

    this.node.services.pubsub.addEventListener('message', (evt) => {
      this.handleMessage(evt.detail);
    });

    return;
  }

  async generatePeerId() {
    const keyPath = process.env.P2P_PEER_KEY_FILE || './p2p-peer-id.json';
    const backupPath = '/root/.znode-backup/p2p-peer-id.json';
    const { generateKeyPair, privateKeyToProtobuf, privateKeyFromProtobuf } = await import('@libp2p/crypto/keys');
    const { peerIdFromPrivateKey } = await import('@libp2p/peer-id');

    const loadFromDisk = async () => {
      const fs = await import('fs/promises');
      let data;
      // Try primary key path first
      try {
        data = await fs.readFile(keyPath, 'utf8');
      } catch {
        // Fallback to backup location
        try {
          data = await fs.readFile(backupPath, 'utf8');
          await fs.writeFile(keyPath, data, { mode: 0o600 });
          console.log('[P2P] Restored P2P key from backup');
        } catch {
          throw new Error('No P2P key file found');
        }
      }

      const base64 = data.trim();
      if (!base64) {
        throw new Error('Empty P2P key file');
      }

      let buf;
      try {
        buf = Buffer.from(base64, 'base64');
      } catch (e) {
        throw new Error('Invalid base64 in P2P key file');
      }

      try {
        const privateKey = privateKeyFromProtobuf(buf);
        return await peerIdFromPrivateKey(privateKey);
      } catch (e) {
        throw new Error('Invalid P2P key protobuf: ' + (e.message || String(e)));
      }
    };

    try {
      return await loadFromDisk();
    } catch (err) {
      console.log('[P2P] Failed to load P2P key: ' + (err.message || String(err)) + ', generating new one');
      const privateKey = await generateKeyPair('Ed25519');
      try {
        const fs = await import('fs/promises');
        const proto = privateKeyToProtobuf(privateKey);
        const base64 = Buffer.from(proto).toString('base64');
        await fs.writeFile(keyPath, base64, { mode: 0o600 });
        try {
          await fs.mkdir('/root/.znode-backup', { recursive: true, mode: 0o700 });
          await fs.writeFile(backupPath, base64, { mode: 0o600 });
        } catch (err) {
          console.log('[P2P] Warning: could not backup P2P key to /root/.znode-backup:', err.message || String(err));
        }
        console.log('[P2P] Generated and saved new P2P key to ' + keyPath);
      } catch (writeErr) {
        console.log('[P2P] Warning: could not save P2P key: ' + (writeErr.message || String(writeErr)));
      }
      return await peerIdFromPrivateKey(privateKey);
    }
  }

  loadPeerStore() {
    try {
      if (!fs.existsSync(this.peerStorePath)) {
        return { peers: [] };
      }
      const raw = fs.readFileSync(this.peerStorePath, 'utf8');
      const data = JSON.parse(raw);
      
      if (!data || typeof data !== 'object') {
        console.log('[P2P] Invalid peer store format: not an object');
        return { peers: [] };
      }
      
      if (!Array.isArray(data.peers)) {
        console.log('[P2P] Invalid peer store format: peers is not an array');
        return { peers: [] };
      }
      
      const validPeers = data.peers.filter(entry => {
        if (!entry || typeof entry !== 'object') return false;
        if (typeof entry.addr !== 'string' || !entry.addr) return false;
        if (!entry.addr.startsWith('/ip4/') && !entry.addr.startsWith('/ip6/') && !entry.addr.startsWith('/dns4/') && !entry.addr.startsWith('/dns6/')) return false;
        if (typeof entry.lastSeen !== 'number' || entry.lastSeen < 0) return false;
        return true;
      });
      
      return { peers: validPeers };
    } catch (err) {
      console.log('[P2P] Error loading peer store:', err.message);
      return { peers: [] };
    }
  }

  recordPeerEndpoint(addr, peerId) {
    (async () => {
      try {
        const dir = path.dirname(this.peerStorePath);
        const fsp = await import('fs/promises');
        try {
          await fsp.mkdir(dir, { recursive: true, mode: 0o700 });
        } catch (e) {
        }
        
        const data = this.loadPeerStore();
        const now = Date.now();
        const peers = Array.isArray(data.peers) ? data.peers : [];
        const filtered = peers.filter(p => p.addr !== addr && p.peerId !== peerId);
        filtered.unshift({ addr, peerId, lastSeen: now });
        const limited = filtered.slice(0, Number(process.env.P2P_MAX_PEERS || 32));
        const out = { peers: limited };
        
        const tmpPath = this.peerStorePath + '.tmp';
        await fsp.writeFile(tmpPath, JSON.stringify(out, null, 2), { mode: 0o600 });
        await fsp.rename(tmpPath, this.peerStorePath);
      } catch (err) {
        console.log('[P2P] Warning: could not save peer store:', err.message);
      }
    })();
  }

  getBootstrapPeers() {
    const peers = [];

    if (process.env.P2P_BOOTSTRAP_PEERS) {
      peers.push(...process.env.P2P_BOOTSTRAP_PEERS
        .split(',')
        .map(p => p.trim())
        .filter(Boolean));
    }

    // Load recent peers from local peer store (best-effort)
    try {
      if (fs.existsSync(this.peerStorePath)) {
        const raw = fs.readFileSync(this.peerStorePath, 'utf8');
        const data = JSON.parse(raw);
        const now = Date.now();
        for (const entry of (data.peers || [])) {
          if (!entry || typeof entry.addr !== 'string') continue;
          // Only keep peers seen in the last 7 days
          if (entry.lastSeen && now - entry.lastSeen > 7 * 24 * 60 * 60 * 1000) continue;
          peers.push(entry.addr);
        }
      }
    } catch (err) {
      console.log('[P2P] Warning: could not load peer store:', err.message);
    }

    // Deduplicate while preserving order
    const seen = new Set();
    const unique = [];
    for (const addr of peers) {
      if (!addr) continue;
      if (seen.has(addr)) continue;
      seen.add(addr);
      unique.push(addr);
    }

    const maxPeers = Number(process.env.P2P_MAX_BOOTSTRAP || 20);
    return unique.slice(0, maxPeers);
  }

  extractPort(multiaddr) {
    const match = multiaddr.match(/\/tcp\/(\d+)/);
    return match ? parseInt(match[1]) : 0;
  }

  async connectToCluster(clusterId, clusterNodes, _registry) {
    console.log('[P2P] Connecting to cluster peers...');
    
    const topic = `/znode/cluster/${clusterId}`;
    
    const membersLower = clusterNodes.map(addr => addr.toLowerCase());
    this.clusterMembers.set(clusterId, new Set(membersLower));
    
    if (!this.subscriptions.has(topic)) {
      this.node.services.pubsub.subscribe(topic);
      this.subscriptions.set(topic, true);
      console.log(`[P2P] Subscribed to topic: ${topic} (${membersLower.length} members)`);
    }

    await new Promise(r => setTimeout(r, 2000));
    
    const peers = this.node.services.pubsub.getSubscribers(topic);
    console.log(`[P2P] Connected to ${peers.length} peers on cluster topic`);
    
    const requireE2E = process.env.P2P_REQUIRE_E2E === '1';
    const maxRetries = Number(process.env.P2P_IDENTITY_RETRIES || 3);
    const retryDelayMs = Number(process.env.P2P_IDENTITY_RETRY_DELAY_MS || 5000);
    
    let identitiesReceived = false;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      await this.broadcastIdentity(clusterId);
      identitiesReceived = await this.waitForIdentities(clusterId, clusterNodes);
      
      if (identitiesReceived) {
        console.log('[P2P] E2E encryption enabled for cluster');
        break;
      }
      
      if (attempt < maxRetries) {
        console.log(`[P2P] Identity collection incomplete, retrying (${attempt}/${maxRetries})...`);
        await new Promise(r => setTimeout(r, retryDelayMs));
      }
    }
    
    if (!identitiesReceived) {
      let receivedCount = 0;
      for (const addr of membersLower) {
        if (this.peerPublicKeys.has(addr)) {
          receivedCount++;
        }
      }
      console.log(`[P2P] Warning: Partial identity collection (${receivedCount}/${membersLower.length} nodes)`);
      
      if (requireE2E) {
        const livenessQuorum = Number(process.env.LIVENESS_QUORUM || 0);
        const defaultMinIdentities = livenessQuorum > 0 ? livenessQuorum : membersLower.length;
        const minIdentities = Number(process.env.P2P_MIN_IDENTITIES || defaultMinIdentities);
        if (receivedCount < minIdentities) {
          throw new Error(`P2P_REQUIRE_E2E=1 but only ${receivedCount}/${minIdentities} peer identities received`);
        }
        console.log(`[P2P] Proceeding with partial E2E encryption (${receivedCount}/${membersLower.length} nodes)`);
      }
    }
    
    return true;
  }

  async leaveCluster(clusterId) {
    const topic = `/znode/cluster/${clusterId}`;
    
    if (this.subscriptions.has(topic)) {
      try {
        this.node.services.pubsub.unsubscribe(topic);
        this.subscriptions.delete(topic);
        console.log(`[P2P] Unsubscribed from topic: ${topic}`);
      } catch (e) {
        console.log(`[P2P] Error unsubscribing from topic: ${e.message}`);
      }
    }
    
    this.clusterMembers.delete(clusterId);
    
    const keysToDelete = [];
    for (const key of this.roundData.keys()) {
      if (key.startsWith(`${clusterId}_`)) {
        keysToDelete.push(key);
      }
    }
    for (const key of keysToDelete) {
      this.roundData.delete(key);
      this.myData.delete(key);
      this.roundTimestamps.delete(key);
    }
    
    this.sstIdentities.delete(`${clusterId}_identity`);
    this.sstShares.delete(`${clusterId}_shares`);
    
    console.log(`[P2P] Cleaned up cluster data for ${clusterId}`);
  }

  handleMessage(message) {
    try {
      const data = JSON.parse(new TextDecoder().decode(message.data));
      const { type } = data;
      
      const senderPeerId = message.from ? message.from.toString() : null;
      
      if (type === 'round_data') {
        this.handleRoundDataMessage(data);
      } else if (type === 'p2p/identity') {
        this.handleIdentityMessage(data, senderPeerId);
      } else if (type === 'sst/identity' || type === 'sst/share') {
        this.handleSSTMessage(data);
      } else if (type === 'QUEUE_PRESENCE') {
        this.handleQueuePresence(data);
      } else if (type === 'p2p/heartbeat') {
        this.handleHeartbeat(data);
      } else if (type === 'p2p/sweep-proposal') {
        this.handleSweepProposal(data);
      } else if (type === 'p2p/sweep-ack') {
        this.handleSweepAck(data);
      } else if (type === 'p2p/sweep-cancel') {
        this.handleSweepCancel(data);
      } else if (type === 'p2p/sweep-txdata') {
        this.handleSweepTxData(data);
      }

      this.cleanupOldMessages();
    } catch (e) {
      console.log('[P2P] Invalid message:', e.message);
    }
  }

  checkRateLimit(address) {
    const now = Date.now();
    const windowMs = Number(process.env.P2P_RATE_LIMIT_WINDOW_MS || 60000);
    const maxMessages = Number(process.env.P2P_RATE_LIMIT_MAX || 100);
    
    const key = address.toLowerCase();
    if (!this.messageRateLimits.has(key)) {
      this.messageRateLimits.set(key, []);
    }
    
    const timestamps = this.messageRateLimits.get(key);
    const cutoff = now - windowMs;
    const recentMessages = timestamps.filter(t => t > cutoff);
    
    if (recentMessages.length >= maxMessages) {
      return false;
    }
    
    recentMessages.push(now);
    this.messageRateLimits.set(key, recentMessages);
    
    return true;
  }

  handleRoundDataMessage(data) {
    const { clusterId, round, address, payload, signature, nonce, timestamp, encrypted } = data;

    const allowedMembers = this.clusterMembers.get(clusterId);
    if (allowedMembers && !allowedMembers.has(address.toLowerCase())) {
      console.log(`[P2P] Rejecting message from non-member ${address.slice(0, 8)}`);
      return;
    }

    if (!this.checkRateLimit(address)) {
      console.log(`[P2P] Rate limit exceeded for ${address.slice(0, 8)}`);
      return;
    }

    const requireE2E = process.env.P2P_REQUIRE_E2E === '1';
    
    if (requireE2E) {
      if (payload && encrypted) {
        console.log(`[P2P] Rejecting mixed message (both payload and encrypted) from ${address.slice(0, 8)} when P2P_REQUIRE_E2E=1`);
        return;
      }
      if (payload && !encrypted) {
        console.log(`[P2P] Rejecting plaintext message from ${address.slice(0, 8)} when P2P_REQUIRE_E2E=1`);
        return;
      }
      if (!encrypted) {
        console.log(`[P2P] Rejecting unencrypted message from ${address.slice(0, 8)} when P2P_REQUIRE_E2E=1`);
        return;
      }
    }

    if (!payload && !encrypted) {
      console.log(`[P2P] Empty message from ${address.slice(0, 8)}`);
      return;
    }

    let decryptedPayload = payload;
    if (encrypted) {
      try {
        decryptedPayload = this.decryptPayload(encrypted, address);
      } catch (e) {
        console.log(`[P2P] Decryption failed from ${address.slice(0, 8)}: ${e.message}`);
        return;
      }
    }

    if (!decryptedPayload) {
      console.log(`[P2P] Empty payload from ${address.slice(0, 8)}`);
      return;
    }

    const payloadSize = typeof decryptedPayload === 'string' ? decryptedPayload.length : JSON.stringify(decryptedPayload).length;
    if (payloadSize > this.MAX_PAYLOAD_SIZE) {
      console.log(`[P2P] Payload too large from ${address.slice(0, 8)}: ${payloadSize} bytes`);
      return;
    }

    if (!this.verifyPayload(address, clusterId, decryptedPayload, round, signature, nonce, timestamp)) {
      console.log(`[P2P] Invalid signature from ${address.slice(0, 8)}`);
      return;
    }

    const messageId = `${clusterId}_${address}_${round}_${nonce}`;
    if (this.seenMessages.has(messageId)) {
      return;
    }
    
    const now = Date.now();
    const maxAge = Number(process.env.P2P_MESSAGE_MAX_AGE_MS || 300000);
    const maxSkew = Number(process.env.P2P_CLOCK_SKEW_MS || 120000);
    
    if (timestamp > now) {
      const futureSkew = timestamp - now;
      if (futureSkew > maxSkew) {
        console.log(`[P2P] Message from future from ${address.slice(0, 8)}: ${futureSkew}ms > ${maxSkew}ms`);
        return;
      }
    } else {
      const age = now - timestamp;
      if (age > maxAge) {
        console.log(`[P2P] Message too old from ${address.slice(0, 8)}: ${age}ms > ${maxAge}ms`);
        return;
      }
    }

    this.seenMessages.set(messageId, Date.now());
    
    const key = `${clusterId}_${round}`;
    if (!this.roundData.has(key)) {
      this.roundData.set(key, new Map());
      this.roundTimestamps.set(key, Date.now());
    }
    
    const roundMap = this.roundData.get(key);
    const clusterSize = Number(process.env.CLUSTER_SIZE || 11);
    
    if (roundMap.size >= clusterSize && !roundMap.has(address.toLowerCase())) {
      console.log(`[P2P] Round ${round} already has ${clusterSize} entries, rejecting additional payload`);
      return;
    }
    
    if (!roundMap.has(address.toLowerCase())) {
      this.totalPayloadSize += payloadSize;
      
      if (this.totalPayloadSize > this.MAX_TOTAL_MEMORY) {
        console.log('[P2P] Total memory limit exceeded, cleaning up old data');
        this.cleanupOldMessages();
      }
      
      roundMap.set(address.toLowerCase(), decryptedPayload);
      const count = roundMap.size;
      console.log(`[P2P] Received R${round} from ${address.slice(0, 8)} (${count})`);
    }
  }

  handleSSTMessage(data) {
    const { type, clusterId, nonce, timestamp } = data;
    
    const senderAddress = data.address || data.ownerAddress;
    if (!senderAddress) {
      console.log('[P2P] Rejecting SST message: no sender address');
      return;
    }
    
    const allowedMembers = this.clusterMembers.get(clusterId);
    if (allowedMembers && !allowedMembers.has(senderAddress.toLowerCase())) {
      console.log(`[P2P] Rejecting SST message from non-member ${senderAddress.slice(0, 8)}`);
      return;
    }

    if (!this.verifySSTMessage(data)) {
      console.log(`[P2P] Invalid SST signature from ${senderAddress.slice(0, 8)}`);
      return;
    }

    const messageId = `${type}_${clusterId}_${senderAddress}_${nonce}`;
    if (this.seenMessages.has(messageId)) {
      return;
    }

    const now = Date.now();
    const maxAge = Number(process.env.P2P_MESSAGE_MAX_AGE_MS || 120000);
    const maxSkew = Number(process.env.P2P_CLOCK_SKEW_MS || 120000);
    
    if (Math.abs(now - timestamp) > Math.max(maxAge, maxSkew)) {
      console.log(`[P2P] SST message timestamp out of acceptable range from ${senderAddress.slice(0, 8)}: ${now - timestamp}ms`);
      return;
    }

    this.seenMessages.set(messageId, Date.now());

    if (type === 'sst/identity') {
      const key = `${clusterId}_identity`;
      if (!this.sstIdentities.has(key)) {
        this.sstIdentities.set(key, new Map());
      }
      this.sstIdentities.get(key).set(senderAddress.toLowerCase(), data);
      console.log(`[P2P] Received SST identity from ${senderAddress.slice(0, 8)}`);
    } else if (type === 'sst/share') {
      const key = `${clusterId}_shares`;
      if (!this.sstShares.has(key)) {
        this.sstShares.set(key, new Map());
      }
      const shareKey = `${data.ownerAddress.toLowerCase()}_${data.recipientAddress.toLowerCase()}`;
      this.sstShares.get(key).set(shareKey, data);
      console.log(`[P2P] Received SST share from ${data.ownerAddress.slice(0, 8)} for ${data.recipientAddress.slice(0, 8)}`);
    }

    const handler = this.sstHandlers.get(type);
    if (handler) {
      handler(data);
    }
  }

  verifySSTMessage(data) {
    try {
      const { type, clusterId, signature, nonce, timestamp } = data;
      
      if (type === 'sst/identity') {
        const message = `${type}:${clusterId}:${data.address}:${data.publicKey}:${nonce}:${timestamp}`;
        const digest = ethers.id(message);
        const recovered = ethers.recoverAddress(digest, signature);
        return recovered.toLowerCase() === data.address.toLowerCase();
      } else if (type === 'sst/share') {
        const message = JSON.stringify({
          type: 'sst/share',
          clusterId,
          ownerAddress: data.ownerAddress.toLowerCase(),
          recipientAddress: data.recipientAddress.toLowerCase(),
          shareIndex: data.shareIndex,
          totalShares: data.totalShares,
          threshold: data.threshold,
          ephemeralPublicKey: data.ephemeralPublicKey,
          iv: data.iv,
          authTag: data.authTag,
          ciphertext: data.ciphertext,
          timestamp,
          nonce
        });
        const recovered = ethers.verifyMessage(message, signature);
        return recovered.toLowerCase() === data.ownerAddress.toLowerCase();
      } else if (type === 'sst/key-transfer') {
        const message = `${type}:${clusterId}:${data.fromAddress}:${data.toAddress}:${nonce}:${timestamp}`;
        const digest = ethers.id(message);
        const recovered = ethers.recoverAddress(digest, signature);
        return recovered.toLowerCase() === data.fromAddress.toLowerCase();
      }
      
      return false;
    } catch (e) {
      console.log('[P2P] SST signature verification error:', e.message);
      return false;
    }
  }

  cleanupOldMessages() {
    const now = Date.now();
    const maxAge = Number(process.env.P2P_MESSAGE_MAX_AGE_MS || 300000);
    
    for (const [messageId, timestamp] of this.seenMessages.entries()) {
      if (now - timestamp > maxAge) {
        this.seenMessages.delete(messageId);
      }
    }
    
    if (this.seenMessages.size > this.MAX_SEEN_MESSAGES) {
      const entries = Array.from(this.seenMessages.entries());
      entries.sort((a, b) => a[1] - b[1]);
      const toRemove = entries.slice(0, this.seenMessages.size - this.MAX_SEEN_MESSAGES);
      for (const [messageId] of toRemove) {
        this.seenMessages.delete(messageId);
      }
    }
    
    const roundMaxAge = Number(process.env.ROUND_DATA_MAX_AGE_MS || 600000);
    this.totalPayloadSize = 0;
    for (const [key, timestamp] of this.roundTimestamps.entries()) {
      if (now - timestamp > roundMaxAge) {
        this.roundData.delete(key);
        this.myData.delete(key);
        this.roundTimestamps.delete(key);
      } else {
        const roundMap = this.roundData.get(key);
        if (roundMap) {
          for (const payload of roundMap.values()) {
            const size = typeof payload === 'string' ? payload.length : JSON.stringify(payload).length;
            this.totalPayloadSize += size;
          }
        }
      }
    }
    
    while (this.totalPayloadSize > this.MAX_TOTAL_MEMORY && this.roundData.size > 0) {
      const entries = Array.from(this.roundTimestamps.entries());
      if (entries.length === 0) break;
      
      entries.sort((a, b) => a[1] - b[1]);
      const oldestKey = entries[0][0];
      
      const roundMap = this.roundData.get(oldestKey);
      if (roundMap) {
        for (const payload of roundMap.values()) {
          const size = typeof payload === 'string' ? payload.length : JSON.stringify(payload).length;
          this.totalPayloadSize -= size;
        }
      }
      
      this.roundData.delete(oldestKey);
      this.myData.delete(oldestKey);
      this.roundTimestamps.delete(oldestKey);
      console.log(`[P2P] Memory pressure: Evicted oldest round ${oldestKey}. Note: Slow peers may lose access to previous round data under high churn.`);
    }
    
    for (const [key, timestamps] of this.messageRateLimits.entries()) {
      const recent = timestamps.filter(t => t > now - 60000);
      if (recent.length === 0) {
        this.messageRateLimits.delete(key);
      } else {
        this.messageRateLimits.set(key, recent);
      }
    }
    
    if (this.messageRateLimits.size > this.MAX_RATE_LIMIT_ENTRIES) {
      const entries = Array.from(this.messageRateLimits.entries());
      entries.sort((a, b) => {
        const aOldest = Math.min(...a[1]);
        const bOldest = Math.min(...b[1]);
        return aOldest - bOldest;
      });
      
      const toRemove = entries.slice(0, this.messageRateLimits.size - this.MAX_RATE_LIMIT_ENTRIES);
      for (const [key] of toRemove) {
        this.messageRateLimits.delete(key);
      }
      console.log(`[P2P] Evicted ${toRemove.length} rate limit entries (max: ${this.MAX_RATE_LIMIT_ENTRIES})`);
    }
  }

  async broadcastRoundData(clusterId, round, payload) {
    const payloadSize = Buffer.byteLength(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');
    
    if (payloadSize > this.MAX_PAYLOAD_SIZE) {
      console.error(`[P2P] Payload size ${payloadSize} bytes exceeds MAX_PAYLOAD_SIZE ${this.MAX_PAYLOAD_SIZE} bytes for round ${round}`);
      throw new Error(`Payload too large: ${payloadSize} bytes > ${this.MAX_PAYLOAD_SIZE} bytes`);
    }
    
    if (payloadSize > this.MAX_PAYLOAD_SIZE * 0.8) {
      console.warn(`[P2P] Round ${round} payload size ${payloadSize} bytes approaching limit (${Math.round(payloadSize/this.MAX_PAYLOAD_SIZE*100)}%)`);
    }
    
    const now = Date.now();
    if (now - this.outboundMessageWindow > this.OUTBOUND_RATE_WINDOW) {
      this.outboundMessageCount = 0;
      this.outboundMessageWindow = now;
    }
    
    if (this.outboundMessageCount >= this.MAX_OUTBOUND_RATE) {
      console.log('[P2P] Outbound rate limit exceeded, dropping message');
      return;
    }
    this.outboundMessageCount++;
    
    const nonce = ethers.hexlify(crypto.randomBytes(32));
    const timestamp = Date.now();
    const signature = this.signPayload(clusterId, payload, round, nonce, timestamp);
    
    const clusterMembers = this.clusterMembers.get(clusterId);
    const requireE2E = process.env.P2P_REQUIRE_E2E === '1';
    
    let fullE2EReady = false;
    if (clusterMembers && clusterMembers.size > 1) {
      let identityCount = 0;
      for (const memberAddr of clusterMembers) {
        if (memberAddr === this.ethereumAddress) continue;
        const keyInfo = this.peerPublicKeys.get(memberAddr);
        const publicKey = keyInfo && keyInfo.publicKey ? keyInfo.publicKey : keyInfo;
        if (publicKey) {
          identityCount++;
        }
      }
      const expectedPeers = clusterMembers.size - 1; // Exclude self
      fullE2EReady = (identityCount === expectedPeers);
      
      if (!fullE2EReady) {
        console.log(`[P2P] Partial identity coverage: ${identityCount}/${expectedPeers} peers`);
      }
    }
    
    if (requireE2E && !fullE2EReady) {
      const identityCount = clusterMembers ? Array.from(clusterMembers).filter(m => m !== this.ethereumAddress && this.peerPublicKeys.has(m)).length : 0;
      const expectedPeers = clusterMembers ? clusterMembers.size - 1 : 0;
      throw new Error(`P2P_REQUIRE_E2E=1 requires full identity coverage, got ${identityCount}/${expectedPeers} peer identities`);
    }
    
    if (fullE2EReady && clusterMembers && clusterMembers.size > 1) {
      const encryptedPayloads = {};
      const expectedPeers = clusterMembers.size - 1;
      let encryptionFailed = false;
      
      for (const memberAddr of clusterMembers) {
        if (memberAddr === this.ethereumAddress) continue;
        const keyInfo = this.peerPublicKeys.get(memberAddr);
        const publicKey = keyInfo && keyInfo.publicKey ? keyInfo.publicKey : keyInfo;
        if (publicKey) {
          try {
            encryptedPayloads[memberAddr] = this.encryptPayload(payload, publicKey);
          } catch (e) {
            console.log(`[P2P] Encryption failed for ${memberAddr.slice(0, 8)}: ${e.message}`);
            encryptionFailed = true;
            if (requireE2E) {
              throw new Error(`P2P_REQUIRE_E2E=1 but encryption failed for ${memberAddr.slice(0, 8)}: ${e.message}`);
            }
            console.log(`[P2P] Falling back to plaintext due to encryption failure`);
            break;
          }
        }
      }
      
      const encryptedCount = Object.keys(encryptedPayloads).length;
      if (!encryptionFailed && encryptedCount === expectedPeers) {
        const message = {
          type: 'round_data',
          clusterId,
          round,
          address: this.ethereumAddress,
          encrypted: encryptedPayloads,
          signature,
          nonce,
          timestamp
        };
        
        const key = `${clusterId}_${round}`;
        if (!this.roundData.has(key)) {
          this.roundData.set(key, new Map());
          this.roundTimestamps.set(key, Date.now());
        }
        this.roundData.get(key).set(this.ethereumAddress.toLowerCase(), payload);
        this.myData.set(key, payload);
        
        const topic = `/znode/cluster/${clusterId}`;
        const msgBytes = new TextEncoder().encode(JSON.stringify(message));
        
        try {
          await this.node.services.pubsub.publish(topic, msgBytes);
          console.log(`[P2P] Broadcast R${round} to cluster topic (encrypted, full E2E)`);
        } catch (e) {
          console.log('[P2P] Broadcast error:', e.message);
        }
        return;
      } else if (encryptionFailed || encryptedCount < expectedPeers) {
        console.log(`[P2P] Partial encryption (${encryptedCount}/${expectedPeers}), falling back to plaintext`);
      }
    }
    
    // Fallback to plaintext when E2E not required and full coverage not available
    if (!requireE2E) {
      console.log(`[P2P] Broadcasting R${round} in plaintext (E2E not required or partial coverage)`);
    }
    
    const message = {
      type: 'round_data',
      clusterId,
      round,
      address: this.ethereumAddress,
      payload,
      signature,
      nonce,
      timestamp
    };
    
    const key = `${clusterId}_${round}`;
    if (!this.roundData.has(key)) {
      this.roundData.set(key, new Map());
      this.roundTimestamps.set(key, Date.now());
    }
    this.roundData.get(key).set(this.ethereumAddress.toLowerCase(), payload);
    this.myData.set(key, payload);
    
    const topic = `/znode/cluster/${clusterId}`;
    const msgBytes = new TextEncoder().encode(JSON.stringify(message));
    
    try {
      await this.node.services.pubsub.publish(topic, msgBytes);
      console.log(`[P2P] Broadcast R${round} to cluster topic`);
    } catch (e) {
      console.log('[P2P] Broadcast error:', e.message);
    }
  }

  async waitForRoundCompletion(clusterId, round, clusterNodes, timeoutMs = 180000) {
    const key = `${clusterId}_${round}`;
    const startTime = Date.now();
    const expected = clusterNodes.length;
    const membersLower = clusterNodes.map(addr => addr.toLowerCase());
    
    console.log(`[P2P] Waiting for R${round} completion (0/${expected})...`);
    
    while (Date.now() - startTime < timeoutMs) {
      const collected = this.roundData.get(key);
      
      let memberCount = 0;
      if (collected) {
        for (const addr of membersLower) {
          if (collected.has(addr)) {
            memberCount++;
          }
        }
      }
      
      if (memberCount >= expected) {
        console.log(`[P2P] Round ${round} complete: ${memberCount}/${expected} nodes`);
        return true;
      }
      
      if (memberCount > 0 && (Date.now() - startTime) % 10000 < 1000) {
        console.log(`[P2P] Round ${round} progress: ${memberCount}/${expected} nodes`);
      }
      
      await new Promise(r => setTimeout(r, 2000));
    }
    
    const collected = this.roundData.get(key);
    let memberCount = 0;
    if (collected) {
      for (const addr of membersLower) {
        if (collected.has(addr)) {
          memberCount++;
        }
      }
    }
    console.log(`[P2P] Round ${round} timeout: ${memberCount}/${expected} nodes`);
    return false;
  }

  getPeerPayloads(clusterId, round, clusterNodes) {
    const key = `${clusterId}_${round}`;
    const collected = this.roundData.get(key) || new Map();
    
    const payloads = [];
    for (const addr of clusterNodes) {
      if (!addr) continue;
      const lower = addr.toLowerCase();
      if (lower === this.ethereumAddress) continue;
      
      const payload = collected.get(lower);
      if (payload && payload.length > 0) {
        payloads.push(payload);
      }
    }
    
    return payloads;
  }

  countConnectedPeers() {
    if (!this.node) return 0;
    return this.node.getConnections().length;
  }

  signPayload(clusterId, payload, round, nonce, timestamp) {
    const chainId = Number(process.env.CHAIN_ID || 11155111);
    
    const domain = {
      name: 'ZNode',
      version: '1',
      chainId: chainId
    };
    
    const types = {
      RoundData: [
        { name: 'messageType', type: 'string' },
        { name: 'sender', type: 'address' },
        { name: 'clusterId', type: 'bytes32' },
        { name: 'round', type: 'uint256' },
        { name: 'payload', type: 'string' },
        { name: 'nonce', type: 'bytes32' },
        { name: 'timestamp', type: 'uint256' }
      ]
    };
    
    const value = {
      messageType: 'round_data',
      sender: this.ethereumAddress,
      clusterId: clusterId,
      round: round,
      payload: payload,
      nonce: nonce,
      timestamp: timestamp
    };
    
    const signingKey = new ethers.SigningKey(this.ethereumPrivateKey);
    const digest = ethers.TypedDataEncoder.hash(domain, types, value);
    return signingKey.sign(digest).serialized;
  }

  verifyPayload(address, clusterId, payload, round, signature, nonce, timestamp) {
    try {
      const chainId = Number(process.env.CHAIN_ID || 11155111);
      
      const domain = {
        name: 'ZNode',
        version: '1',
        chainId: chainId
      };
      
      const types = {
        RoundData: [
          { name: 'messageType', type: 'string' },
          { name: 'sender', type: 'address' },
          { name: 'clusterId', type: 'bytes32' },
          { name: 'round', type: 'uint256' },
          { name: 'payload', type: 'string' },
          { name: 'nonce', type: 'bytes32' },
          { name: 'timestamp', type: 'uint256' }
        ]
      };
      
      const value = {
        messageType: 'round_data',
        sender: address,
        clusterId: clusterId,
        round: round,
        payload: payload,
        nonce: nonce,
        timestamp: timestamp
      };
      
      const digest = ethers.TypedDataEncoder.hash(domain, types, value);
      const recovered = ethers.recoverAddress(digest, signature);
      const isValid = recovered.toLowerCase() === address.toLowerCase();
      
      if (!isValid) {
        console.log(`[P2P] Signature verification failed for ${address.slice(0, 8)}: recovered=${recovered.slice(0, 8)}, expected=${address.slice(0, 8)}, chainId=${chainId}, round=${round}`);
      }
      
      return isValid;
    } catch (e) {
      const chainId = Number(process.env.CHAIN_ID || 11155111);
      console.log(`[P2P] Signature verification error for ${address.slice(0, 8)}: ${e.message}, chainId=${chainId}, round=${round}`);
      return false;
    }
  }

  async broadcastIdentity(clusterId) {
    const signingKey = new ethers.SigningKey(this.ethereumPrivateKey);
    const publicKey = '0x' + signingKey.publicKey.slice(2);
    
    const nonce = ethers.hexlify(crypto.randomBytes(32));
    const timestamp = Date.now();
    const peerId = this.node.peerId.toString();
    const topic = `/znode/cluster/${clusterId}`;
    
    const chainIdStr = process.env.CHAIN_ID || '11155111';
    const chainId = Number(chainIdStr);
    if (isNaN(chainId) || chainId < 1 || chainId > Number.MAX_SAFE_INTEGER) {
      throw new Error(`Invalid CHAIN_ID: ${chainIdStr}`);
    }
    const domain = {
      name: 'ZNode',
      version: '1',
      chainId: chainId
    };
    
    const types = {
      Identity: [
        { name: 'messageType', type: 'string' },
        { name: 'clusterId', type: 'bytes32' },
        { name: 'peerId', type: 'string' },
        { name: 'topic', type: 'string' },
        { name: 'publicKey', type: 'string' },
        { name: 'nonce', type: 'bytes32' },
        { name: 'timestamp', type: 'uint256' }
      ]
    };
    
    const value = {
      messageType: 'p2p_identity',
      clusterId: clusterId,
      peerId: peerId,
      topic: topic,
      publicKey: publicKey,
      nonce: nonce,
      timestamp: timestamp
    };
    
    const digest = ethers.TypedDataEncoder.hash(domain, types, value);
    const signature = signingKey.sign(digest).serialized;
    
    const message = {
      type: 'p2p/identity',
      clusterId,
      address: this.ethereumAddress,
      peerId,
      topic,
      publicKey,
      nonce,
      timestamp,
      signature
    };
    
    const msgBytes = new TextEncoder().encode(JSON.stringify(message));
    
    try {
      await this.node.services.pubsub.publish(topic, msgBytes);
      console.log('[P2P] Broadcast identity with public key and PeerId binding');
      
      this.peerPublicKeys.set(this.ethereumAddress.toLowerCase(), { publicKey, peerId, lastSeen: Date.now() });
    } catch (e) {
      console.log('[P2P] Identity broadcast error:', e.message);
    }
  }

  handleIdentityMessage(data, senderPeerId) {
    const { clusterId, address, publicKey, peerId, topic, signature, nonce, timestamp } = data;
    
    const allowedMembers = this.clusterMembers.get(clusterId);
    if (allowedMembers && !allowedMembers.has(address.toLowerCase())) {
      console.log(`[P2P] Rejecting identity from non-member ${address.slice(0, 8)}`);
      return;
    }
    
    if (!this.checkRateLimit(address)) {
      console.log(`[P2P] Rate limit exceeded for identity from ${address.slice(0, 8)}`);
      return;
    }
    
    const now = Date.now();
    const maxAge = Number(process.env.P2P_MESSAGE_MAX_AGE_MS || 300000);
    const maxSkew = Number(process.env.P2P_CLOCK_SKEW_MS || 120000);
    const timeDiff = now - timestamp;
    
    if (timeDiff > maxAge) {
      console.log(`[P2P] Identity message too old from ${address.slice(0, 8)}: ${timeDiff}ms > ${maxAge}ms`);
      return;
    }
    
    if (timeDiff < -maxSkew) {
      console.log(`[P2P] Identity message from future (clock skew) from ${address.slice(0, 8)}: ${-timeDiff}ms > ${maxSkew}ms`);
      return;
    }
    
    if (!publicKey || !publicKey.startsWith('0x04') || publicKey.length !== 132) {
      console.log(`[P2P] Invalid public key format from ${address.slice(0, 8)} (expected 132 chars, got ${publicKey?.length || 0})`);
      return;
    }
    
    if (!peerId || typeof peerId !== 'string') {
      console.log(`[P2P] Missing or invalid peerId from ${address.slice(0, 8)}`);
      return;
    }
    
    if (senderPeerId && senderPeerId !== peerId) {
      console.error(`[P2P] SECURITY: PeerID mismatch from ${address.slice(0, 8)}`);
      console.error(`[P2P]   Claimed PeerID: ${peerId.slice(0, 20)}...`);
      console.error(`[P2P]   Actual sender PeerID: ${senderPeerId.slice(0, 20)}...`);
      console.error(`[P2P]   This indicates a potential MITM attack or message relay`);
      console.error(`[P2P]   Rejecting identity message to prevent key substitution`);
      return;
    }
    
    const expectedTopic = `/znode/cluster/${clusterId}`;
    if (topic !== expectedTopic) {
      console.log(`[P2P] Topic mismatch from ${address.slice(0, 8)}: expected ${expectedTopic}, got ${topic}`);
      return;
    }
    
    try {
      const chainIdStr = process.env.CHAIN_ID || '11155111';
      const chainId = Number(chainIdStr);
      if (isNaN(chainId) || chainId < 1 || chainId > Number.MAX_SAFE_INTEGER) {
        throw new Error(`Invalid CHAIN_ID: ${chainIdStr}`);
      }
      
      const domain = {
        name: 'ZNode',
        version: '1',
        chainId: chainId
      };
      
      const types = {
        Identity: [
          { name: 'messageType', type: 'string' },
          { name: 'clusterId', type: 'bytes32' },
          { name: 'peerId', type: 'string' },
          { name: 'topic', type: 'string' },
          { name: 'publicKey', type: 'string' },
          { name: 'nonce', type: 'bytes32' },
          { name: 'timestamp', type: 'uint256' }
        ]
      };
      
      const value = {
        messageType: 'p2p_identity',
        clusterId: clusterId,
        peerId: peerId,
        topic: topic,
        publicKey: publicKey,
        nonce: nonce,
        timestamp: timestamp
      };
      
      const digest = ethers.TypedDataEncoder.hash(domain, types, value);
      const recovered = ethers.recoverAddress(digest, signature);
      
      if (recovered.toLowerCase() !== address.toLowerCase()) {
        console.log(`[P2P] Invalid identity signature from ${address.slice(0, 8)}`);
        return;
      }
      
      const testKey = ec.keyFromPublic(publicKey.slice(2), 'hex');
      const testAddress = '0x' + ethers.keccak256('0x' + testKey.getPublic().encode('hex').slice(2)).slice(-40);
      
      if (testAddress.toLowerCase() !== address.toLowerCase()) {
        console.log(`[P2P] Public key does not match address from ${address.slice(0, 8)}`);
        return;
      }
    } catch (e) {
      console.log(`[P2P] Identity verification failed from ${address.slice(0, 8)}: ${e.message}`);
      return;
    }
    
    const messageId = `identity_${clusterId}_${address}_${nonce}`;
    if (this.seenMessages.has(messageId)) {
      return;
    }
    this.seenMessages.set(messageId, Date.now());
    
    const addressLower = address.toLowerCase();
    const existingBinding = this.peerIdBindings.get(addressLower);
    
    if (existingBinding && existingBinding.peerId !== peerId) {
      console.warn(`[P2P] SECURITY WARNING: Address ${address.slice(0, 8)} attempting to rebind peerId`);
      console.warn(`[P2P]   Previous peerId: ${existingBinding.peerId}`);
      console.warn(`[P2P]   New peerId claim: ${peerId}`);
      console.warn(`[P2P]   This may indicate an identity replay attack or node restart`);
      console.warn(`[P2P]   Rejecting identity message to prevent potential attack`);
      return;
    }
    
    if (!existingBinding) {
      this.peerIdBindings.set(addressLower, { peerId, firstSeen: Date.now(), lastSeen: Date.now() });
      console.log(`[P2P] Established peerId binding for ${address.slice(0, 8)} -> ${peerId.slice(0, 12)}`);
    } else {
      existingBinding.lastSeen = Date.now();
    }
    
    this.peerPublicKeys.set(addressLower, { publicKey, peerId, lastSeen: Date.now() });
    console.log(`[P2P] Stored public key for ${address.slice(0, 8)} with PeerId ${peerId.slice(0, 20)}...`);
  }

  async waitForIdentities(clusterId, clusterNodes, timeoutMs = 60000) {
    const startTime = Date.now();
    const expected = clusterNodes.length;
    const membersLower = clusterNodes.map(addr => addr.toLowerCase());
    
    console.log(`[P2P] Waiting for identities (0/${expected})...`);
    
    while (Date.now() - startTime < timeoutMs) {
      let count = 0;
      for (const addr of membersLower) {
        if (this.peerPublicKeys.has(addr)) {
          count++;
        }
      }
      
      if (count >= expected) {
        console.log(`[P2P] Identities complete: ${count}/${expected} nodes`);
        return true;
      }
      
      if (count > 0 && (Date.now() - startTime) % 10000 < 1000) {
        console.log(`[P2P] Identities progress: ${count}/${expected} nodes`);
      }
      
      await new Promise(r => setTimeout(r, 2000));
    }
    
    let count = 0;
    for (const addr of membersLower) {
      if (this.peerPublicKeys.has(addr)) {
        count++;
      }
    }
    console.log(`[P2P] Identities timeout: ${count}/${expected} nodes`);
    return false;
  }

  getRecentPeers(ttlMs) {
    const now = Date.now();
    const maxAge = Number(ttlMs || process.env.P2P_ONLINE_TTL_MS || 300000);
    const out = [];
    for (const [addr, info] of this.peerPublicKeys.entries()) {
      const lastSeen = info && typeof info === 'object' && 'lastSeen' in info ? info.lastSeen : null;
      if (!lastSeen) continue;
      if (now - lastSeen <= maxAge) {
        out.push(addr);
      }
    }
    return out;
  }

  async broadcastSSTMessage(clusterId, messageData) {
    const topic = `/znode/cluster/${clusterId}`;
    const msgBytes = new TextEncoder().encode(JSON.stringify(messageData));
    
    try {
      await this.node.services.pubsub.publish(topic, msgBytes);
      console.log(`[P2P] Broadcast SST message type=${messageData.type}`);
    } catch (e) {
      console.log('[P2P] SST broadcast error:', e.message);
    }
  }

  registerSSTHandler(type, handler) {
    this.sstHandlers.set(type, handler);
  }

  getSSTIdentities(clusterId) {
    const key = `${clusterId}_identity`;
    return this.sstIdentities.get(key) || new Map();
  }

  getSSTShares(clusterId, ownerAddress, recipientAddress) {
    const key = `${clusterId}_shares`;
    const shares = this.sstShares.get(key);
    if (!shares) return null;
    
    const shareKey = `${ownerAddress.toLowerCase()}_${recipientAddress.toLowerCase()}`;
    return shares.get(shareKey);
  }

  async waitForSSTIdentities(clusterId, clusterNodes, timeoutMs = 180000) {
    const startTime = Date.now();
    const expected = clusterNodes.length;
    const membersLower = clusterNodes.map(addr => addr.toLowerCase());
    
    console.log(`[P2P] Waiting for SST identities (0/${expected})...`);
    
    while (Date.now() - startTime < timeoutMs) {
      const identities = this.getSSTIdentities(clusterId);
      
      let count = 0;
      for (const addr of membersLower) {
        if (identities.has(addr)) {
          count++;
        }
      }
      
      if (count >= expected) {
        console.log(`[P2P] SST identities complete: ${count}/${expected} nodes`);
        return true;
      }
      
      if (count > 0 && (Date.now() - startTime) % 10000 < 1000) {
        console.log(`[P2P] SST identities progress: ${count}/${expected} nodes`);
      }
      
      await new Promise(r => setTimeout(r, 2000));
    }
    
    const identities = this.getSSTIdentities(clusterId);
    let count = 0;
    for (const addr of membersLower) {
      if (identities.has(addr)) {
        count++;
      }
    }
    console.log(`[P2P] SST identities timeout: ${count}/${expected} nodes`);
    return false;
  }

  async waitForSSTShares(clusterId, ownerAddresses, recipientAddress, timeoutMs = 180000) {
    const startTime = Date.now();
    const expected = ownerAddresses.length;
    const ownersLower = ownerAddresses.map(addr => addr.toLowerCase());
    const recipientLower = recipientAddress.toLowerCase();
    
    console.log(`[P2P] Waiting for SST shares (0/${expected})...`);
    
    while (Date.now() - startTime < timeoutMs) {
      let count = 0;
      for (const ownerAddr of ownersLower) {
        const share = this.getSSTShares(clusterId, ownerAddr, recipientLower);
        if (share) {
          count++;
        }
      }
      
      if (count >= expected) {
        console.log(`[P2P] SST shares complete: ${count}/${expected} shares`);
        return true;
      }
      
      if (count > 0 && (Date.now() - startTime) % 10000 < 1000) {
        console.log(`[P2P] SST shares progress: ${count}/${expected} shares`);
      }
      
      await new Promise(r => setTimeout(r, 2000));
    }
    
    let count = 0;
    for (const ownerAddr of ownersLower) {
      const share = this.getSSTShares(clusterId, ownerAddr, recipientLower);
      if (share) {
        count++;
      }
    }
    console.log(`[P2P] SST shares timeout: ${count}/${expected} shares`);
    return false;
  }

  encryptPayload(payload, recipientPublicKey) {
    if (!recipientPublicKey || !recipientPublicKey.startsWith('0x04')) {
      throw new Error('Invalid recipient public key format');
    }

    const ephemeralKey = ec.genKeyPair();
    const ephemeralPublicKey = '0x' + ephemeralKey.getPublic('hex');

    const recipientKeyHex = recipientPublicKey.slice(2);
    const recipientKey = ec.keyFromPublic(recipientKeyHex, 'hex');
    
    const validation = recipientKey.validate();
    if (!validation.result) {
      throw new Error('Invalid recipient public key: not on secp256k1 curve');
    }

    const sharedPoint = ephemeralKey.derive(recipientKey.getPublic());
    const sharedSecret = Buffer.from(sharedPoint.toArray('be', 32));

    const salt = Buffer.from('znode-p2p-v1', 'utf8');
    const info = Buffer.from('aes-256-gcm', 'utf8');
    const aesKey = this._hkdf(sharedSecret, salt, info, 32);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    
    const dataBuffer = Buffer.from(typeof payload === 'string' ? payload : JSON.stringify(payload), 'utf8');
    const ciphertext = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
    const authTag = cipher.getAuthTag();

    aesKey.fill(0);
    sharedSecret.fill(0);

    return {
      ephemeralPublicKey,
      iv: '0x' + iv.toString('hex'),
      authTag: '0x' + authTag.toString('hex'),
      ciphertext: '0x' + ciphertext.toString('hex')
    };
  }

  decryptPayload(encryptedPayloads, _senderAddress) {
    const envelope = encryptedPayloads[this.ethereumAddress];
    if (!envelope) {
      throw new Error('No encrypted payload for this node');
    }

    const { ephemeralPublicKey, iv, authTag, ciphertext } = envelope;

    const ephemeralKeyHex = ephemeralPublicKey.slice(2);
    const ephemeralKey = ec.keyFromPublic(ephemeralKeyHex, 'hex');
    
    const validation = ephemeralKey.validate();
    if (!validation.result) {
      throw new Error('Invalid ephemeral public key: not on secp256k1 curve');
    }

    const privKeyHex = this.ethereumPrivateKey.startsWith('0x') ? this.ethereumPrivateKey.slice(2) : this.ethereumPrivateKey;
    const ourKey = ec.keyFromPrivate(privKeyHex, 'hex');

    const sharedPoint = ourKey.derive(ephemeralKey.getPublic());
    const sharedSecret = Buffer.from(sharedPoint.toArray('be', 32));

    const salt = Buffer.from('znode-p2p-v1', 'utf8');
    const info = Buffer.from('aes-256-gcm', 'utf8');
    const aesKey = this._hkdf(sharedSecret, salt, info, 32);

    const ivBuffer = Buffer.from(iv.slice(2), 'hex');
    const authTagBuffer = Buffer.from(authTag.slice(2), 'hex');
    const ciphertextBuffer = Buffer.from(ciphertext.slice(2), 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', aesKey, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    const plaintext = Buffer.concat([decipher.update(ciphertextBuffer), decipher.final()]);

    aesKey.fill(0);
    sharedSecret.fill(0);

    return plaintext.toString('utf8');
  }

  _hkdf(ikm, salt, info, length) {
    const hmac1 = crypto.createHmac('sha256', salt);
    hmac1.update(ikm);
    const prk = hmac1.digest();

    const n = Math.ceil(length / 32);
    let t = Buffer.alloc(0);
    let okm = Buffer.alloc(0);

    for (let i = 1; i <= n; i++) {
      const hmac2 = crypto.createHmac('sha256', prk);
      hmac2.update(t);
      hmac2.update(info);
      hmac2.update(Buffer.from([i]));
      t = hmac2.digest();
      okm = Buffer.concat([okm, t]);
    }

    return okm.slice(0, length);
  }

  handleQueuePresence(data) {
    const { address, timestamp } = data || {};
    if (!address) return;
    const ts = typeof timestamp === 'number' ? timestamp : Date.now();
    this.queuePresence.set(address.toLowerCase(), ts);
  }

  async startQueueDiscovery(ethereumAddress) {
    if (this._queueDiscoveryStarted) {
      return;
    }
    this._queueDiscoveryStarted = true;
    
    if (!this.node || !this.node.services || !this.node.services.pubsub) {
      console.log('[P2P] Queue discovery skipped: pubsub not available');
      return;
    }

    const topic = '/znode/queue/presence';

    if (!this.subscriptions.has(topic)) {
      this.node.services.pubsub.subscribe(topic);
      this.subscriptions.set(topic, true);
      console.log('[P2P] Subscribed to queue presence topic');
    }

    const sendPresence = async () => {
      try {
        const msg = {
          type: 'QUEUE_PRESENCE',
          address: ethereumAddress.toLowerCase(),
          timestamp: Date.now()
        };
        const bytes = new TextEncoder().encode(JSON.stringify(msg));
        await this.node.services.pubsub.publish(topic, bytes);
      } catch (e) {
        console.log('[P2P] Queue presence broadcast error:', e.message || String(e));
      }
    };

    if (this.queuePresenceInterval) {
      clearInterval(this.queuePresenceInterval);
    }

    await sendPresence();
    const intervalMs = Number(process.env.P2P_QUEUE_PRESENCE_INTERVAL_MS || 60000);
    this.queuePresenceInterval = setInterval(sendPresence, intervalMs);
  }

  getQueuePeers(ttlMs) {
    const now = Date.now();
    const maxAge = Number(ttlMs || process.env.P2P_ONLINE_TTL_MS || 300000);
    const out = [];
    for (const [addr, ts] of this.queuePresence.entries()) {
      if (now - ts <= maxAge) {
        out.push(addr);
      }
    }
    return out;
  }

  async broadcastHeartbeat() {
    if (!this.node || !this.node.services || !this.node.services.pubsub) {
      console.log('[P2P] Heartbeat broadcast skipped: pubsub not available');
      return;
    }

    const topic = '/znode/heartbeat';
    
    if (!this.subscriptions.has(topic)) {
      this.node.services.pubsub.subscribe(topic);
      this.subscriptions.set(topic, true);
      console.log('[P2P] Subscribed to heartbeat topic');
    }

    try {
      const timestamp = Date.now();
      const nonce = ethers.hexlify(crypto.randomBytes(32));
      
      const message = `heartbeat:${this.ethereumAddress}:${timestamp}:${nonce}`;
      const digest = ethers.id(message);
      const signature = await this.signHeartbeat(digest);
      
      const msg = {
        type: 'p2p/heartbeat',
        address: this.ethereumAddress,
        timestamp,
        nonce,
        signature
      };
      
      const bytes = new TextEncoder().encode(JSON.stringify(msg));
      await this.node.services.pubsub.publish(topic, bytes);
      
      this.heartbeats.set(this.ethereumAddress.toLowerCase(), timestamp);
      console.log('[P2P] Heartbeat broadcast sent');
    } catch (e) {
      console.log('[P2P] Heartbeat broadcast error:', e.message || String(e));
    }
  }

  async signHeartbeat(digest) {
    const wallet = new ethers.Wallet(this.ethereumPrivateKey);
    return await wallet.signMessage(ethers.getBytes(digest));
  }

  handleHeartbeat(data) {
    const { address, timestamp, nonce, signature } = data || {};
    
    if (!address || !timestamp || !nonce || !signature) {
      console.log('[P2P] Invalid heartbeat message: missing fields');
      return;
    }

    if (!this.checkRateLimit(address)) {
      console.log(`[P2P] Heartbeat rate limit exceeded for ${address.slice(0, 8)}`);
      return;
    }

    const now = Date.now();
    const maxAge = Number(process.env.P2P_MESSAGE_MAX_AGE_MS || 300000);
    const maxSkew = Number(process.env.P2P_CLOCK_SKEW_MS || 120000);
    
    if (timestamp > now) {
      const futureSkew = timestamp - now;
      if (futureSkew > maxSkew) {
        console.log(`[P2P] Heartbeat from future from ${address.slice(0, 8)}: ${futureSkew}ms > ${maxSkew}ms`);
        return;
      }
    } else {
      const age = now - timestamp;
      if (age > maxAge) {
        console.log(`[P2P] Heartbeat too old from ${address.slice(0, 8)}: ${age}ms > ${maxAge}ms`);
        return;
      }
    }

    const messageId = `heartbeat_${address}_${nonce}`;
    if (this.seenMessages.has(messageId)) {
      return;
    }

    try {
      const message = `heartbeat:${address}:${timestamp}:${nonce}`;
      const digest = ethers.id(message);
      const recovered = ethers.recoverAddress(digest, signature);
      
      if (recovered.toLowerCase() !== address.toLowerCase()) {
        console.log(`[P2P] Invalid heartbeat signature from ${address.slice(0, 8)}`);
        return;
      }

      this.seenMessages.set(messageId, Date.now());
      this.heartbeats.set(address.toLowerCase(), timestamp);
      console.log(`[P2P] Received heartbeat from ${address.slice(0, 8)}`);
    } catch (e) {
      console.log(`[P2P] Heartbeat verification error from ${address.slice(0, 8)}:`, e.message);
    }
  }

  getHeartbeats(ttlMs) {
    const now = Date.now();
    const maxAge = Number(ttlMs || process.env.P2P_HEARTBEAT_TTL_MS || 1800000);
    const out = new Map();
    for (const [addr, ts] of this.heartbeats.entries()) {
      if (now - ts <= maxAge) {
        out.set(addr, ts);
      }
    }
    return out;
  }

  getLastHeartbeat(address) {
    return this.heartbeats.get(address.toLowerCase());
  }

  async stop() {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    if (this.node) {
      await this.node.stop();
      console.log('[P2P] LibP2P node stopped');
    }
  }
}

export default LibP2PExchange;
