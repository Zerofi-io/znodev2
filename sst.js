/**
 * Shamir's Secret Sharing (SST) Module
 * 
 * Provides cryptographic primitives for splitting, encrypting, and reconstructing
 * Monero private keys for seamless node replacement in ZNode clusters.
 */

import secrets from 'secrets.js-grempe';
import crypto from 'crypto';
import { ethers } from 'ethers';
import elliptic from 'elliptic';
import fs from 'fs/promises';
import path from 'path';

const ec = new elliptic.ec('secp256k1');

class SSTManager {
  constructor(config = {}) {
    this.enabled = config.enabled || process.env.ENABLE_SST === '1';
    this.threshold = config.threshold || Number(process.env.SST_THRESHOLD) || 7;
    this.totalShares = config.totalShares || Number(process.env.SST_TOTAL_SHARES) || 11;
    this.storageDir = config.storageDir || process.env.SST_STORAGE_DIR || './sst-data';
    this.encScheme = config.encScheme || process.env.SST_ENC_SCHEME || 'eth-ecdh-v1';
    this.storagePassphrase = config.storagePassphrase || process.env.SST_STORAGE_PASSPHRASE || process.env.MONERO_WALLET_PASSWORD;
    this.pbkdf2Iterations = config.pbkdf2Iterations || Number(process.env.SST_PBKDF2_ITERATIONS) || 600000;
    
    if (this.enabled && !this.storagePassphrase) {
      throw new Error('SST enabled but no storage passphrase configured (SST_STORAGE_PASSPHRASE or MONERO_WALLET_PASSWORD)');
    }
  }

  /**
   * Split a secret into Shamir shares
   * @param {string} secret - Hex-encoded secret to split
   * @returns {Array<string>} Array of hex-encoded shares
   */
  splitSecret(secret) {
    if (!secret || typeof secret !== 'string') {
      throw new Error('Secret must be a non-empty string');
    }

    const secretHex = secret.startsWith('0x') ? secret.slice(2) : secret;
    
    const shares = secrets.share(secretHex, this.totalShares, this.threshold);
    
    return shares;
  }

  /**
   * Combine Shamir shares to reconstruct the secret
   * @param {Array<string>} shares - Array of hex-encoded shares (at least threshold)
   * @returns {string} Reconstructed hex-encoded secret
   */
  combineShares(shares) {
    if (!Array.isArray(shares) || shares.length < this.threshold) {
      throw new Error(`Need at least ${this.threshold} shares to reconstruct secret`);
    }

    const secret = secrets.combine(shares.slice(0, this.threshold));
    
    return secret;
  }

  /**
   * Derive Ethereum public key from address using a signature
   * @param {string} address - Ethereum address
   * @param {string} message - Message that was signed
   * @param {string} signature - Signature of the message
   * @returns {string} Uncompressed public key (0x04...)
   */
  recoverPublicKey(address, message, signature) {
    const messageHash = ethers.hashMessage(message);
    const recoveredAddress = ethers.recoverAddress(messageHash, signature);
    
    if (recoveredAddress.toLowerCase() !== address.toLowerCase()) {
      throw new Error('Signature does not match address');
    }

    const sig = ethers.Signature.from(signature);
    const publicKey = ethers.SigningKey.recoverPublicKey(messageHash, sig);
    
    return publicKey;
  }

  /**
   * Encrypt data for a specific recipient using ECDH + AES-256-GCM
   * @param {string} data - Hex-encoded data to encrypt
   * @param {string} recipientPublicKey - Recipient's uncompressed public key (0x04...)
   * @returns {Object} Encrypted envelope with iv, authTag, ephemeralPublicKey, ciphertext
   */
  encryptForRecipient(data, recipientPublicKey) {
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

    const salt = Buffer.from('znode-sst-v1', 'utf8');
    const info = Buffer.from('aes-256-gcm', 'utf8');
    const aesKey = this._hkdf(sharedSecret, salt, info, 32);

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    
    const dataBuffer = Buffer.from(data.startsWith('0x') ? data.slice(2) : data, 'hex');
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

  /**
   * Decrypt data encrypted for this node using ECDH + AES-256-GCM
   * @param {Object} envelope - Encrypted envelope
   * @param {string} privateKey - This node's Ethereum private key
   * @returns {string} Decrypted hex-encoded data
   */
  decryptForSelf(envelope, privateKey) {
    const { ephemeralPublicKey, iv, authTag, ciphertext } = envelope;

    const ephemeralKeyHex = ephemeralPublicKey.slice(2);
    const ephemeralKey = ec.keyFromPublic(ephemeralKeyHex, 'hex');
    
    const validation = ephemeralKey.validate();
    if (!validation.result) {
      throw new Error('Invalid ephemeral public key: not on secp256k1 curve');
    }

    const privKeyHex = privateKey.startsWith('0x') ? privateKey.slice(2) : privateKey;
    const ourKey = ec.keyFromPrivate(privKeyHex, 'hex');

    const sharedPoint = ourKey.derive(ephemeralKey.getPublic());
    const sharedSecret = Buffer.from(sharedPoint.toArray('be', 32));

    const salt = Buffer.from('znode-sst-v1', 'utf8');
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

    return '0x' + plaintext.toString('hex');
  }

  /**
   * HKDF key derivation function
   * @private
   */
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

  /**
   * Create a signed share envelope
   * @param {Object} params - Share parameters
   * @returns {Object} Signed envelope
   */
  createShareEnvelope(params) {
    const {
      clusterId,
      ownerAddress,
      recipientAddress,
      shareIndex,
      encryptedShare,
      privateKey,
      timestamp = Date.now()
    } = params;

    const nonce = '0x' + crypto.randomBytes(16).toString('hex');

    const message = JSON.stringify({
      type: 'sst/share',
      clusterId,
      ownerAddress: ownerAddress.toLowerCase(),
      recipientAddress: recipientAddress.toLowerCase(),
      shareIndex,
      totalShares: this.totalShares,
      threshold: this.threshold,
      ephemeralPublicKey: encryptedShare.ephemeralPublicKey,
      iv: encryptedShare.iv,
      authTag: encryptedShare.authTag,
      ciphertext: encryptedShare.ciphertext,
      timestamp,
      nonce
    });

    const digest = ethers.hashMessage(message);
    const signingKey = new ethers.SigningKey(privateKey);
    const signature = signingKey.sign(digest).serialized;

    return {
      ...JSON.parse(message),
      signature
    };
  }

  /**
   * Verify a share envelope signature
   * @param {Object} envelope - Share envelope
   * @returns {boolean} True if signature is valid
   */
  verifyShareEnvelope(envelope) {
    const {
      type,
      clusterId,
      ownerAddress,
      recipientAddress,
      shareIndex,
      totalShares,
      threshold,
      ephemeralPublicKey,
      iv,
      authTag,
      ciphertext,
      timestamp,
      nonce,
      signature
    } = envelope;

    const now = Date.now();
    if (Math.abs(now - timestamp) > 5 * 60 * 1000) {
      throw new Error('Share envelope timestamp too old or in future');
    }

    const message = JSON.stringify({
      type,
      clusterId,
      ownerAddress: ownerAddress.toLowerCase(),
      recipientAddress: recipientAddress.toLowerCase(),
      shareIndex,
      totalShares,
      threshold,
      ephemeralPublicKey,
      iv,
      authTag,
      ciphertext,
      timestamp,
      nonce
    });

    const recoveredAddress = ethers.verifyMessage(message, signature);
    
    if (recoveredAddress.toLowerCase() !== ownerAddress.toLowerCase()) {
      throw new Error('Share envelope signature verification failed');
    }

    return true;
  }

  /**
   * Store encrypted share to disk
   * @param {string} clusterId - Cluster ID
   * @param {Object} envelope - Share envelope
   */
  async storeShare(clusterId, envelope) {
    const { ownerAddress, shareIndex } = envelope;
    
    if (!clusterId || typeof clusterId !== 'string' || clusterId.includes('..') || clusterId.includes('/')) {
      throw new Error('Invalid clusterId for storage');
    }
    if (!ownerAddress || typeof ownerAddress !== 'string' || ownerAddress.includes('..') || ownerAddress.includes('/')) {
      throw new Error('Invalid ownerAddress for storage');
    }
    
    const clusterDir = path.join(this.storageDir, `cluster-${clusterId.slice(2, 10)}`);
    const sharesDir = path.join(clusterDir, 'shares');
    
    const resolvedPath = path.resolve(sharesDir);
    const resolvedStorageDir = path.resolve(this.storageDir);
    if (!resolvedPath.startsWith(resolvedStorageDir)) {
      throw new Error('Path traversal attempt detected in SST storage');
    }
    
    await fs.mkdir(sharesDir, { recursive: true, mode: 0o700 });

    const envelopeJson = JSON.stringify(envelope);
    const encrypted = this._encryptStorage(envelopeJson);

    const filename = `${ownerAddress.toLowerCase()}-share-${shareIndex}.json.enc`;
    const filepath = path.join(sharesDir, filename);
    await fs.writeFile(filepath, JSON.stringify(encrypted), { mode: 0o600 });

    await this._updateMetadata(clusterDir, {
      clusterId,
      lastUpdated: Date.now(),
      shareCount: (await fs.readdir(sharesDir)).length
    });
  }

  /**
   * Load encrypted share from disk
   * @param {string} clusterId - Cluster ID
   * @param {string} ownerAddress - Owner address
   * @param {number} shareIndex - Share index
   * @returns {Object} Share envelope
   */
  async loadShare(clusterId, ownerAddress, shareIndex) {
    const clusterDir = path.join(this.storageDir, `cluster-${clusterId.slice(2, 10)}`);
    const sharesDir = path.join(clusterDir, 'shares');
    const filename = `${ownerAddress.toLowerCase()}-share-${shareIndex}.json.enc`;
    const filepath = path.join(sharesDir, filename);

    const encryptedData = await fs.readFile(filepath, 'utf8');
    const encrypted = JSON.parse(encryptedData);
    const envelopeJson = this._decryptStorage(encrypted);
    
    return JSON.parse(envelopeJson);
  }

  /**
   * Load all shares for a specific owner
   * @param {string} clusterId - Cluster ID
   * @param {string} ownerAddress - Owner address
   * @returns {Array<Object>} Array of share envelopes
   */
  async loadSharesForOwner(clusterId, ownerAddress) {
    const clusterDir = path.join(this.storageDir, `cluster-${clusterId.slice(2, 10)}`);
    const sharesDir = path.join(clusterDir, 'shares');
    
    try {
      const files = await fs.readdir(sharesDir);
      const ownerFiles = files.filter(f => 
        f.startsWith(ownerAddress.toLowerCase()) && f.endsWith('.json.enc')
      );

      const shares = [];
      for (const file of ownerFiles) {
        const filepath = path.join(sharesDir, file);
        const encryptedData = await fs.readFile(filepath, 'utf8');
        const encrypted = JSON.parse(encryptedData);
        const envelopeJson = this._decryptStorage(encrypted);
        shares.push(JSON.parse(envelopeJson));
      }

      return shares;
    } catch (error) {
      if (error.code === 'ENOENT') {
        return [];
      }
      throw error;
    }
  }

  /**
   * Encrypt data for storage using passphrase
   * @private
   */
  _encryptStorage(data) {
    const salt = crypto.randomBytes(32);
    const key = crypto.pbkdf2Sync(this.storagePassphrase, salt, this.pbkdf2Iterations, 32, 'sha256');

    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([
      cipher.update(Buffer.from(data, 'utf8')),
      cipher.final()
    ]);
    const authTag = cipher.getAuthTag();

    key.fill(0);

    return {
      version: 1,
      salt: salt.toString('hex'),
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
      ciphertext: ciphertext.toString('hex')
    };
  }

  /**
   * Decrypt data from storage using passphrase
   * @private
   */
  _decryptStorage(encrypted) {
    const { salt, iv, authTag, ciphertext } = encrypted;

    const saltBuffer = Buffer.from(salt, 'hex');
    const key = crypto.pbkdf2Sync(this.storagePassphrase, saltBuffer, this.pbkdf2Iterations, 32, 'sha256');

    const ivBuffer = Buffer.from(iv, 'hex');
    const authTagBuffer = Buffer.from(authTag, 'hex');
    const ciphertextBuffer = Buffer.from(ciphertext, 'hex');

    const decipher = crypto.createDecipheriv('aes-256-gcm', key, ivBuffer);
    decipher.setAuthTag(authTagBuffer);

    const plaintext = Buffer.concat([
      decipher.update(ciphertextBuffer),
      decipher.final()
    ]);

    key.fill(0);

    return plaintext.toString('utf8');
  }

  /**
   * Update cluster metadata
   * @private
   */
  async _updateMetadata(clusterDir, metadata) {
    const metadataPath = path.join(clusterDir, 'metadata.json');
    let existing = {};
    
    try {
      const data = await fs.readFile(metadataPath, 'utf8');
      existing = JSON.parse(data);
    } catch {
    }

    const updated = { ...existing, ...metadata };
    await fs.writeFile(metadataPath, JSON.stringify(updated, null, 2), { mode: 0o600 });
  }
}

export default SSTManager;
