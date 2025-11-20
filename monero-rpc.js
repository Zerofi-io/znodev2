/**
 * Monero RPC Client for Wallet Operations
 */

import axios from 'axios';
import http from 'http';
import https from 'https';
import crypto from 'crypto';

class MoneroRPC {
  constructor(config = {}) {
    this._lastWallet = null;
    this.url = config.url || process.env.MONERO_RPC_URL || process.env.MONERO_WALLET_RPC_URL || 'http://127.0.0.1:18083';
    this.user = config.user || process.env.MONERO_WALLET_RPC_USER;
    this.password = config.password || process.env.MONERO_WALLET_RPC_PASSWORD;
    
    this.httpAgent = new http.Agent({ 
      keepAlive: true, 
      maxSockets: 20,
      keepAliveMsecs: 30000
    });
    this.httpsAgent = new https.Agent({ 
      keepAlive: true,
      maxSockets: 20,
      keepAliveMsecs: 30000
    });
  }

  async call(method, params = {}, timeout = 180000) {
    const baseUrl = this.url.endsWith('/') ? this.url.slice(0, -1) : this.url;
    const requestUrl = `${baseUrl}/json_rpc`;
    const urlObj = new URL(requestUrl);
    const uri = urlObj.pathname + (urlObj.search || '');
    const body = {
      jsonrpc: '2.0',
      id: '0',
      method,
      params
    };

    const axiosConfig = {
      timeout,
      httpAgent: this.httpAgent,
      httpsAgent: this.httpsAgent
    };

    try {
      let response;
      if (this.user && this.password) {
        response = await this._postWithAuth(requestUrl, uri, body, axiosConfig);
      } else {
        response = await axios.post(requestUrl, body, {
          ...axiosConfig,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      if (response.status === 401) {
        throw new Error('HTTP 401: Unauthorized');
      }
      if (response.status < 200 || response.status >= 300) {
        throw new Error(`HTTP ${response.status}: ${response.statusText || 'Unknown error'}`);
      }

      if (response.data && response.data.error) {
        throw new Error(`RPC Error: ${response.data.error.message}`);
      }

      return response.data.result;
    } catch (error) {
      if (error.response) {
        throw new Error(`HTTP ${error.response.status}: ${error.response.statusText}`);
      }
      throw error;
    }
  }

  async _postWithAuth(url, uri, body, axiosConfig) {
    // First request to detect auth scheme (401)
    const initialResponse = await axios.post(url, body, {
      ...axiosConfig,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: status => (status === 401 || (status >= 200 && status < 300))
    });

    if (initialResponse.status !== 401) {
      return initialResponse;
    }

    const wwwAuth = initialResponse.headers['www-authenticate'] || initialResponse.headers['WWW-Authenticate'];
    if (!wwwAuth) {
      throw new Error('HTTP 401: Unauthorized (no WWW-Authenticate header)');
    }

    if (/^basic\s+/i.test(wwwAuth)) {
      const response = await axios.post(url, body, {
        ...axiosConfig,
        headers: { 'Content-Type': 'application/json' },
        auth: {
          username: this.user,
          password: this.password
        },
        validateStatus: status => status < 500
      });
      return response;
    } else if (/^digest\s+/i.test(wwwAuth)) {
      const challenge = this._parseDigestChallenge(wwwAuth);
      const authHeader = this._buildDigestAuthHeader(challenge, {
        method: 'POST',
        uri,
        username: this.user,
        password: this.password
      });

      const response = await axios.post(url, body, {
        ...axiosConfig,
        headers: {
          'Content-Type': 'application/json',
          Authorization: authHeader
        },
        validateStatus: status => status < 500
      });
      return response;
    } else {
      throw new Error(`HTTP 401: Unsupported authentication scheme: ${wwwAuth.split(' ')[0]}`);
    }
  }

  async _postWithDigestAuth(url, uri, body, axiosConfig) {
    // First request to get Digest challenge (401)
    const initialResponse = await axios.post(url, body, {
      ...axiosConfig,
      headers: { 'Content-Type': 'application/json' },
      validateStatus: status => (status === 401 || (status >= 200 && status < 300))
    });

    if (initialResponse.status !== 401) {
      return initialResponse;
    }

    const wwwAuth = initialResponse.headers['www-authenticate'] || initialResponse.headers['WWW-Authenticate'];
    if (!wwwAuth || !/^digest\s+/i.test(wwwAuth)) {
      throw new Error('HTTP 401: Unauthorized');
    }

    const challenge = this._parseDigestChallenge(wwwAuth);
    const authHeader = this._buildDigestAuthHeader(challenge, {
      method: 'POST',
      uri,
      username: this.user,
      password: this.password
    });

    const response = await axios.post(url, body, {
      ...axiosConfig,
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader
      },
      validateStatus: status => status < 500
    });

    return response;
  }

  _parseDigestChallenge(header) {
    const prefix = /^digest\s+/i;
    const value = header.replace(prefix, '');
    const params = {};
    const regex = /([a-zA-Z0-9_]+)=(("[^"]+")|([^,]+))/g;
    let match;
    while ((match = regex.exec(value)) !== null) {
      const key = match[1];
      let val = match[3] || match[4] || '';
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      params[key] = val;
    }
    return params;
  }

  _md5(str) {
    return crypto.createHash('md5').update(str).digest('hex');
  }

  _buildDigestAuthHeader(challenge, { method, uri, username, password }) {
    const realm = challenge.realm || '';
    const nonce = challenge.nonce || '';
    const qop = challenge.qop || 'auth';
    const opaque = challenge.opaque;
    const algorithm = (challenge.algorithm || 'MD5').toUpperCase();

    const cnonce = crypto.randomBytes(16).toString('hex');
    const nc = '00000001';

    let ha1 = this._md5(`${username}:${realm}:${password}`);
    if (algorithm === 'MD5-SESS') {
      ha1 = this._md5(`${ha1}:${nonce}:${cnonce}`);
    }

    const ha2 = this._md5(`${method}:${uri}`);
    const response = this._md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);

    let header = `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", qop=${qop}, nc=${nc}, cnonce="${cnonce}", response="${response}"`;
    if (opaque) {
      header += `, opaque="${opaque}"`;
    }
    if (algorithm) {
      header += `, algorithm=${algorithm}`;
    }
    return header;
  }
  // Get wallet address
  async getAddress() {
    const result = await this.call('get_address');
    if (!result || typeof result.address !== 'string' || !result.address) {
      throw new Error('Invalid get_address response: missing or invalid address field');
    }
    return result.address;
  }

  // Create new wallet
  async createWallet(filename, password = '') {
    return this.call('create_wallet', {
      filename,
      password,
      language: 'English'
    }, 180000);
  }

  // Close current wallet
  async closeWallet() {
    return this.call('close_wallet', {});
  }

  // Open existing wallet
  async openWallet(filename, password = '') {
    const r = await this.call('open_wallet', {
      filename,
      password
    }, 180000);
    try {
      await this.call('set', { key: 'enable-multisig-experimental', value: 1 });
    } catch { /* ignore */ }
    this._lastWallet = { filename, password };
    return r;
  }

  // Get balance
  async getBalance() {
    const result = await this.call('get_balance');
    return {
      balance: result.balance,
      unlockedBalance: result.unlocked_balance
    };
  }

  // Prepare multisig with extended timeout and retry
  async prepareMultisig() {
    const maxRetries = 3;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        // Use 90s timeout for multisig operations (wallet may be syncing)
        const result = await this.call('prepare_multisig', {}, 180000);
        return result.multisig_info;
      } catch (error) {
        if (attempt === maxRetries) {
          throw new Error(`Failed to prepare multisig after ${maxRetries} attempts: ${error.message}`);
        }
        console.log(`  Retry ${attempt}/${maxRetries} - waiting for wallet sync...`);
        await new Promise(resolve => setTimeout(resolve, 5000));
      }
    }
  }

  // Make multisig (7-of-11)
  async isMultisig() {
    const result = await this.call('is_multisig');
    if (!result || typeof result.multisig !== 'boolean') {
      throw new Error('Invalid is_multisig response: missing or invalid multisig field');
    }
    return result;
  }

  async makeMultisig(multisigInfo, threshold = 7) {
    const result = await this.call('make_multisig', {
      multisig_info: multisigInfo,
      threshold
    }, 180000);
    if (!result || typeof result.address !== 'string' || !result.address) {
      throw new Error('Invalid make_multisig response: missing or invalid address field');
    }
    if (typeof result.multisig_info !== 'string') {
      throw new Error('Invalid make_multisig response: missing or invalid multisig_info field');
    }
    return {
      address: result.address,
      multisigInfo: result.multisig_info
    };
  }

  // Exchange multisig keys
  async exchangeMultisigKeys(multisigInfo, password) {
    try {
      await this.call('set', { key: 'enable-multisig-experimental', value: 1 });
    } catch { /* ignore */ }
    const params = { multisig_info: multisigInfo };
    if (password) params.password = password;
    try {
      const result = await this.call('exchange_multisig_keys', params, 180000);
      return result.multisig_info;
    } catch (e) {
      const msg = (e && e.message) || '';
      if (msg.includes('multisig is disabled') || msg.includes('enable-multisig-experimental')) {
        try {
          if (this._lastWallet) {
            const lw = this._lastWallet || {};
            try { await this.call('open_wallet', { filename: lw.filename, password: lw.password }, 30000); } catch { /* ignore */ }
            try { await this.call('set', { key: 'enable-multisig-experimental', value: 1 }); } catch { /* ignore */ }
          }
          const result2 = await this.call('exchange_multisig_keys', params, 180000);
          return result2.multisig_info;
        } catch (e4) {
          throw e4;
        }
      }
      throw e;
    }
  }

  // Export multisig info
  async exportMultisigInfo() {
    const result = await this.call('export_multisig_info');
    return result.info;
  }

  // Import multisig info
  async importMultisigInfo(info) {
    const result = await this.call('import_multisig_info', {
      info
    });
    return result.n_outputs;
  }

  // Sign multisig transaction
  async signMultisig(txDataHex) {
    const result = await this.call('sign_multisig', {
      tx_data_hex: txDataHex
    });
    return {
      txDataHex: result.tx_data_hex,
      txHashList: result.tx_hash_list
    };
  }

  // Submit multisig transaction
  async submitMultisig(txDataHex) {
    const result = await this.call('submit_multisig', {
      tx_data_hex: txDataHex
    });
    return result.tx_hash_list;
  }

  // Transfer (create unsigned transaction)
  async transfer(destinations, mixinOrRingSize = 16) {
    try {
      const result = await this.call('transfer', {
        destinations,
        ring_size: mixinOrRingSize,
        get_tx_key: true,
        do_not_relay: true
      });
      return {
        txDataHex: result.multisig_txset,
        txHash: result.tx_hash
      };
    } catch (error) {
      const errorMsg = error.message || '';
      const errorCode = error.code || '';
      if (errorMsg.includes('ring_size') || errorMsg.includes('invalid') || errorCode === -32602 || errorMsg.includes('Unknown parameter')) {
        try {
          const result = await this.call('transfer', {
            destinations,
            mixin: mixinOrRingSize,
            get_tx_key: true,
            do_not_relay: true
          });
          return {
            txDataHex: result.multisig_txset,
            txHash: result.tx_hash
          };
        } catch {
          throw error;
        }
      }
      throw error;
    }
  }

  async sweepAll(address, options = {}) {
    const params = {
      address,
      account_index: options.accountIndex || 0,
      subaddr_indices: options.subaddrIndices || undefined,
      priority: options.priority || 0,
      ring_size: options.ringSize || 16,
      get_tx_key: true,
      do_not_relay: options.doNotRelay !== undefined ? options.doNotRelay : true
    };
    
    Object.keys(params).forEach(key => params[key] === undefined && delete params[key]);
    
    try {
      const result = await this.call('sweep_all', params, 180000);
      return {
        txDataHex: result.multisig_txset || result.tx_hash_list,
        txHashList: result.tx_hash_list,
        amountList: result.amount_list,
        feeList: result.fee_list
      };
    } catch (error) {
      const errorMsg = error.message || '';
      const errorCode = error.code || '';
      if (errorMsg.includes('ring_size') || errorMsg.includes('invalid') || errorCode === -32602 || errorMsg.includes('Unknown parameter')) {
        try {
          const paramsWithMixin = { ...params };
          delete paramsWithMixin.ring_size;
          paramsWithMixin.mixin = options.ringSize || 16;
          const result = await this.call('sweep_all', paramsWithMixin, 180000);
          return {
            txDataHex: result.multisig_txset || result.tx_hash_list,
            txHashList: result.tx_hash_list,
            amountList: result.amount_list,
            feeList: result.fee_list
          };
        } catch {
          throw error;
        }
      }
      throw error;
    }
  }

  // Refresh wallet
  async refresh() {
    return this.call('refresh');
  }

  // Query key (spend_key or view_key)
  async queryKey(keyType) {
    const result = await this.call('query_key', {
      key_type: keyType
    });
    return result.key;
  }

  // Finalize multisig
  async finalizeMultisig(exchangedKeys) {
    const params = exchangedKeys ? { multisig_info: exchangedKeys } : {};
    const result = await this.call('finalize_multisig', params, 180000);
    return result;
  }

  // Get height
  async getHeight() {
    const result = await this.call('get_height');
    if (!result || typeof result.height !== 'number') {
      throw new Error('Invalid get_height response: missing or invalid height field');
    }
    return result.height;
  }
}

export default MoneroRPC;
