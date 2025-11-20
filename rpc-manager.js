import path from 'path';
import { execFile } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import axios from 'axios';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

class RPCManager {
  constructor({ url, scriptPath } = {}) {
    this.url = url;
    this._timer = null;
    this.scriptPath = scriptPath || process.env.MONERO_RPC_START_SCRIPT || path.join(__dirname, 'start-monero-rpc.sh');
  }

  async restart(monero, lastWallet) {
    const script = this.scriptPath;
    if (!script) {
      console.warn('[RPCManager] No Monero RPC start script configured; skipping restart.');
    } else {
      await new Promise((resolve) => {
        const child = execFile('bash', [script], { stdio: 'ignore' });
        const timeout = setTimeout(() => {
          try { child.kill('SIGTERM'); } catch {}
          console.error('[RPCManager] Monero RPC start script timed out.');
          resolve();
        }, 30000);

        child.on('exit', (code) => {
          clearTimeout(timeout);
          if (code === 0) {
            console.log('[RPCManager] Monero wallet RPC restart script completed.');
          } else {
            console.error(`[RPCManager] Monero wallet RPC restart script exited with code ${code}.`);
          }
          resolve();
        });

        child.on('error', (err) => {
          clearTimeout(timeout);
          console.error('[RPCManager] Failed to execute Monero RPC start script:', err.message || err);
          resolve();
        });
      });
    }

    // Wait for RPC to become ready before reopening wallet
    if (monero && monero.url) {
      console.log('[RPCManager] Waiting for Monero RPC to become ready...');
      const maxRetries = Number(process.env.RPC_READY_RETRIES || 60);
      const retryInterval = Number(process.env.RPC_READY_INTERVAL_MS || 1000);
      
      for (let i = 0; i < maxRetries; i++) {
        try {
          await axios.post(`${monero.url}/json_rpc`, {
            jsonrpc: '2.0',
            id: '0',
            method: 'get_version',
            params: {}
          }, {
            timeout: 5000,
            auth: monero.user && monero.password ? {
              username: monero.user,
              password: monero.password
            } : undefined
          });
          console.log('[RPCManager] Monero RPC is ready');
          break;
        } catch {
          if (i === maxRetries - 1) {
            console.error(`[RPCManager] Monero RPC did not become ready within ${maxRetries * retryInterval / 1000}s`);
          }
          await new Promise(r => setTimeout(r, retryInterval));
        }
      }
    }

    // Attempt to reopen last wallet if provided
    if (lastWallet) {
      const filename = typeof lastWallet === 'string' ? lastWallet : lastWallet.filename;
      const password = (typeof lastWallet === 'object' && lastWallet.password != null)
        ? lastWallet.password
        : (process.env.MONERO_WALLET_PASSWORD || '');

      if (!filename) {
        console.warn('[RPCManager] lastWallet provided but filename is missing; skipping wallet reopen.');
      } else {
        try {
          await monero.call('open_wallet', { filename, password }, 180000);
          console.log('[RPCManager] Reopened wallet after RPC restart:', filename);
        } catch (e) {
          console.error('[RPCManager] Failed to reopen wallet after RPC restart:', e && e.message ? e.message : e);
        }
      }
    }

    return true;
  }

  startHealthWatch(monero) {
    if (this._timer) return;
    this._timer = setInterval(async () => {
      try {
        await monero.call('get_version', {}, 10000);
      } catch (e) {
        console.error('[RPCManager] Monero RPC health check failed:', e && e.message ? e.message : e);
        // monero.call wrapper will already have attempted a restart on connection errors
      }
    }, 30000);
  }
}

export default RPCManager;
