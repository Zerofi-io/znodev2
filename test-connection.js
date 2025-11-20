// Simple smoke test for Ethereum and Monero RPC connectivity

import { JsonRpcProvider } from 'ethers';
import axios from 'axios';

async function main() {
  const rpcUrl = process.env.RPC_URL || process.env.ETH_RPC_URL;
  const moneroUrl = (process.env.MONERO_RPC_URL || 'http://127.0.0.1:18083') + '/json_rpc';
  
  if (!rpcUrl) {
    console.error('[test] ERROR: RPC_URL environment variable is required');
    process.exit(1);
  }

  console.log('[test] Using Ethereum RPC URL:', rpcUrl);
  console.log('[test] Using Monero RPC URL:', moneroUrl);

  // Ethereum provider construction
  try {
    const provider = new JsonRpcProvider(rpcUrl);
    const network = await provider.getNetwork();
    console.log('[test] Ethereum network:', network.name || network.chainId);
  } catch (e) {
    console.error('[test] Ethereum RPC check failed:', e.message || e);
    process.exitCode = 1;
  }

  // Monero get_version
  try {
    const res = await axios.post(moneroUrl, {
      jsonrpc: '2.0',
      id: 1,
      method: 'get_version'
    }, { timeout: 5000 });
    console.log('[test] Monero RPC get_version result:', res.data && res.data.result);
  } catch (e) {
    const msg = e.response ? `${e.response.status} ${e.response.statusText}` : (e.message || e);
    console.error('[test] Monero RPC check failed:', msg);
    process.exitCode = 1;
  }

  if (process.exitCode && process.exitCode !== 0) {
    console.error('[test] One or more checks failed.');
  } else {
    console.log('[test] All connectivity checks passed.');
  }
}

main().catch((e) => {
  console.error('[test] Unexpected error:', e.message || e);
  process.exit(1);
});
