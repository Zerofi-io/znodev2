/**
 * LibP2P Smoke Test
 * Verifies LibP2P API compatibility with pinned versions
 */

import { createLibp2p } from 'libp2p';
import { tcp } from '@libp2p/tcp';
import { noise } from '@chainsafe/libp2p-noise';
import { mplex } from '@libp2p/mplex';
import { gossipsub } from '@libp2p/gossipsub';
import { kadDHT } from '@libp2p/kad-dht';
import { mdns } from '@libp2p/mdns';
import { identify } from '@libp2p/identify';
import { ping } from '@libp2p/ping';
import { createEd25519PeerId } from '@libp2p/peer-id-factory';
import crypto from 'crypto';

async function testLibP2P() {
  console.log('[test-libp2p] Starting LibP2P smoke test...');
  
  let node = null;
  
  try {
    console.log('[test-libp2p] Generating peer ID...');
    const peerId = await createEd25519PeerId();
    console.log('[test-libp2p] ✓ Peer ID generated');
    
    console.log('[test-libp2p] Creating LibP2P node...');
    node = await createLibp2p({
      peerId,
      addresses: {
        listen: ['/ip4/127.0.0.1/tcp/0']
      },
      transports: [tcp()],
      streamMuxers: [mplex()],
      connectionEncryption: [noise()],
      services: {
        identify: identify(),
        ping: ping(),
        pubsub: gossipsub({
          emitSelf: true,
          canRelayMessage: true,
          allowPublishToZeroTopicPeers: true,
          msgIdFn: (msg) => {
            return crypto.createHash('sha256').update(msg.data).digest();
          }
        }),
        dht: kadDHT({
          clientMode: false
        })
      },
      peerDiscovery: [mdns()]
    });
    console.log('[test-libp2p] ✓ LibP2P node created');
    
    console.log('[test-libp2p] Starting node...');
    await node.start();
    console.log('[test-libp2p] ✓ Node started');
    
    console.log('[test-libp2p] Testing services access...');
    if (!node.services) {
      throw new Error('node.services is undefined');
    }
    if (!node.services.pubsub) {
      throw new Error('node.services.pubsub is undefined');
    }
    if (!node.services.identify) {
      throw new Error('node.services.identify is undefined');
    }
    if (!node.services.dht) {
      throw new Error('node.services.dht is undefined');
    }
    console.log('[test-libp2p] ✓ Services accessible');
    
    console.log('[test-libp2p] Testing pubsub subscribe...');
    const testTopic = '/test/topic';
    node.services.pubsub.subscribe(testTopic);
    console.log('[test-libp2p] ✓ Subscribed to topic');
    
    console.log('[test-libp2p] Testing pubsub getSubscribers...');
    const subscribers = node.services.pubsub.getSubscribers(testTopic);
    if (!Array.isArray(subscribers)) {
      throw new Error('getSubscribers did not return an array');
    }
    console.log('[test-libp2p] ✓ getSubscribers works (returned array)');
    
    console.log('[test-libp2p] Testing pubsub addEventListener...');
    node.services.pubsub.addEventListener('message', (_evt) => {
      console.log('[test-libp2p] ✓ Message event received');
    });
    console.log('[test-libp2p] ✓ addEventListener works');
    
    console.log('[test-libp2p] Testing pubsub publish...');
    const testMessage = new TextEncoder().encode('test message');
    await node.services.pubsub.publish(testTopic, testMessage);
    console.log('[test-libp2p] ✓ Published message');
    
    await new Promise(resolve => setTimeout(resolve, 100));
    
    console.log('[test-libp2p] Testing pubsub unsubscribe...');
    node.services.pubsub.unsubscribe(testTopic);
    console.log('[test-libp2p] ✓ Unsubscribed from topic');
    
    console.log('[test-libp2p] Testing getMultiaddrs...');
    const addrs = node.getMultiaddrs();
    if (!Array.isArray(addrs)) {
      throw new Error('getMultiaddrs did not return an array');
    }
    console.log('[test-libp2p] ✓ getMultiaddrs works (returned array with', addrs.length, 'addresses)');
    
    console.log('[test-libp2p] Testing getConnections...');
    const connections = node.getConnections();
    if (!Array.isArray(connections)) {
      throw new Error('getConnections did not return an array');
    }
    console.log('[test-libp2p] ✓ getConnections works (returned array with', connections.length, 'connections)');
    
    console.log('[test-libp2p] Stopping node...');
    await node.stop();
    console.log('[test-libp2p] ✓ Node stopped');
    
    console.log('\n[test-libp2p] ✅ All LibP2P API tests passed!');
    console.log('[test-libp2p] LibP2P version compatibility verified.');
    process.exit(0);
    
  } catch (error) {
    console.error('\n[test-libp2p] ❌ LibP2P smoke test failed:', error.message);
    console.error('[test-libp2p] Stack trace:', error.stack);
    
    if (node) {
      try {
        await node.stop();
      } catch (stopError) {
        console.error('[test-libp2p] Error stopping node:', stopError.message);
      }
    }
    
    process.exit(1);
  }
}

testLibP2P();
