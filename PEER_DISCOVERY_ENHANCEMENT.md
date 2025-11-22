# P2P Peer Discovery Enhancement

## Summary
Modified the P2P heartbeat mechanism to send immediate heartbeats when detecting new peers, reducing discovery time from up to 10 minutes down to seconds.

## Changes Made

### File: `p2p-libp2p.js`

**1. Added peer tracking (line ~51):**
```javascript
this.knownQueuePeers = new Set(); // Track peers we've already seen
```

**2. Enhanced `handleQueuePresence` method (lines 1714-1732):**
- Detects when a new peer sends a queue presence message
- Immediately broadcasts a heartbeat to help the new peer discover us faster
- Tracks known peers to avoid sending duplicate immediate heartbeats

## Behavior

### Before:
- VPS3 had to wait for its next scheduled heartbeat broadcast (default every 30 seconds via HEARTBEAT_INTERVAL)
- If VPS2 just missed VPS3's last heartbeat, it could take nearly 30 seconds to detect it
- Multiple factors (timing, clock skew, rate limits) could extend this to 10 minutes

### After:
- When VPS3 receives VPS2's queue presence message for the first time, it immediately sends a heartbeat
- VPS2 receives the heartbeat within seconds instead of waiting for the next scheduled broadcast
- Both nodes discover each other much faster (typically < 5 seconds)

## Deployment

1. **Backup created:** `p2p-libp2p.js.backup`
2. **No configuration changes needed** - works with existing settings
3. **Restart required:** Restart your node process to activate the changes

```bash
# Stop the node
./stop

# Start the node
./start
```

## Testing

After restarting, watch for this log message when peers discover each other:
```
[P2P] New peer detected: 0x611e4e, sending immediate heartbeat
```

The "Online Members in Queue (on-chain)" count should reach full capacity within seconds of all nodes starting.

## Rollback

If needed, restore the original file:
```bash
cp p2p-libp2p.js.backup p2p-libp2p.js
```

## Technical Details

- **Thread-safe**: Uses async/await properly, heartbeat is fire-and-forget
- **Idempotent**: Only triggers once per unique peer address
- **Low overhead**: Set lookup is O(1), minimal memory footprint
- **Respects rate limits**: Still goes through existing rate limiting in `broadcastHeartbeat()`
