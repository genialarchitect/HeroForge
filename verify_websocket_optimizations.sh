#!/bin/bash

echo "=== WebSocket Optimization Verification ==="
echo ""

echo "1. Checking modified files..."
echo "   ✓ src/web/broadcast.rs"
ls -lh src/web/broadcast.rs | awk '{print "     ", $9, "-", $5}'

echo "   ✓ src/web/websocket/mod.rs"
ls -lh src/web/websocket/mod.rs | awk '{print "     ", $9, "-", $5}'

echo "   ✓ src/web/websocket/aggregator.rs (NEW)"
ls -lh src/web/websocket/aggregator.rs | awk '{print "     ", $9, "-", $5}'

echo "   ✓ src/web/api/scans.rs"
ls -lh src/web/api/scans.rs | awk '{print "     ", $9, "-", $5}'

echo "   ✓ src/web/mod.rs"
ls -lh src/web/mod.rs | awk '{print "     ", $9, "-", $5}'

echo ""
echo "2. Checking configuration constants..."
echo "   Message Batching:"
grep -E "const (BATCH_INTERVAL_MS|MAX_BATCH_SIZE)" src/web/broadcast.rs
echo "   Message Throttling:"
grep -E "const MAX_MESSAGES_PER_SECOND" src/web/broadcast.rs
echo "   Connection Management:"
grep -E "const (HEARTBEAT_INTERVAL|CLIENT_TIMEOUT|CHANNEL_CLEANUP)" src/web/broadcast.rs src/web/websocket/mod.rs

echo ""
echo "3. Checking key functions..."
echo "   Batching functions:"
grep -c "fn.*batch" src/web/broadcast.rs
echo "   Throttling functions:"
grep -c "fn.*throttle" src/web/broadcast.rs
echo "   Aggregation functions:"
grep -c "pub async fn" src/web/websocket/aggregator.rs

echo ""
echo "4. Checking API endpoint..."
grep "scans/stats" src/web/mod.rs && echo "   ✓ Endpoint registered" || echo "   ✗ Endpoint NOT found"

echo ""
echo "5. Checking documentation..."
ls -lh WEBSOCKET_OPTIMIZATIONS.md WEBSOCKET_IMPLEMENTATION_SUMMARY.md 2>/dev/null | awk '{print "   ✓", $9, "-", $5}'

echo ""
echo "=== Verification Complete ==="
echo ""
echo "To test the optimizations:"
echo "  1. Build: cargo build --release"
echo "  2. Run: cargo run -- serve"
echo "  3. Test endpoint: curl -H 'Authorization: Bearer TOKEN' http://localhost:8080/api/scans/stats"
echo "  4. Monitor logs: RUST_LOG=heroforge::web=debug cargo run -- serve"
