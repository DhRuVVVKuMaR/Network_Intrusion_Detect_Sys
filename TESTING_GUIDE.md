# NIDS Testing Guide

This guide explains how to test your Network Intrusion Detection System to verify it's working properly.

## Prerequisites

1. **NIDS must be running** - Start the main system first:
   ```powershell
   python main.py
   ```

2. **Dashboard should be accessible** - Open http://localhost:5000 in your browser

3. **Run tests from a separate terminal** - Keep NIDS running, open a new terminal for tests

## Quick Start

### Option 1: Run All Tests Automatically
```powershell
python test_threats.py --all
```

### Option 2: Interactive Menu (Recommended)
```powershell
python test_threats.py
```
Then select tests from the menu.

## Test Scenarios

### Test 1: Port Scanning
**What it does:** Scans multiple ports rapidly (exceeds threshold of 10 ports in 60 seconds)

**Expected Alert:**
- Type: `PORT_SCAN`
- Severity: `HIGH`
- Message: "Port scan detected from [IP]: X unique ports in Y seconds"

**How to verify:**
- Check dashboard "Recent Alerts" section
- Should see red HIGH severity alert
- Detection Statistics should show increased alert count

---

### Test 2: Suspicious Ports
**What it does:** Attempts connections to known suspicious ports (23, 135, 139, 445, 1433, 3389, etc.)

**Expected Alerts:**
- Type: `SUSPICIOUS_PORT`
- Severity: `MEDIUM`
- Message: "Connection to suspicious port X from [IP]"

**How to verify:**
- Check dashboard for MEDIUM severity alerts (yellow/orange)
- Multiple alerts should appear (one per suspicious port)

---

### Test 3: Suspicious Payload
**What it does:** Sends packets containing known attack patterns (SQL injection, XSS, command injection)

**Expected Alerts:**
- Type: `SUSPICIOUS_PAYLOAD`
- Severity: `HIGH`
- Message: "Suspicious pattern detected in payload from [IP]"

**How to verify:**
- Check dashboard for HIGH severity alerts
- Pattern should be mentioned in alert details

---

### Test 4: High Traffic Rate
**What it does:** Sends packets at a very high rate (exceeds normal baseline)

**Expected Alert:**
- Type: `ANOMALOUS_TRAFFIC_RATE`
- Severity: `HIGH`
- Message: "Unusual traffic rate from [IP]: X packets/min"

**How to verify:**
- Wait 10-15 seconds after test completes
- Anomaly detection needs time to analyze
- Check dashboard for traffic rate alert

---

### Test 5: Connection Flood
**What it does:** Creates many connections rapidly (exceeds MAX_CONNECTIONS_PER_IP = 100)

**Expected Alert:**
- Type: `CONNECTION_FLOOD`
- Severity: `HIGH`
- Message: "Connection flood detected from [IP]: X connections"

**How to verify:**
- Should trigger immediately
- Check dashboard for connection flood alert

---

### Test 6: Anomalous Packet Size
**What it does:** Sends packets with unusual sizes (very small or very large)

**Expected Alerts:**
- Type: `ANOMALOUS_PACKET_SIZE`
- Severity: `MEDIUM`
- Message: "Unusual packet size detected: X bytes (z-score: Y)"

**How to verify:**
- May take a moment to trigger (needs baseline)
- Check dashboard for packet size anomalies

---

### Test 7: Mixed Attack
**What it does:** Combines multiple attack types in one test

**Expected Alerts:**
- Multiple alert types
- PORT_SCAN, SUSPICIOUS_PORT, SUSPICIOUS_PAYLOAD

**How to verify:**
- Check dashboard for multiple different alert types
- Alert count should increase significantly

## Testing Checklist

After running tests, verify:

- [ ] Dashboard shows "Connected" status (green)
- [ ] Capture Statistics show increasing packet counts
- [ ] Detection Statistics show alerts being generated
- [ ] Recent Alerts section displays new alerts
- [ ] Alert Severity counters increase
- [ ] Alerts appear in real-time (within 2-5 seconds)
- [ ] Console shows alert messages

## Troubleshooting

### No Alerts Appearing

1. **Check if NIDS is capturing packets:**
   - Look at "Total Packets" in dashboard
   - If it's 0, packet capture isn't working
   - **Solution:** Run NIDS as Administrator

2. **Check WebSocket connection:**
   - Status should show "Connected" (green)
   - If "Disconnected", refresh the page

3. **Check console logs:**
   - Look at the terminal running `main.py`
   - Should see "ALERT:" messages

4. **Verify test is running:**
   - Check test script output
   - Should see "[TEST X] Starting..." messages

### Alerts Appear But Dashboard Not Updating

1. **Hard refresh browser:** `Ctrl + F5`
2. **Check browser console:** Press F12, look for errors
3. **Check WebSocket:** Status should be "Connected"

### Port Scan Not Detected

- Port scan detection needs 10+ unique ports in 60 seconds
- Make sure test scans enough ports
- Wait a moment for detection to trigger

### Anomaly Detection Not Working

- Anomaly detection needs baseline (100+ packets)
- Let NIDS run for a minute first
- Then run high traffic rate test
- May take 10-15 seconds to analyze

## Advanced Testing

### Custom Test Script

You can create your own test by modifying `test_threats.py`:

```python
def my_custom_test():
    # Your test code here
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((TARGET_HOST, 8080))
    sock.send(b"Suspicious data here")
    sock.close()
```

### Testing Against Remote Host

Edit `test_threats.py` and change:
```python
TARGET_HOST = "192.168.1.100"  # Your target IP
```

### Testing Specific Ports

Modify the port lists in test functions to target specific services.

## Expected Results Summary

| Test | Alert Type | Severity | Detection Time |
|------|-----------|----------|----------------|
| Port Scan | PORT_SCAN | HIGH | Immediate |
| Suspicious Ports | SUSPICIOUS_PORT | MEDIUM | Immediate |
| Suspicious Payload | SUSPICIOUS_PAYLOAD | HIGH | Immediate |
| High Traffic Rate | ANOMALOUS_TRAFFIC_RATE | HIGH | 10-15 seconds |
| Connection Flood | CONNECTION_FLOOD | HIGH | Immediate |
| Anomalous Packet Size | ANOMALOUS_PACKET_SIZE | MEDIUM | 5-10 seconds |
| Mixed Attack | Multiple | Various | Immediate |

## Next Steps

After testing:

1. Review all alerts in dashboard
2. Check alert details and timestamps
3. Verify statistics are updating correctly
4. Test with real network traffic
5. Adjust detection thresholds in `config.py` if needed

## Notes

- Some tests may fail if target ports are filtered by firewall
- Anomaly detection requires baseline establishment
- All tests use localhost (127.0.0.1) by default
- Tests are designed to be safe and non-destructive




