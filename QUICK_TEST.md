# Quick Test Guide - NIDS Testing

## 🚀 Quick Start (3 Steps)

### Step 1: Make sure NIDS is running
Your NIDS should already be running. If not:
```powershell
python main.py
```
Keep this terminal open!

### Step 2: Open Dashboard
Open your browser and go to: **http://localhost:5000**

### Step 3: Run Tests
Open a **NEW** PowerShell terminal and run:

```powershell
cd D:\network_intrusion_detection_system
python test_threats.py
```

## 📋 What to Expect

### Interactive Menu
You'll see a menu like this:
```
============================================================
NIDS Threat Testing Menu
============================================================
1. Port Scan
2. Suspicious Ports
3. Suspicious Payload
4. High Traffic Rate
5. Connection Flood
6. Anomalous Packet Size
7. Mixed Attack
8. Run All Tests
0. Exit
============================================================
```

### Recommended Test Order

1. **Start with Test 1 (Port Scan)** - Easiest to verify
   - Select `1` and press Enter
   - Should see alert within 2-5 seconds

2. **Then Test 2 (Suspicious Ports)**
   - Select `2` and press Enter
   - Multiple alerts should appear

3. **Run All Tests**
   - Select `8` to run everything
   - Watch dashboard update in real-time

## ✅ Verification Checklist

After running tests, check your dashboard:

- [ ] **Connection Status**: Should show "Connected" (green)
- [ ] **Total Packets**: Should be increasing
- [ ] **Total Alerts**: Should show alert count > 0
- [ ] **Recent Alerts**: Should show new alerts appearing
- [ ] **Alert Severity**: High/Medium counters should increase

## 🎯 What Each Test Does

| Test | What It Does | Expected Alert |
|------|-------------|----------------|
| **Port Scan** | Scans 25+ ports rapidly | PORT_SCAN (HIGH) |
| **Suspicious Ports** | Connects to known bad ports | SUSPICIOUS_PORT (MEDIUM) |
| **Suspicious Payload** | Sends attack patterns | SUSPICIOUS_PAYLOAD (HIGH) |
| **High Traffic Rate** | Sends packets very fast | ANOMALOUS_TRAFFIC_RATE (HIGH) |
| **Connection Flood** | Creates 150 connections | CONNECTION_FLOOD (HIGH) |
| **Anomalous Packet Size** | Sends unusual sized packets | ANOMALOUS_PACKET_SIZE (MEDIUM) |
| **Mixed Attack** | Combines multiple attacks | Multiple alert types |

## 🔍 Where to Look

1. **Dashboard Main Page**: See all statistics
2. **Recent Alerts Section**: See individual alerts
3. **Console (Terminal running main.py)**: See alert logs
4. **Browser Console (F12)**: See WebSocket connection status

## ⚠️ Troubleshooting

**No alerts appearing?**
- Make sure NIDS is running as Administrator
- Check "Total Packets" - if 0, packet capture isn't working
- Wait 10-15 seconds for anomaly detection

**Dashboard not updating?**
- Refresh browser (Ctrl + F5)
- Check connection status is "Connected"
- Check browser console (F12) for errors

**Test script errors?**
- Make sure you're in the project directory
- Check that requests library is installed: `pip install requests`

## 🎬 Example Test Run

```
Select test to run: 1

[TEST 1] Starting Port Scan Test...
This should trigger a PORT_SCAN alert (HIGH severity)
[TEST 1] Scanned 25 ports - Check dashboard for PORT_SCAN alert
✓ Port Scan test completed
```

Then check dashboard - you should see a red HIGH severity alert!

## 💡 Pro Tips

1. **Run tests one at a time** first to understand each alert type
2. **Watch the dashboard** while tests run to see real-time updates
3. **Check the console** running main.py to see alert messages
4. **Use "Run All Tests"** after understanding individual tests

## 📚 More Information

See `TESTING_GUIDE.md` for detailed information about each test.




