# How to Run the Network Intrusion Detection System

## Prerequisites

1. **Install Python 3.8 or higher**
2. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

3. **Windows-specific requirement:**
   - Install **Npcap** (recommended) or **WinPcap** for packet capture
   - Download from: https://nmap.org/npcap/
   - This is required for Scapy to capture network packets on Windows

## Running the System

### **Option 1: Run as Administrator (Recommended)**

1. **Open PowerShell as Administrator:**
   - Right-click on PowerShell
   - Select "Run as Administrator"

2. **Navigate to project directory:**
   ```powershell
   cd D:\network_intrusion_detection_system
   ```

3. **Run the system:**
   ```powershell
   python main.py
   ```

### **Option 2: Run from Command Prompt**

1. **Open Command Prompt as Administrator:**
   - Press `Win + X`
   - Select "Command Prompt (Admin)" or "Windows PowerShell (Admin)"

2. **Navigate and run:**
   ```cmd
   cd D:\network_intrusion_detection_system
   python main.py
   ```

### **Option 3: Run from IDE (with Admin privileges)**

If using VS Code or another IDE:
1. Right-click on the IDE icon
2. Select "Run as Administrator"
3. Open the project and run `main.py`

## What to Expect

After running, you should see:

```
Starting Network Intrusion Detection System...
Network Interface: [detected interface name]
Signature Detection: Enabled
Anomaly Detection: Enabled
Dashboard available at http://0.0.0.0:5000
NIDS is now running. Press Ctrl+C to stop.
```

## Access the Dashboard

Open your web browser and navigate to:
- **http://localhost:5000**
- **http://127.0.0.1:5000**

## Stopping the System

Press `Ctrl+C` in the terminal to gracefully stop the system.

## Troubleshooting

### Error: "No network interfaces found"
- Make sure you're running as Administrator
- Check that Npcap/WinPcap is installed
- Verify network adapter is active

### Error: "Permission denied" or packet capture fails
- **You MUST run as Administrator on Windows**
- Right-click PowerShell/CMD → "Run as Administrator"

### Error: Module not found
- Install dependencies: `pip install -r requirements.txt`
- Make sure you're in the correct directory

### Dashboard not accessible
- Check if port 5000 is already in use
- Modify `WEB_PORT` in `config.py` if needed
- Check Windows Firewall settings

## Quick Start Command (Copy-Paste Ready)

```powershell
# Run as Administrator
cd D:\network_intrusion_detection_system
python main.py
```




