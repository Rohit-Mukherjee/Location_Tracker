# 🔬 Insider Threat Locator

A cross-platform geolocation and spoofing detection script for use in Insider Threat Investigations via EDR tools. This tool runs on both Windows and macOS, requiring no dependencies, and provides both network-based geolocation and spoofing detection (VPN, VM, and location mismatch).

## ⚙️ Supported Platforms

✅ Windows (PowerShell)

✅ macOS (Bash)


## 🚀 Features

🌐 Public IP and geolocation

📶 Nearby Wi-Fi scanning (SSID, BSSID, Signal Strength)

🛰️ Wi-Fi-based location via Mozilla Location Services API

🧱 Offline BSSID fallback mapping (if API fails)



## 🧬 Spoofing indicators:

VPN or Proxy detection

Virtual machine/KVM detection

Mismatched IP and Wi-Fi locations




## 👤 Windows Usage (PowerShell)

💡 Tested on Windows 10/11, requires administrator privileges and outbound internet access.

🔹 Steps

Download the scriptSave the PowerShell script as insider-threat-locator.ps1

Run it with elevated permissions

```powershell.exe -ExecutionPolicy Bypass -File .\insider-threat-locator.ps1```

OutputThe results are displayed in the console – no data is saved to disk.





## 🍎 macOS Usage (Bash)

💡 Requires admin privileges for Wi-Fi scanning. Works on Monterey and newer. No dependencies required.

🔹 Steps

Download the scriptSave the macOS script as insider-threat-locator.sh

Make it executable

```chmod +x insider-threat-locator.sh```

Run the script

```./insider-threat-locator.sh```

OutputAll results are printed to terminal in a readable format.



## 🔐 Privacy & Ethics

This tool is intended only for authorized use by security analysts or incident responders. Use in compliance with your organization's internal policies and legal regulations.

🗜️ Offline BSSID Fallback

Both scripts support offline geolocation using pre-defined BSSIDs when Mozilla's API is unavailable.

## Sample mapping in macOS version
```OFFLINE_MAP["68:34:21:cb:c2:01"]="28.6139,77.2090,New Delhi, India"```

Extend this list to fit your own organization's network infrastructure.



