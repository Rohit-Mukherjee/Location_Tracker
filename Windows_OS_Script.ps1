# =======================
# Insider Threat Locator - Full PowerShell Script
# =======================

# Requires Admin Privileges
# Features:
# - Detect Public IP & IP-based Location
# - Scan Nearby Wi-Fi Networks (BSSID, SSID, Signal)
# - Mozilla Geolocation API (if available)
# - Offline fallback based on known BSSID list
# - Spoofing Detection (VPN, KVM, Location mismatch)

# -----------------------
# CONFIG
# -----------------------
$MozillaAPI = "https://location.services.mozilla.com/v1/geolocate?key=geoclue"

# Optional: Offline known BSSID mapping
$OfflineBSSIDMap = @{
    "68:34:21:CB:C2:01" = @{ Lat = 28.6139; Lon = 77.2090; Location = "New Delhi, India" }
    "00:11:22:33:44:55" = @{ Lat = 40.7128; Lon = -74.0060; Location = "New York, USA" }
    "F4:92:BF:AB:CD:EF" = @{ Lat = 51.5074; Lon = -0.1278; Location = "London, UK" }
}

# -----------------------
# FUNCTIONS
# -----------------------

function Get-PublicIPInfo {
    try {
        $ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/"
        return $ipInfo
    } catch {
        return $null
    }
}

function Get-NearbyWiFiNetworks {
    $wifiData = @()
    try {
        $interfaces = netsh wlan show interfaces
        $interfaceName = ($interfaces | Select-String "Name\s+:" | ForEach-Object {
            ($_ -split ":")[1].Trim()
        }) | Select-Object -First 1

        if (-not $interfaceName) {
            return @()
        }

        $scanResult = netsh wlan show networks mode=bssid interface="$interfaceName"
        $lines = $scanResult | ForEach-Object { $_.Trim() }

        $currentSSID = ""
        $currentAuth = ""

        for ($i = 0; $i -lt $lines.Count; $i++) {
            $line = $lines[$i]
            if ($line -match "^SSID \d+ : (.+)$") {
                $currentSSID = $matches[1].Trim()
            } elseif ($line -match "^Authentication\s+: (.+)$") {
                $currentAuth = $matches[1].Trim()
            } elseif ($line -match "^BSSID \d+\s+: (.+)$") {
                $bssid = $matches[1].Trim().ToUpper()
                $signalLine = $lines[$i + 1]
                $signal = if ($signalLine -match "Signal\s+: (\d+)%") { $matches[1].Trim() } else { "N/A" }

                $wifiData += [PSCustomObject]@{
                    SSID           = $currentSSID
                    Authentication = $currentAuth
                    BSSID          = $bssid
                    Signal         = $signal
                }
            }
        }
        return $wifiData
    } catch {
        return @()
    }
}

function Get-MozillaGeoLocation ($wifiData) {
    if ($wifiData.Count -eq 0) { return $null }

    $wifiPayload = @{ wifiAccessPoints = @() }
    foreach ($net in $wifiData) {
        $wifiPayload.wifiAccessPoints += @{ macAddress = $net.BSSID; signalStrength = [int]$net.Signal }
    }

    try {
        $json = $wifiPayload | ConvertTo-Json -Depth 5
        $result = Invoke-RestMethod -Method Post -Uri $MozillaAPI -Body $json -ContentType "application/json"
        return $result
    } catch {
        return $null
    }
}

function Get-OfflineLocation ($wifiData) {
    foreach ($net in $wifiData) {
        if ($OfflineBSSIDMap.ContainsKey($net.BSSID)) {
            return $OfflineBSSIDMap[$net.BSSID]
        }
    }
    return $null
}

function Detect-Spoofing ($ipInfo, $mozillaGeo) {
    $flags = @()
    if (-not $mozillaGeo) {
        $flags += "MozillaLocationFailed"
        return $flags
    }
    if ($ipInfo.country -ne $mozillaGeo.location.country -and $mozillaGeo.location.country) {
        $flags += "LocationMismatch"
    }
    if ($ipInfo.org -match "vpn|proxy|cloudflare|digitalocean|linode|aws|azure") {
        $flags += "PossibleVPN"
    }
    if ((Get-WmiObject Win32_ComputerSystem).Model -match "KVM|VirtualBox|VMware") {
        $flags += "KVMDetected"
    }
    return $flags
}

# -----------------------
# MAIN EXECUTION
# -----------------------

$report = @{}
$wifiData = Get-NearbyWiFiNetworks
$report.WiFiNetworksDetected = $wifiData.Count
$report.WiFiNearbyNetworks = $wifiData

$ipInfo = Get-PublicIPInfo
if ($ipInfo) {
    $report.PublicIP = $ipInfo.query
    $report.IPLocation = "$($ipInfo.city), $($ipInfo.regionName), $($ipInfo.country)"
    $report.ISP = $ipInfo.org
    $report.MapsLink_IP = "https://maps.google.com?q=$($ipInfo.lat),$($ipInfo.lon)"
} else {
    $report.PublicIP = "Unavailable"
    $report.IPLocation = "Unavailable"
    $report.MapsLink_IP = "Unavailable"
}

$mozillaResult = Get-MozillaGeoLocation -wifiData $wifiData
if ($mozillaResult) {
    $report.GeoFromWiFi = "Lat: $($mozillaResult.location.lat), Lon: $($mozillaResult.location.lng)"
    $report.GeoAccuracy = "$($mozillaResult.accuracy) meters"
    $report.MapsLink_WiFi = "https://maps.google.com?q=$($mozillaResult.location.lat),$($mozillaResult.location.lng)"
} else {
    $offline = Get-OfflineLocation -wifiData $wifiData
    if ($offline) {
        $report.GeoFromWiFi = "Lat: $($offline.Lat), Lon: $($offline.Lon)"
        $report.GeoAccuracy = "Offline Estimation"
        $report.MapsLink_WiFi = "https://maps.google.com?q=$($offline.Lat),$($offline.Lon)"
    } else {
        $report.GeoFromWiFi = "Mozilla API failed"
        $report.GeoAccuracy = "Unavailable"
        $report.MapsLink_WiFi = "Unavailable"
    }
}

$report.SpoofingIndicators = Detect-Spoofing -ipInfo $ipInfo -mozillaGeo $mozillaResult

# -----------------------
# OUTPUT
# -----------------------

Write-Host "\n========= Insider Threat Locator =========\n" -ForegroundColor Cyan
foreach ($key in $report.Keys) {
    if ($key -eq "WiFiNearbyNetworks") {
        Write-Host "`n${key}:`n" -ForegroundColor Yellow
        foreach ($net in $report[$key]) {
            Write-Host "  SSID: $($net.SSID) | BSSID: $($net.BSSID) | Signal: $($net.Signal)% | Auth: $($net.Authentication)"
        }
    } else {
        Write-Host ("{0,-25}: {1}" -f $key, $report[$key])
    }
}
Write-Host "\n=========================================" -ForegroundColor Cyan
