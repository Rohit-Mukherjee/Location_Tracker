#!/bin/bash

# =====================
# Insider Threat Locator 
# =====================

# Features:
# - Detect Public IP & Location
# - Scan Nearby Wi-Fi Networks (BSSID, SSID, Signal)
# - Mozilla Geolocation API with Offline fallback
# - Spoofing Detection (VPN, KVM, Location mismatch)

# ----------- FUNCTIONS -----------

get_public_ip_info() {
    ip_json=$(curl -s http://ip-api.com/json)
    pub_ip=$(echo "$ip_json" | awk -F'"' '/query/ {print $4}')
    city=$(echo "$ip_json" | awk -F'"' '/city/ {print $4}')
    region=$(echo "$ip_json" | awk -F'"' '/regionName/ {print $4}')
    country=$(echo "$ip_json" | awk -F'"' '/country/ {print $4}')
    isp=$(echo "$ip_json" | awk -F'"' '/org/ {print $4}')
    lat=$(echo "$ip_json" | awk -F: '/"lat"/ {gsub(/,/, "", $2); print $2}')
    lon=$(echo "$ip_json" | awk -F: '/"lon"/ {gsub(/,/, "", $2); print $2}')

    echo "🌐 Public IP: $pub_ip"
    echo "🌍 IP Location: $city, $region, $country"
    echo "📡 ISP: $isp"
    echo "📍 Google Maps (IP): https://maps.google.com?q=$lat,$lon"

    export IP_LAT="$lat"
    export IP_LON="$lon"
    export IP_COUNTRY="$country"
    export IP_ORG="$isp"
}

get_wifi_bssids() {
    echo ""
    echo "📶 Scanning Nearby Wi-Fi Networks..."

    wifi_info=$(system_profiler SPAirPortDataType 2>/dev/null)
    bssids=$(echo "$wifi_info" | grep "BSSID:" | awk '{print $2}' | tr '[:upper:]' '[:lower:]')
    ssids=$(echo "$wifi_info" | grep "SSID:" | sed -e 's/^ *SSID: //')

    i=0
    wifi_payload=""
    while IFS= read -r bssid && IFS= read -r ssid <&3; do
        strength=$(echo "$wifi_info" | grep -A5 "$bssid" | grep "Signal" | awk '{print $3}' | head -n1)
        wifi_payload+="{\"macAddress\":\"$bssid\",\"signalStrength\":$strength},"
        echo "SSID: $ssid | BSSID: $bssid | Signal: ${strength:-unknown}"
        i=$((i+1))
    done < <(echo "$bssids") 3< <(echo "$ssids")

    wifi_payload=${wifi_payload%,}
    export WIFI_JSON="{\"wifiAccessPoints\":[${wifi_payload}]}"
    export WIFI_COUNT="$i"
    export BSSID_LIST=( $(echo "$bssids") )
}

get_offline_location() {
    declare -A OFFLINE_MAP
    OFFLINE_MAP["68:34:21:cb:c2:01"]="28.6139,77.2090,New Delhi, India"
    OFFLINE_MAP["00:11:22:33:44:55"]="40.7128,-74.0060,New York, USA"
    OFFLINE_MAP["f4:92:bf:ab:cd:ef"]="51.5074,-0.1278,London, UK"

    for bssid in "${BSSID_LIST[@]}"; do
        loc_info="${OFFLINE_MAP[$bssid]}"
        if [[ -n "$loc_info" ]]; then
            lat=$(echo $loc_info | cut -d',' -f1)
            lon=$(echo $loc_info | cut -d',' -f2)
            city=$(echo $loc_info | cut -d',' -f3-)
            echo "📍 Offline Location (Fallback): $lat, $lon"
            echo "📍 Estimated Area: $city"
            echo "📍 Google Maps (Offline): https://maps.google.com?q=$lat,$lon"
            export WIFI_LAT="$lat"
            export WIFI_LON="$lon"
            export GEO_ACC="Offline Estimation"
            export OFFLINE_USED="true"
            return
        fi
    done
    export OFFLINE_USED="false"
}

get_mozilla_geolocation() {
    if [[ -z "$WIFI_JSON" ]]; then
        echo "❌ No Wi-Fi data found for geolocation."
        return
    fi

    echo ""
    echo "📡 Querying Mozilla Geolocation API..."
    geo_response=$(curl -s -X POST "https://location.services.mozilla.com/v1/geolocate?key=geoclue" \
        -H "Content-Type: application/json" \
        -d "$WIFI_JSON")

    lat=$(echo "$geo_response" | awk -F: '/"lat"/ {gsub(/,/, "", $2); print $2}')
    lon=$(echo "$geo_response" | awk -F: '/"lng"/ {gsub(/,/, "", $2); print $2}')
    acc=$(echo "$geo_response" | awk -F: '/"accuracy"/ {gsub(/[^0-9.]*/, "", $2); print $2}')

    if [[ -z "$lat" ]]; then
        echo "❌ Mozilla API failed. Trying offline fallback..."
        export MOZILLA_FAIL="true"
        get_offline_location
        return
    fi

    echo "📍 Mozilla Geo Location: $lat, $lon"
    echo "🎯 Accuracy: $acc meters"
    echo "📍 Google Maps (Wi-Fi): https://maps.google.com?q=$lat,$lon"

    export WIFI_LAT="$lat"
    export WIFI_LON="$lon"
    export GEO_ACC="$acc"
    export MOZILLA_FAIL="false"
    export OFFLINE_USED="false"
}

detect_spoofing() {
    echo ""
    echo "🧬 Checking for Spoofing Indicators..."

    flags=()

    if [[ "$MOZILLA_FAIL" == "true" && "$OFFLINE_USED" != "true" ]]; then
        flags+=("MozillaLocationFailed")
    elif [[ "$IP_COUNTRY" != "" && "$WIFI_LAT" != "" ]]; then
        remote_country=$(curl -s "https://geocode.maps.co/reverse?lat=$WIFI_LAT&lon=$WIFI_LON" | grep country | awk -F'"' '{print $4}')
        if [[ "$remote_country" != "$IP_COUNTRY" && "$remote_country" != "" ]]; then
            flags+=("LocationMismatch")
        fi
    fi

    if [[ "$IP_ORG" =~ vpn|proxy|cloudflare|digitalocean|linode|aws|azure ]]; then
        flags+=("PossibleVPN")
    fi

    sys_model=$(sysctl -n hw.model)
    if [[ "$sys_model" =~ VirtualBox|VMware ]]; then
        flags+=("KVMDetected")
    fi

    if [[ ${#flags[@]} -eq 0 ]]; then
        echo "✅ No obvious spoofing detected."
    else
        for flag in "${flags[@]}"; do
            echo "⚠️  $flag"
        done
    fi
}

# ----------- MAIN -----------

get_public_ip_info
get_wifi_bssids
get_mozilla_geolocation
detect_spoofing

echo ""
echo "✅ Scan complete."
