// ===== STORAGE MANAGER =====
const StorageManager = {
    CURRENT_SCAN_KEY: 'current_wardrive_scan',
    SAVED_SCANS_KEY: 'saved_wardrive_scans',
    
    saveCurrentScan: function(aps, metadata = {}) {
        const scanData = {
            timestamp: Date.now(),
            date: new Date().toISOString(),
            apCount: aps.length,
            aps: aps,
            metadata: metadata
        };
        localStorage.setItem(this.CURRENT_SCAN_KEY, JSON.stringify(scanData));
    },
    
    getCurrentScan: function() {
        const data = localStorage.getItem(this.CURRENT_SCAN_KEY);
        return data ? JSON.parse(data) : null;
    },
    
    saveToHistory: function(name) {
        const currentScan = this.getCurrentScan();
        if (!currentScan) {
            alert('No current scan to save!');
            return false;
        }
        
        const savedScans = this.getSavedScans();
        currentScan.name = name || `Scan ${new Date().toLocaleString()}`;
        savedScans.push(currentScan);
        
        localStorage.setItem(this.SAVED_SCANS_KEY, JSON.stringify(savedScans));
        return true;
    },
    
    getSavedScans: function() {
        const data = localStorage.getItem(this.SAVED_SCANS_KEY);
        return data ? JSON.parse(data) : [];
    },
    
    deleteScan: function(index) {
        const savedScans = this.getSavedScans();
        savedScans.splice(index, 1);
        localStorage.setItem(this.SAVED_SCANS_KEY, JSON.stringify(savedScans));
    },
    
    clearAll: function() {
        if (confirm('Clear all saved scans? This cannot be undone.')) {
            localStorage.removeItem(this.SAVED_SCANS_KEY);
            localStorage.removeItem(this.CURRENT_SCAN_KEY);
            return true;
        }
        return false;
    }
};

// ===== EXPORT MANAGER =====
const ExportManager = {
    toCSV: function(aps, filename = 'wardrive_export.csv') {
        let csv = 'SSID,BSSID,RSSI,Channel,Security,Seen Count,First Seen,Last Seen\n';
        
        aps.forEach(ap => {
            const ssid = (ap.ssid || '<hidden>').replace(/"/g, '""');
            csv += `"${ssid}",${ap.bssid},${ap.rssi},${ap.channel},"${ap.auth_str}",${ap.seen},${ap.first_seen},${ap.last_seen}\n`;
        });
        
        this.downloadFile(csv, filename, 'text/csv');
    },
    
    toJSON: function(aps, filename = 'wardrive_export.json') {
        const json = JSON.stringify(aps, null, 2);
        this.downloadFile(json, filename, 'application/json');
    },
    
    toKML: function(aps, filename = 'wardrive_export.kml') {
        // Basic KML without GPS (placeholder for future GPS integration)
        let kml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        kml += '<kml xmlns="http://www.opengis.net/kml/2.2">\n<Document>\n';
        kml += '<name>Wardrive Scan</name>\n';
        
        aps.forEach((ap, idx) => {
            kml += `<Placemark>\n`;
            kml += `  <name>${ap.ssid || 'Hidden'}</name>\n`;
            kml += `  <description>BSSID: ${ap.bssid}, RSSI: ${ap.rssi}dBm, Channel: ${ap.channel}, Security: ${ap.auth_str}</description>\n`;
            kml += `</Placemark>\n`;
        });
        
        kml += '</Document>\n</kml>';
        this.downloadFile(kml, filename, 'application/vnd.google-earth.kml+xml');
    },
    
    downloadFile: function(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
};

// ===== Tab Switching =====
document.querySelectorAll(".tabs button").forEach(btn => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tabs button").forEach(b => b.classList.remove("active"));
        document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
        
        btn.classList.add("active");
        const tabId = btn.getAttribute("data-tab");
        document.getElementById(tabId).classList.add("active");
        
        // Update export tab when opened
        if (tabId === 'export') {
            updateExportTab();
        }
    });
});

// ===== LOG HELPER =====
function log(el, msg) {
    const timestamp = new Date().toLocaleTimeString();
    el.textContent += `[${timestamp}] ${msg}\n`;
    el.scrollTop = el.scrollHeight;
}

// ===== FORMAT HELPERS =====
function formatUptime(seconds) {
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${String(hrs).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function formatBytes(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(2) + ' KB';
    return (bytes / 1048576).toFixed(2) + ' MB';
}

function getSignalClass(rssi) {
    if (rssi >= -50) return 'signal-strong';
    if (rssi >= -70) return 'signal-medium';
    return 'signal-weak';
}

function getSecurityBadge(authStr) {
    if (authStr.includes('OPEN')) return '<span class="security-badge security-open">OPEN</span>';
    if (authStr.includes('WEP')) return '<span class="security-badge security-wep">WEP</span>';
    if (authStr.includes('WPA3')) return '<span class="security-badge security-wpa3">WPA3</span>';
    if (authStr.includes('WPA2')) return '<span class="security-badge security-wpa2">WPA2</span>';
    if (authStr.includes('WPA')) return '<span class="security-badge security-wpa">WPA</span>';
    return '<span class="security-badge security-wpa">' + authStr + '</span>';
}

function getStatusClass(ageMs) {
    if (ageMs < 10000) return 'status-new';
    if (ageMs < 60000) return 'status-active';
    return 'status-old';
}

function getStatusText(ageMs) {
    if (ageMs < 10000) return '● NEW';
    if (ageMs < 60000) return '● ACTIVE';
    return '○ STALE';
}

function formatLastSeen(ageMs) {
    const seconds = Math.floor(ageMs / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours}h ago`;
}

// ===== WARDRIVE CONTROL =====
let isWardriveActive = false;

document.getElementById("btnStart").onclick = async () => {
    try {
        const res = await fetch("/api/wardrive/on", { method: "POST" });
        const data = await res.json();
        isWardriveActive = true;
        log(document.getElementById("log"), "✓ WARDRIVE STARTED");
        updateStatus();
    } catch(e) {
        log(document.getElementById("log"), "✗ ERROR STARTING: " + e);
    }
};

document.getElementById("btnStop").onclick = async () => {
    try {
        const res = await fetch("/api/wardrive/off", { method: "POST" });
        const data = await res.json();
        isWardriveActive = false;
        log(document.getElementById("log"), "✓ WARDRIVE STOPPED");
        updateStatus();
    } catch(e) {
        log(document.getElementById("log"), "✗ ERROR STOPPING: " + e);
    }
};

document.getElementById("btnScanDash").onclick = async () => {
    try {
        log(document.getElementById("log"), "⟳ INITIATING MANUAL SCAN...");
        await fetch("/api/scan/once", { method: "POST" });
        log(document.getElementById("log"), "✓ SCAN COMPLETE");
        await updateDashboard();
    } catch(e) {
        log(document.getElementById("log"), "✗ SCAN ERROR: " + e);
    }
};

document.getElementById("btnClear").onclick = async () => {
    if (confirm("Clear all captured network data?")) {
        try {
            await fetch("/api/aps/clear", { method: "POST" });
            log(document.getElementById("log"), "✓ DATA CLEARED");
            await updateDashboard();
        } catch(e) {
            log(document.getElementById("log"), "✗ CLEAR ERROR: " + e);
        }
    }
};

document.getElementById("btnSaveCurrentScan").onclick = () => {
    const name = prompt("Enter a name for this scan:", `Scan ${new Date().toLocaleString()}`);
    if (name && StorageManager.saveToHistory(name)) {
        log(document.getElementById("log"), "✓ SCAN SAVED TO HISTORY");
        updateExportTab();
    }
};

// ===== DASHBOARD UPDATE =====
async function updateDashboard() {
    try {
        // Fetch APs
        const apsRes = await fetch("/api/aps");
        const aps = await apsRes.json();
        
        // Save to current scan storage
        StorageManager.saveCurrentScan(aps);
        
        // Fetch state
        const stateRes = await fetch("/api/state");
        const state = await stateRes.json();
        
        // Update stats
        document.getElementById("apCount").textContent = state.ap_count;
        document.getElementById("scanSuccess").textContent = 
            `${state.successful_scans}/${state.total_scans}`;
        document.getElementById("uptime").textContent = formatUptime(state.uptime_sec);
        
        // Update system stats
        document.getElementById("freeHeap").textContent = formatBytes(state.free_heap);
        document.getElementById("minFreeHeap").textContent = formatBytes(state.min_free_heap);
        
        const heapUsagePercent = ((state.min_free_heap / state.free_heap) * 100).toFixed(1);
        document.getElementById("heapUsage").textContent = heapUsagePercent + '%';
        
        // Update heap usage bar
        const heapBar = document.getElementById("heapBar");
        if (heapBar) {
            heapBar.style.width = heapUsagePercent + '%';
            heapBar.className = 'heap-bar ' + 
                (heapUsagePercent < 50 ? 'heap-ok' : 
                 heapUsagePercent < 75 ? 'heap-warn' : 'heap-critical');
        }
        
        // Update table
        const tbody = document.getElementById("dashApList");
        tbody.innerHTML = "";
        
        if (aps.length === 0) {
            tbody.innerHTML = '<tr class="no-data"><td colspan="8">No networks detected yet...</td></tr>';
        } else {
            // Sort by RSSI (strongest first)
            aps.sort((a, b) => b.rssi - a.rssi);
            
            aps.forEach(ap => {
                const tr = document.createElement("tr");
                const signalClass = getSignalClass(ap.rssi);
                const statusClass = getStatusClass(ap.age_ms);
                
                tr.innerHTML = `
                    <td><strong>${ap.ssid}</strong></td>
                    <td style="font-family: monospace; font-size: 0.8em;">${ap.bssid}</td>
                    <td class="${signalClass}">${ap.rssi} dBm</td>
                    <td>${ap.channel}</td>
                    <td>${getSecurityBadge(ap.auth_str)}</td>
                    <td>${ap.seen}</td>
                    <td style="font-size: 0.85em;">${formatLastSeen(ap.age_ms)}</td>
                    <td class="${statusClass}">${getStatusText(ap.age_ms)}</td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch(e) {
        console.error("Dashboard update error:", e);
    }
}

function updateStatus() {
    const statusEl = document.getElementById("statusText");
    if (isWardriveActive) {
        statusEl.textContent = "ONLINE";
        statusEl.style.color = "var(--cyber-green)";
    } else {
        statusEl.textContent = "OFFLINE";
        statusEl.style.color = "var(--cyber-pink)";
    }
}

// Auto-refresh dashboard every 2 seconds
setInterval(async () => {
    if (document.getElementById("dashboard").classList.contains("active")) {
        await updateDashboard();
    }
}, 2000);

// Initial update
updateDashboard();

// ===== EXPORT TAB FUNCTIONALITY =====
function updateExportTab() {
    const currentScan = StorageManager.getCurrentScan();
    const savedScans = StorageManager.getSavedScans();
    
    // Update current scan info
    const currentInfo = document.getElementById("currentScanInfo");
    if (currentScan) {
        currentInfo.innerHTML = `
            <div class="scan-info">
                <strong>Last Updated:</strong> ${new Date(currentScan.timestamp).toLocaleString()}<br>
                <strong>Networks Found:</strong> ${currentScan.apCount}<br>
                <strong>Status:</strong> <span style="color: var(--cyber-green);">Ready to Export</span>
            </div>
        `;
    } else {
        currentInfo.innerHTML = '<div class="scan-info" style="color: var(--text-secondary);">No active scan data</div>';
    }
    
    // Update saved scans list
    const savedList = document.getElementById("savedScansList");
    savedList.innerHTML = '';
    
    if (savedScans.length === 0) {
        savedList.innerHTML = '<div class="no-data">No saved scans</div>';
    } else {
        savedScans.forEach((scan, index) => {
            const div = document.createElement("div");
            div.className = "saved-scan-item";
            div.innerHTML = `
                <div class="scan-item-header">
                    <strong>${scan.name}</strong>
                    <span class="scan-date">${new Date(scan.timestamp).toLocaleString()}</span>
                </div>
                <div class="scan-item-details">
                    ${scan.apCount} networks
                </div>
                <div class="scan-item-actions">
                    <button onclick="exportSavedScan(${index}, 'csv')" class="btn-mini btn-primary">CSV</button>
                    <button onclick="exportSavedScan(${index}, 'json')" class="btn-mini btn-secondary">JSON</button>
                    <button onclick="exportSavedScan(${index}, 'kml')" class="btn-mini btn-secondary">KML</button>
                    <button onclick="deleteSavedScan(${index})" class="btn-mini btn-danger">Delete</button>
                </div>
            `;
            savedList.appendChild(div);
        });
    }
}

// Export button handlers
document.getElementById("btnExportCurrentCSV").onclick = () => {
    const scan = StorageManager.getCurrentScan();
    if (scan) {
        ExportManager.toCSV(scan.aps, `wardrive_current_${Date.now()}.csv`);
        log(document.getElementById("log"), "✓ EXPORTED CURRENT SCAN AS CSV");
    } else {
        alert("No current scan data to export");
    }
};

document.getElementById("btnExportCurrentJSON").onclick = () => {
    const scan = StorageManager.getCurrentScan();
    if (scan) {
        ExportManager.toJSON(scan.aps, `wardrive_current_${Date.now()}.json`);
        log(document.getElementById("log"), "✓ EXPORTED CURRENT SCAN AS JSON");
    } else {
        alert("No current scan data to export");
    }
};

document.getElementById("btnExportCurrentKML").onclick = () => {
    const scan = StorageManager.getCurrentScan();
    if (scan) {
        ExportManager.toKML(scan.aps, `wardrive_current_${Date.now()}.kml`);
        log(document.getElementById("log"), "✓ EXPORTED CURRENT SCAN AS KML");
    } else {
        alert("No current scan data to export");
    }
};

function exportSavedScan(index, format) {
    const savedScans = StorageManager.getSavedScans();
    const scan = savedScans[index];
    if (!scan) return;
    
    const timestamp = scan.timestamp;
    switch(format) {
        case 'csv':
            ExportManager.toCSV(scan.aps, `wardrive_${timestamp}.csv`);
            break;
        case 'json':
            ExportManager.toJSON(scan.aps, `wardrive_${timestamp}.json`);
            break;
        case 'kml':
            ExportManager.toKML(scan.aps, `wardrive_${timestamp}.kml`);
            break;
    }
    log(document.getElementById("log"), `✓ EXPORTED SAVED SCAN: ${scan.name}`);
}

function deleteSavedScan(index) {
    if (confirm("Delete this saved scan?")) {
        StorageManager.deleteScan(index);
        updateExportTab();
        log(document.getElementById("log"), "✓ DELETED SAVED SCAN");
    }
}

document.getElementById("btnClearStorage").onclick = () => {
    if (StorageManager.clearAll()) {
        updateExportTab();
        log(document.getElementById("log"), "✓ CLEARED ALL STORAGE");
    }
};

// ===== SCAN ONCE (AP Tab) =====
document.getElementById("btnScan").onclick = async () => {
    try {
        log(document.getElementById("log"), "⟳ SCANNING...");
        
        await fetch("/api/scan/once", { method: "POST" });
        
        const res = await fetch("/api/aps");
        const aps = await res.json();

        const tbody = document.getElementById("apList");
        tbody.innerHTML = "";

        if (aps.length === 0) {
            tbody.innerHTML = '<tr class="no-data"><td colspan="6">No APs found</td></tr>';
            log(document.getElementById("log"), "✗ NO NETWORKS DETECTED");
        } else {
            aps.forEach(ap => {
                const tr = document.createElement("tr");
                tr.innerHTML = `
                    <td>${ap.ssid}</td>
                    <td>${ap.bssid}</td>
                    <td class="${getSignalClass(ap.rssi)}">${ap.rssi}</td>
                    <td>${ap.channel}</td>
                    <td>${ap.auth_str}</td>
                    <td>${ap.seen}</td>
                `;
                tbody.appendChild(tr);
            });
            log(document.getElementById("log"), `✓ FOUND ${aps.length} NETWORKS`);
        }
    } catch(e) {
        log(document.getElementById("log"), "✗ SCAN ERROR: " + e);
        console.error("Scan error:", e);
    }
};

// ===== ROGUE APS =====
document.getElementById("btnRogue").onclick = async () => {
    try {
        const res = await fetch("/api/security/rogues");
        const data = await res.json();
        document.getElementById("rogueList").textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        document.getElementById("rogueList").textContent = "Error: " + e;
    }
};

// ===== VULNERABILITIES =====
document.getElementById("btnVuln").onclick = async () => {
    try {
        const res = await fetch("/api/security/vulnerabilities");
        const data = await res.json();
        document.getElementById("vulnList").textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        document.getElementById("vulnList").textContent = "Error: " + e;
    }
};

// ===== DEAUTH DETECTOR =====
document.getElementById("btnDeauth").onclick = async () => {
    try {
        const res = await fetch("/api/security/deauth");
        const data = await res.json();
        document.getElementById("deauthLog").textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        document.getElementById("deauthLog").textContent = "Error: " + e;
    }
};

// ===== CLASSIFICATIONS =====
document.getElementById("btnClass").onclick = async () => {
    try {
        const res = await fetch("/api/classifications");
        const data = await res.json();
        document.getElementById("classList").textContent = JSON.stringify(data, null, 2);
    } catch(e) {
        document.getElementById("classList").textContent = "Error: " + e;
    }
};

// ===== IMPROVED PACKET INJECTOR =====
document.getElementById("btnInject").onclick = async () => {
    const logEl = document.getElementById("injectLog");
    const btn = document.getElementById("btnInject");
    
    try {
        btn.disabled = true;
        btn.textContent = "SENDING...";
        
        const bssid = document.getElementById("inj_bssid").value.trim();
        const type = document.getElementById("inj_type").value;
        const count = Number(document.getElementById("inj_count").value);
        const interval = Number(document.getElementById("inj_interval").value);
        
        // Validation
        if (!bssid || !/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/.test(bssid)) {
            logEl.textContent = "ERROR: Invalid BSSID format. Use XX:XX:XX:XX:XX:XX";
            return;
        }
        
        if (count < 1 || count > 100) {
            logEl.textContent = "ERROR: Count must be between 1 and 100";
            return;
        }
        
        if (interval < 10 || interval > 5000) {
            logEl.textContent = "ERROR: Interval must be between 10 and 5000ms";
            return;
        }
        
        logEl.textContent = `Sending ${count} ${type} packets to ${bssid}...\n`;
        
        const payload = { bssid, type, count, interval };
        
        const res = await fetch("/api/packets/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
        });

        const data = await res.json();
        
        if (data.status === "ok") {
            logEl.textContent += `\n✓ SUCCESS: Sent ${data.sent}/${count} packets\n`;
            logEl.textContent += `\nResponse:\n${JSON.stringify(data, null, 2)}`;
            log(document.getElementById("log"), `✓ INJECTED ${data.sent} ${type.toUpperCase()} PACKETS`);
        } else {
            logEl.textContent += `\n✗ FAILED: ${JSON.stringify(data, null, 2)}`;
        }
    } catch(e) {
        logEl.textContent = "ERROR: " + e.message + "\n\n" + e.stack;
        console.error("Packet injection error:", e);
    } finally {
        btn.disabled = false;
        btn.textContent = "FIRE PACKETS";
    }
};