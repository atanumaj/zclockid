        // 1. System & Dashboard Status
        async function fetchSystemStatus() {
            try {
                const res = await fetch(`${API_BASE}/system/status`);
                if (!res.ok) return;
                const data = await res.json();

                // Resource Gauges
                if (data.resources) {
                    document.getElementById('meter-cpu').textContent = `${data.resources.cpu_percent}%`;
                    document.getElementById('bar-cpu').style.width = `${data.resources.cpu_percent}%`;
                    document.getElementById('meter-mem').textContent = `${data.resources.memory_used_mb} / ${data.resources.memory_total_mb} MB (${data.resources.memory_percent}%)`;
                    document.getElementById('bar-mem').style.width = `${data.resources.memory_percent}%`;
                    document.getElementById('meter-disk').textContent = `${data.resources.disk_used_gb} / ${data.resources.disk_total_gb} GB (${data.resources.disk_percent}%)`;
                    document.getElementById('bar-disk').style.width = `${data.resources.disk_percent}%`;
                }

                document.getElementById('header-host').textContent = data.hostname || 'zclockid';
                document.getElementById('appliance-health').textContent = data.overall_health || 'HEALTHY';
                const upH = Math.floor(data.uptime_seconds / 3600);
                const upM = Math.floor((data.uptime_seconds % 3600) / 60);
                document.getElementById('appliance-uptime').textContent = `${upH}h ${upM}m`;

                if (data.version) {
                    const vHeader = document.getElementById('header-version-badge');
                    const vPill = document.getElementById('dash-version-badge');
                    const vApp = document.getElementById('appliance-version-label');
                    const vCur = document.getElementById('update-current-ver-badge');
                    const vInf = document.getElementById('info-current-version');
                    if (vHeader) vHeader.textContent = `v${data.version}`;
                    if (vPill) vPill.textContent = `v${data.version}`;
                    if (vApp) vApp.textContent = `ZclockID v${data.version}`;
                    if (vCur) vCur.textContent = `v${data.version}`;
                    if (vInf) vInf.textContent = data.version;
                }

                // Services Badges, Autostart & Dynamic Control Buttons
                latestSystemStatus = data;
                if (data.services) {
                    for (const [key, srv] of Object.entries(data.services)) {
                        const dashKey = key.replace(/_/g, '-');
                        const badge = document.getElementById(`badge-${dashKey}`);
                        const enabledEl = document.getElementById(`enabled-${dashKey}`);
                        const pidEl = document.getElementById(`pid-${dashKey}`);
                        const memEl = document.getElementById(`mem-${dashKey}`);
                        const actionsEl = document.getElementById(`actions-${dashKey}`);

                        if (badge) {
                            badge.textContent = srv.status.toUpperCase();
                            badge.className = srv.status === 'active' 
                                ? 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800'
                                : (srv.status === 'failed'
                                    ? 'px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 font-bold animate-pulse'
                                    : 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-900 text-slate-400 border border-slate-700');
                        }
                        if (enabledEl && srv.enabled) {
                            const isEn = srv.enabled === 'enabled' || srv.enabled === 'alias';
                            enabledEl.textContent = isEn ? 'BOOT: ON' : 'BOOT: OFF';
                            enabledEl.className = isEn
                                ? 'px-1.5 py-0.5 rounded text-[9px] font-mono bg-cyan-950 text-cyan-400 border border-cyan-800'
                                : 'px-1.5 py-0.5 rounded text-[9px] font-mono bg-amber-950 text-amber-400 border border-amber-800';
                        }
                        if (pidEl) pidEl.textContent = srv.pid ? `${srv.pid}` : '-';
                        if (memEl) memEl.textContent = srv.memory_mb ? `${srv.memory_mb} MB` : '-';

                        if (actionsEl) {
                            const meta = SERVICE_METADATA[dashKey] || { title: dashKey };
                            const safeKey = escapeHtml(dashKey);
                            const safeTitle = escapeHtml(meta.title);
                            if (srv.status === 'active') {
                                actionsEl.innerHTML = `
                                    <button data-action="control-service" data-service="${safeKey}" data-op="restart" class="flex-1 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-[11px] font-semibold transition flex items-center justify-center gap-1">
                                        <i class="fa-solid fa-arrows-rotate"></i> Restart
                                    </button>
                                    <button data-action="control-service" data-service="${safeKey}" data-op="stop" class="px-2.5 py-1 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-300 border border-slate-700 hover:border-rose-800 rounded text-[11px] font-semibold transition" title="Stop Service">
                                        <i class="fa-solid fa-stop"></i>
                                    </button>
                                    <button data-action="open-service-modal" data-service="${safeKey}" class="px-2 py-1 bg-slate-800 hover:bg-indigo-950 text-slate-400 hover:text-indigo-300 border border-slate-700 hover:border-indigo-800 rounded text-[11px] transition" title="Service Control Menu">
                                        <i class="fa-solid fa-sliders"></i>
                                    </button>
                                    <button data-action="open-log-viewer" data-service="${safeKey}" data-title="${safeTitle}" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 rounded text-[11px] transition" title="Journalctl Logs">
                                        <i class="fa-solid fa-terminal"></i>
                                    </button>
                                `;
                            } else {
                                actionsEl.innerHTML = `
                                    <button data-action="control-service" data-service="${safeKey}" data-op="start" class="flex-1 py-1 bg-emerald-600 hover:bg-emerald-500 text-white rounded text-[11px] font-bold transition flex items-center justify-center gap-1 shadow-sm shadow-emerald-600/30">
                                        <i class="fa-solid fa-play"></i> Start
                                    </button>
                                    <button data-action="control-service" data-service="${safeKey}" data-op="restart" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded text-[11px] font-semibold transition" title="Restart Service">
                                        <i class="fa-solid fa-arrows-rotate"></i>
                                    </button>
                                    <button data-action="open-service-modal" data-service="${safeKey}" class="px-2 py-1 bg-slate-800 hover:bg-indigo-950 text-slate-400 hover:text-indigo-300 border border-slate-700 hover:border-indigo-800 rounded text-[11px] transition" title="Service Control Menu">
                                        <i class="fa-solid fa-sliders"></i>
                                    </button>
                                    <button data-action="open-log-viewer" data-service="${safeKey}" data-title="${safeTitle}" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white border border-slate-700 rounded text-[11px] transition" title="Journalctl Logs">
                                        <i class="fa-solid fa-terminal"></i>
                                    </button>
                                `;
                            }
                        }
                    }
                }
            } catch (err) {
                console.error('Failed to fetch status:', err);
            }
        }

        // Service Metadata Catalog
        const SERVICE_METADATA = {
            'samba-ad-dc': { title: 'Samba AD DC', unit: 'samba-ad-dc.service', role: 'Active Directory Domain Controller (Kerberos, LDAP, SMB, RPC)', ports: '53, 88, 135, 139, 389, 445, 464, 636, 3268' },
            'bind9': { title: 'BIND9 DLZ & DoH', unit: 'bind9.service', role: 'Active Directory Dynamic DNS & RFC 8484 DNS-over-HTTPS', ports: '53 (UDP/TCP), 8053 (DoH)' },
            'freeradius': { title: 'FreeRADIUS 3', unit: 'freeradius.service', role: '802.1X WPA-Enterprise RADIUS Authentication & Accounting', ports: '1812 (Auth), 1813 (Acct)' },
            'chrony': { title: 'Chrony NTP Server', unit: 'chrony.service', role: 'Precision Network Time Server with Samba MS-SNTP Signing', ports: '123 (UDP Authenticated)' },
            'zclock-sysvold': { title: 'Sysvol NTACL Guardian', unit: 'zclock-sysvold.service', role: 'Bi-directional Sysvol Replication & Windows NTACL Self-Healing (Custom Built)', ports: '/var/lib/samba/sysvol' },
            'zclock-azuresync': { title: 'Azure Cloud Sync', unit: 'zclock-azuresync.service', role: 'Hybrid Cloud Identity, User & Password Hash Synchronization (Custom Built)', ports: 'Microsoft Entra ID' },
            'zclock-api': { title: 'ZclockID REST API', unit: 'zclock-api.service', role: 'Appliance Headless REST Management API & Web Backend (Custom Built)', ports: '8000 (FastAPI Engine)' },
            'nginx': { title: 'Nginx Multiplexer', unit: 'nginx.service', role: 'HTTP/2 TLS Termination, Web UI Host, DoH Path Routing', ports: '80, 443 (HTTPS/TLS)' },
            'snmpd': { title: 'SNMP Daemon', unit: 'snmpd.service', role: 'Enterprise Telemetry Provider & Active Directory Custom MIB', ports: '161 (UDP)' }
        };

        let currentModalServiceKey = 'samba-ad-dc';
        let latestSystemStatus = null;

        function openServiceControlModal(serviceKey) {
            currentModalServiceKey = serviceKey;
            const meta = SERVICE_METADATA[serviceKey] || { title: serviceKey, unit: `${serviceKey}.service`, role: 'Appliance Subsystem', ports: '-' };
            
            document.getElementById('modal-srv-title').innerText = meta.title;
            document.getElementById('modal-srv-unit').innerText = meta.unit;
            document.getElementById('modal-srv-role').innerText = meta.role;
            document.getElementById('modal-srv-ports').innerText = meta.ports;

            refreshModalServiceDetails();
            document.getElementById('modal-service-control').classList.remove('hidden');
        }

        function closeServiceControlModal() {
            document.getElementById('modal-service-control').classList.add('hidden');
        }

        function openLogFromModal() {
            const meta = SERVICE_METADATA[currentModalServiceKey] || { title: currentModalServiceKey };
            closeServiceControlModal();
            openLogViewer(currentModalServiceKey, meta.title);
        }

        function refreshModalServiceDetails() {
            if (!latestSystemStatus || !latestSystemStatus.services) return;
            const pyKey = currentModalServiceKey.replace(/-/g, '_');
            const srv = latestSystemStatus.services[pyKey];
            if (!srv) return;

            const isActive = srv.status === 'active';
            const isFailed = srv.status === 'failed';
            const dot = document.getElementById('modal-srv-dot');
            const stText = document.getElementById('modal-srv-status-text');
            const enText = document.getElementById('modal-srv-enabled-text');

            if (isActive) {
                dot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400';
                stText.className = 'text-emerald-400 font-bold text-xs';
                stText.innerText = 'ACTIVE (RUNNING)';
            } else if (isFailed) {
                dot.className = 'w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse';
                stText.className = 'text-rose-400 font-bold text-xs';
                stText.innerText = 'FAILED (CHECK LOGS)';
            } else {
                dot.className = 'w-2.5 h-2.5 rounded-full bg-slate-500';
                stText.className = 'text-slate-400 font-bold text-xs';
                stText.innerText = 'INACTIVE (STOPPED)';
            }

            const isEn = srv.enabled === 'enabled' || srv.enabled === 'alias';
            enText.innerText = isEn ? 'BOOT: ON (ENABLED)' : `BOOT: OFF (${srv.enabled || 'DISABLED'})`;
            enText.className = isEn ? 'text-cyan-400 font-bold text-xs' : 'text-amber-400 font-bold text-xs';

            document.getElementById('modal-srv-pid').innerText = srv.pid ? `${srv.pid}` : '-';
            document.getElementById('modal-srv-mem').innerText = srv.memory_mb ? `${srv.memory_mb} MB` : '-';
        }

        async function executeModalServiceAction(action) {
            await controlService(currentModalServiceKey, action);
            await fetchSystemStatus();
            refreshModalServiceDetails();
        }

        // Comprehensive Service Control (Start / Stop / Restart / Reload / Enable / Disable)
        async function controlService(serviceName, action) {
            const confirmed = confirm(`Are you sure you want to execute '${action.toUpperCase()}' on ${serviceName}?`);
            if (!confirmed) return;
            try {
                const res = await fetch(`${API_BASE}/services/${serviceName}/control`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ action: action })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`${serviceName} ${action} successful!`);
                    fetchSystemStatus();
                } else {
                    alert(`Action failed: ${data.detail || 'Service control error'}`);
                }
            } catch (err) {
                alert(`Error executing control command: ${err}`);
            }
        }

        // Live Log Viewer
        async function openLogViewer(serviceName, title) {
            currentActiveLogService = serviceName;
            document.getElementById('log-modal-title').innerText = `${title} (journalctl -u ${serviceName})`;
            document.getElementById('log-modal-body').innerText = 'Streaming logs from journalctl...';
            document.getElementById('log-modal').classList.remove('hidden');
            refreshActiveLogs();
        }

        async function refreshActiveLogs() {
            if (!currentActiveLogService) return;
            try {
                const res = await fetch(`${API_BASE}/services/${currentActiveLogService}/logs?lines=60`);
                const data = await res.json();
                document.getElementById('log-modal-body').innerText = data.logs || 'No logs found.';
            } catch (err) {
                document.getElementById('log-modal-body').innerText = `Error retrieving logs: ${err}`;
            }
        }

        function closeLogModal() {
            document.getElementById('log-modal').classList.add('hidden');
            currentActiveLogService = '';
        }

        // ==================== 24-HOUR AUTHENTICATION GRAPH ====================
        let authChartInstance = null;

        async function fetchAuthStats24h() {
            try {
                const res = await fetch(`${API_BASE}/system/auth-stats/24h`);
                if (!res.ok) return;
                const data = await res.json();

                const totalEl = document.getElementById('auth-metric-total');
                const rateEl = document.getElementById('auth-metric-rate');
                const peakEl = document.getElementById('auth-metric-peak');
                const sessionsEl = document.getElementById('auth-metric-sessions');
                const peakTimeEl = document.getElementById('auth-peak-time');
                const legKerbEl = document.getElementById('legend-kerb-ldap');
                const legFailEl = document.getElementById('legend-failed');
                const legRadiusEl = document.getElementById('legend-radius');

                if (totalEl) totalEl.innerText = Number(data.total_24h || 0).toLocaleString();
                if (rateEl) rateEl.innerText = `${data.success_rate_percent || 100}%`;
                if (peakEl) peakEl.innerText = `${data.peak_count || 0} req/h`;
                if (sessionsEl) sessionsEl.innerText = String(data.active_sessions_now || 0);
                if (peakTimeEl) peakTimeEl.innerText = `${data.peak_hour} (${data.peak_count} auths)`;
                if (legKerbEl) legKerbEl.innerText = `${((data.breakdown?.kerberos || 0) + (data.breakdown?.ldap || 0)).toLocaleString()} AD/Kerb`;
                if (legFailEl) legFailEl.innerText = `${(data.failed_count || 0).toLocaleString()} rejected`;
                if (legRadiusEl) legRadiusEl.innerText = `${(data.breakdown?.radius || 0).toLocaleString()} EAP`;

                const hourly = data.hourly || [];
                const labels = hourly.map(h => h.hour_label);
                const successData = hourly.map(h => h.success);
                const failedData = hourly.map(h => h.failed);
                const radiusData = hourly.map(h => h.radius);

                const canvas = document.getElementById('authChart24h');
                if (!canvas || typeof Chart === 'undefined') return;

                const ctx = canvas.getContext('2d');
                if (!ctx) return;

                const gradSuccess = ctx.createLinearGradient(0, 0, 0, 240);
                gradSuccess.addColorStop(0, 'rgba(16, 185, 129, 0.45)');
                gradSuccess.addColorStop(1, 'rgba(16, 185, 129, 0.02)');

                const gradRadius = ctx.createLinearGradient(0, 0, 0, 240);
                gradRadius.addColorStop(0, 'rgba(14, 165, 233, 0.35)');
                gradRadius.addColorStop(1, 'rgba(14, 165, 233, 0.01)');

                if (authChartInstance) {
                    authChartInstance.data.labels = labels;
                    authChartInstance.data.datasets[0].data = successData;
                    authChartInstance.data.datasets[1].data = radiusData;
                    authChartInstance.data.datasets[2].data = failedData;
                    authChartInstance.update();
                } else {
                    authChartInstance = new Chart(ctx, {
                        type: 'line',
                        data: {
                            labels: labels,
                            datasets: [
                                {
                                    label: 'Successful Auths (AD & PAM)',
                                    data: successData,
                                    borderColor: '#10b981',
                                    backgroundColor: gradSuccess,
                                    borderWidth: 2.5,
                                    fill: true,
                                    tension: 0.35,
                                    pointBackgroundColor: '#10b981',
                                    pointBorderColor: '#ffffff',
                                    pointBorderWidth: 1.5,
                                    pointRadius: 3,
                                    pointHoverRadius: 6
                                },
                                {
                                    label: 'FreeRADIUS 802.1X',
                                    data: radiusData,
                                    borderColor: '#0ea5e9',
                                    backgroundColor: gradRadius,
                                    borderWidth: 2,
                                    fill: true,
                                    tension: 0.35,
                                    pointBackgroundColor: '#0ea5e9',
                                    pointRadius: 2.5,
                                    pointHoverRadius: 5
                                },
                                {
                                    label: 'Failed / Rejected',
                                    data: failedData,
                                    borderColor: '#f43f5e',
                                    backgroundColor: 'rgba(244, 63, 94, 0.15)',
                                    borderWidth: 1.5,
                                    fill: false,
                                    tension: 0.2,
                                    pointBackgroundColor: '#f43f5e',
                                    pointRadius: 2,
                                    pointHoverRadius: 5
                                }
                            ]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            interaction: {
                                mode: 'index',
                                intersect: false
                            },
                            plugins: {
                                legend: {
                                    display: false
                                },
                                tooltip: {
                                    backgroundColor: '#0f172a',
                                    titleColor: '#f8fafc',
                                    bodyColor: '#cbd5e1',
                                    borderColor: '#334155',
                                    borderWidth: 1,
                                    padding: 10,
                                    boxPadding: 4,
                                    usePointStyle: true,
                                    callbacks: {
                                        label: function(context) {
                                            return ` ${context.dataset.label}: ${context.parsed.y} reqs`;
                                        }
                                    }
                                }
                            },
                            scales: {
                                x: {
                                    grid: {
                                        color: 'rgba(51, 65, 85, 0.3)',
                                        drawBorder: false
                                    },
                                    ticks: {
                                        color: '#64748b',
                                        font: {
                                            family: 'JetBrains Mono, monospace',
                                            size: 10
                                        },
                                        maxRotation: 0,
                                        autoSkip: true,
                                        maxTicksLimit: 12
                                    }
                                },
                                y: {
                                    beginAtZero: true,
                                    grid: {
                                        color: 'rgba(51, 65, 85, 0.3)',
                                        drawBorder: false
                                    },
                                    ticks: {
                                        color: '#64748b',
                                        font: {
                                            family: 'JetBrains Mono, monospace',
                                            size: 10
                                        },
                                        precision: 0
                                    }
                                }
                            }
                        }
                    });
                }
            } catch (err) {
                console.error('Error fetching auth stats 24h:', err);
            }
        }

