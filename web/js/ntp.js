        // ==================== NTP SERVER & CLOCK SYNC JS ====================
        async function fetchNtpStatus() {
            try {
                const res = await fetch(`${API_BASE}/ntp/status`);
                const data = await res.json();

                const statusText = document.getElementById('ntp-status-text');
                const statusDot = document.getElementById('ntp-status-dot');
                const signdVal = document.getElementById('ntp-signd-val');
                const stratumVal = document.getElementById('ntp-stratum-val');
                const offsetVal = document.getElementById('ntp-offset-val');
                const tbody = document.getElementById('ntp-sources-table-body');

                if (data.server_listening) {
                    statusText.innerText = 'SERVING (PORT 123)';
                    statusText.className = 'text-emerald-400 font-bold text-xs truncate';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse';
                } else {
                    statusText.innerText = 'CLIENT ONLY';
                    statusText.className = 'text-slate-400 font-bold text-xs truncate';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-slate-500';
                }

                signdVal.innerText = data.service_active ? 'ACTIVE (ntp_signd)' : 'INACTIVE';
                stratumVal.innerText = `Stratum ${data.stratum} (${data.reference_id || 'Local'})`;
                offsetVal.innerText = data.last_offset || '+0.00 ms';

                if (tbody && data.sources) {
                    if (data.sources.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="6" class="px-3 py-4 text-center text-slate-500 font-sans">No NTP peer sources configured.</td></tr>';
                    } else {
                        tbody.innerHTML = data.sources.map(s => {
                            const isBest = s.state.includes('Best');
                            const stateBadge = isBest
                                ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-emerald-950 text-emerald-400 border border-emerald-800">ACTIVE</span>'
                                : (s.state.includes('Combined')
                                    ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-indigo-950 text-indigo-300 border border-indigo-800">PEER</span>'
                                    : '<span class="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-400">CANDIDATE</span>');
                            return `
                                <tr class="hover:bg-slate-800/30">
                                    <td class="px-3 py-2">${stateBadge}</td>
                                    <td class="px-3 py-2 font-bold text-white">${s.address}</td>
                                    <td class="px-3 py-2 text-cyan-300">Stratum ${s.stratum}</td>
                                    <td class="px-3 py-2 text-slate-400">${s.reach}</td>
                                    <td class="px-3 py-2 text-amber-300">${s.offset}s</td>
                                    <td class="px-3 py-2 text-slate-500">${s.last_rx}</td>
                                </tr>
                            `;
                        }).join('');
                    }
                }
            } catch (err) {
                console.error('Error fetching NTP status:', err);
            }
        }

        async function fetchNtpConfig() {
            try {
                const res = await fetch(`${API_BASE}/ntp/config`);
                const data = await res.json();

                document.getElementById('ntp-cfg-server-enabled').checked = Boolean(data.ntp_server_enabled);
                document.getElementById('ntp-cfg-ms-sntp').checked = Boolean(data.ms_sntp_enabled);
                document.getElementById('ntp-cfg-subnets').value = data.allowed_subnets || '0.0.0.0/0, ::/0';
                document.getElementById('ntp-cfg-upstreams').value = (data.upstream_servers || []).join('\n');
                if (data.timezone) {
                    document.getElementById('ntp-cfg-timezone').value = data.timezone;
                }
            } catch (err) {
                console.error('Error fetching NTP config:', err);
            }
        }

        async function saveNtpConfig(e) {
            if (e) e.preventDefault();
            const btn = document.getElementById('btn-save-ntp-cfg');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

            const upstreams = document.getElementById('ntp-cfg-upstreams').value
                .split('\n')
                .map(s => s.trim())
                .filter(Boolean);

            const payload = {
                ntp_server_enabled: document.getElementById('ntp-cfg-server-enabled').checked,
                ms_sntp_enabled: document.getElementById('ntp-cfg-ms-sntp').checked,
                allowed_subnets: document.getElementById('ntp-cfg-subnets').value.trim(),
                upstream_servers: upstreams,
                timezone: document.getElementById('ntp-cfg-timezone').value
            };

            try {
                const res = await fetch(`${API_BASE}/ntp/config`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to update NTP config');

                alert('NTP Authoritative Time Server settings saved and Chrony restarted successfully.');
                await fetchNtpConfig();
                await fetchNtpStatus();
            } catch (err) {
                alert(`Error saving NTP settings: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

        async function triggerNtpSyncNow() {
            const btn = document.getElementById('btn-ntp-step');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Stepping Clock...';

            try {
                const res = await fetch(`${API_BASE}/ntp/sync-now`, { method: 'POST' });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to step clock');
                alert(`Clock Step Successful!\n\n${data.message}`);
                await fetchNtpStatus();
            } catch (err) {
                alert(`Error stepping clock: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

