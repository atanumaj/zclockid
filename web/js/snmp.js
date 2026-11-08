        // ==================== SNMP & Telemetry Logic ====================
        function setQueryOid(oid) {
            document.getElementById('snmp-test-oid').value = oid;
        }

        async function fetchSnmpStatus() {
            try {
                const res = await fetch(`${API_BASE}/snmp/status`);
                const data = await res.json();
                if (res.ok) {
                    const badge = document.getElementById('snmp-status-badge');
                    if (data.service_active) {
                        badge.className = 'inline-flex items-center gap-1 text-emerald-400 text-xs font-semibold';
                        badge.innerHTML = `<span class="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span> ACTIVE (UDP ${data.listening_port})`;
                    } else {
                        badge.className = 'inline-flex items-center gap-1 text-rose-400 text-xs font-semibold';
                        badge.innerHTML = `<span class="w-2 h-2 rounded-full bg-rose-500"></span> STOPPED`;
                    }

                    if (data.metrics) {
                        const m = data.metrics;
                        const adEl = document.getElementById('snmp-metric-ad');
                        adEl.innerText = m.ad_status || 'UNKNOWN';
                        adEl.className = m.ad_status === 'HEALTHY' ? 'text-sm font-bold text-emerald-400 font-mono' : 'text-sm font-bold text-rose-400 font-mono';

                        document.getElementById('snmp-metric-sessions').innerText = m.active_sessions || '0';

                        const sysEl = document.getElementById('snmp-metric-sysvol');
                        sysEl.innerText = m.sysvol_health || 'UNKNOWN';
                        sysEl.className = m.sysvol_health === 'HEALTHY' ? 'text-emerald-400' : 'text-amber-400';

                        const radEl = document.getElementById('snmp-metric-radius');
                        radEl.innerText = m.radius_auths || 'UNKNOWN';
                        radEl.className = m.radius_auths === 'ACTIVE' ? 'text-emerald-400' : 'text-rose-400';
                    }
                }
            } catch (err) {
                console.error('Error fetching SNMP status:', err);
            }
        }

        async function fetchSnmpConfig() {
            try {
                const res = await fetch(`${API_BASE}/snmp/config`);
                const data = await res.json();
                if (res.ok && data.config) {
                    const c = data.config;
                    document.getElementById('snmp-cfg-enabled').checked = c.enabled !== false;
                    document.getElementById('snmp-cfg-address').value = c.agent_address || 'udp:161,udp6:[::1]:161';
                    document.getElementById('snmp-cfg-community').value = c.community_string || 'zclock_public';
                    document.getElementById('snmp-cfg-location').value = c.sys_location || 'Primary Datacenter';
                    document.getElementById('snmp-cfg-contact').value = c.sys_contact || 'admin@example.com';
                    document.getElementById('snmp-cfg-subnets').value = c.allowed_subnets || '192.168.1.0/24, 127.0.0.1';
                    document.getElementById('snmp-cfg-extensions').checked = c.enable_extensions !== false;
                    document.getElementById('snmp-test-community').value = c.community_string || 'zclock_public';
                }
            } catch (err) {
                console.error('Error fetching SNMP config:', err);
            }
        }

        async function saveSnmpConfig(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-save-snmp-config');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving & Restarting...`;

            const payload = {
                enabled: document.getElementById('snmp-cfg-enabled').checked,
                agent_address: document.getElementById('snmp-cfg-address').value.trim(),
                sys_location: document.getElementById('snmp-cfg-location').value.trim(),
                sys_contact: document.getElementById('snmp-cfg-contact').value.trim(),
                community_string: document.getElementById('snmp-cfg-community').value.trim(),
                allowed_subnets: document.getElementById('snmp-cfg-subnets').value.trim(),
                enable_extensions: document.getElementById('snmp-cfg-extensions').checked
            };

            try {
                const res = await fetch(`${API_BASE}/snmp/config`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('SNMP configuration saved and daemon reloaded successfully!');
                    fetchSnmpStatus();
                    fetchSnmpConfig();
                } else {
                    alert(`Failed to save SNMP configuration: ${data.detail || 'Unknown error'}`);
                }
            } catch (err) {
                alert(`Error saving SNMP configuration: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save & Restart SNMP Daemon`;
            }
        }

        async function executeSnmpTestQuery(e) {
            if (e) e.preventDefault();
            const btn = document.getElementById('btn-run-snmp-test');
            const output = document.getElementById('snmp-test-output');
            const timeEl = document.getElementById('snmp-test-time');

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Querying...`;
            output.innerText = 'Executing SNMP query / walk in progress...';
            output.className = 'p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-slate-400 whitespace-pre-wrap break-all max-h-56 overflow-y-auto custom-scroll';

            const payload = {
                target_host: document.getElementById('snmp-test-target').value.trim(),
                community_string: document.getElementById('snmp-test-community').value.trim(),
                oid: document.getElementById('snmp-test-oid').value.trim()
            };

            const startTime = performance.now();
            try {
                const res = await fetch(`${API_BASE}/snmp/test-query`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const duration = Math.round(performance.now() - startTime);
                timeEl.innerText = `${duration} ms`;

                const data = await res.json();
                if (res.ok && data.status === 'success') {
                    output.className = 'p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-emerald-400 whitespace-pre-wrap break-all max-h-56 overflow-y-auto custom-scroll';
                    output.innerText = `$ ${data.command}\n\n${data.stdout || '(Empty response / leaf reached)'}`;
                } else {
                    output.className = 'p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-rose-400 whitespace-pre-wrap break-all max-h-56 overflow-y-auto custom-scroll';
                    output.innerText = `$ ${data.command || 'snmpwalk'}\n\nExit Code: ${data.exit_code}\n${data.stderr || data.detail || 'Query failed or timed out.'}`;
                }
            } catch (err) {
                timeEl.innerText = 'ERR';
                output.className = 'p-3 bg-slate-950 rounded-xl border border-slate-800 text-[11px] font-mono text-rose-400 whitespace-pre-wrap break-all max-h-56 overflow-y-auto custom-scroll';
                output.innerText = `Network or API Exception: ${err}`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-play"></i> Query / Walk`;
            }
        }

