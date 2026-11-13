        // 3. DNS & Kerberos Diagnostics, Forwarders & Overrides
        async function fetchDnsForwarders() {
            try {
                const res = await fetch(`${API_BASE}/dns/forwarders`);
                const data = await res.json();
                const container = document.getElementById('forwarders-list-display');
                if (container && data.forwarders) {
                    container.innerHTML = data.forwarders.map(ip => `
                        <span class="px-2.5 py-1 bg-slate-800 text-cyan-300 rounded-lg text-xs border border-cyan-800/40">${escapeHtml(ip)}</span>
                    `).join('');
                }
                const policyEl = document.getElementById('forward-policy-val');
                if (policyEl) policyEl.textContent = data.policy === 'only' ? 'Forward Only' : 'Forward First (Fallback to Root)';
            } catch (err) {
                console.error('Error fetching DNS forwarders:', err);
            }
            fetchDnsOverrides();
        }

        // ==================== DNS OVERRIDES, DOMAIN FORWARDERS & CACHE PURGE ====================
        let currentDnsOverrides = { host_overrides: [], domain_forwarders: [] };

        async function fetchDnsOverrides() {
            try {
                const res = await fetch(`${API_BASE}/dns/overrides`);
                const data = await res.json();
                currentDnsOverrides = data || { host_overrides: [], domain_forwarders: [] };
                renderDomainForwardersTable(currentDnsOverrides.domain_forwarders || []);
                renderHostOverridesTable(currentDnsOverrides.host_overrides || []);
            } catch (err) {
                console.error('Error fetching DNS overrides:', err);
            }
        }

        function renderDomainForwardersTable(list) {
            const tbody = document.getElementById('domain-forwarders-tbody');
            const countBadge = document.getElementById('domain-forwarders-count');
            if (countBadge) countBadge.textContent = `${list.length} Domain${list.length === 1 ? '' : 's'}`;
            if (!tbody) return;

            if (!list || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="px-3 py-3 text-center text-slate-600 font-sans text-[11px]">No conditional domain forwarders configured.</td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(item => {
                const fwdsDisplay = (item.forwarders || []).join(', ');
                const safeDomain = escapeHtml(item.domain || '');
                const safeFwds = escapeHtml(fwdsDisplay);
                const policyBadge = item.policy === 'only'
                    ? '<span class="px-1.5 py-0.5 rounded text-[9px] bg-emerald-950/80 text-emerald-400 border border-emerald-800/60 font-semibold">Only</span>'
                    : '<span class="px-1.5 py-0.5 rounded text-[9px] bg-slate-800 text-slate-300 border border-slate-700 font-semibold">First</span>';

                return `
                    <tr class="hover:bg-slate-900/60 transition">
                        <td class="px-3 py-2 text-white font-bold">${safeDomain}</td>
                        <td class="px-3 py-2 text-emerald-400 truncate max-w-[140px]" title="${safeFwds}">${safeFwds}</td>
                        <td class="px-3 py-2">${policyBadge}</td>
                        <td class="px-3 py-2 text-right">
                            <button data-action="delete-forwarder" data-domain="${safeDomain}" class="px-2 py-0.5 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 rounded text-[10px] transition border border-slate-700 hover:border-rose-800" title="Delete Domain Forwarder">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function renderHostOverridesTable(list) {
            const tbody = document.getElementById('host-overrides-tbody');
            const countBadge = document.getElementById('host-overrides-count');
            if (countBadge) countBadge.textContent = `${list.length} Host${list.length === 1 ? '' : 's'}`;
            if (!tbody) return;

            if (!list || list.length === 0) {
                tbody.innerHTML = `<tr><td colspan="4" class="px-3 py-3 text-center text-slate-600 font-sans text-[11px]">No host overrides configured.</td></tr>`;
                return;
            }

            tbody.innerHTML = list.map(item => {
                const safeFqdn = escapeHtml(item.fqdn || '');
                const safeType = escapeHtml(item.record_type || 'A');
                const safeTarget = escapeHtml(item.target || '');
                let typeBadge = 'bg-indigo-950/80 text-indigo-400 border-indigo-800/60';
                if (item.record_type === 'CNAME') typeBadge = 'bg-amber-950/80 text-amber-400 border-amber-800/60';
                else if (item.record_type === 'AAAA') typeBadge = 'bg-teal-950/80 text-teal-400 border-teal-800/60';
                else if (item.record_type === 'TXT') typeBadge = 'bg-sky-950/80 text-sky-400 border-sky-800/60';

                return `
                    <tr class="hover:bg-slate-900/60 transition">
                        <td class="px-3 py-2 text-white font-bold truncate max-w-[120px]" title="${safeFqdn}">${safeFqdn}</td>
                        <td class="px-3 py-2">
                            <span class="px-1.5 py-0.5 rounded text-[9px] border font-bold ${typeBadge}">${safeType}</span>
                        </td>
                        <td class="px-3 py-2 text-cyan-300 truncate max-w-[130px]" title="${safeTarget}">${safeTarget}</td>
                        <td class="px-3 py-2 text-right">
                            <button data-action="delete-override" data-fqdn="${safeFqdn}" data-type="${safeType}" class="px-2 py-0.5 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-400 rounded text-[10px] transition border border-slate-700 hover:border-rose-800" title="Delete Host Override">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function openAddHostOverrideModal() {
            document.getElementById('override-fqdn').value = '';
            document.getElementById('override-type').value = 'A';
            document.getElementById('override-target').value = '';
            document.getElementById('override-desc').value = '';
            onOverrideTypeChange();
            document.getElementById('modal-host-override').classList.remove('hidden');
        }
        function closeAddHostOverrideModal() {
            document.getElementById('modal-host-override').classList.add('hidden');
        }

        function onOverrideTypeChange() {
            const t = document.getElementById('override-type').value;
            const targetLabel = document.getElementById('override-target-label');
            const targetInput = document.getElementById('override-target');
            if (t === 'A') {
                targetLabel.innerText = 'Target IPv4 Address';
                targetInput.placeholder = 'e.g. 192.168.1.5';
            } else if (t === 'AAAA') {
                targetLabel.innerText = 'Target IPv6 Address';
                targetInput.placeholder = 'e.g. 2001:db8::5';
            } else if (t === 'CNAME') {
                targetLabel.innerText = 'Canonical Target FQDN (Alias)';
                targetInput.placeholder = 'e.g. gateway.example.com';
            } else {
                targetLabel.innerText = 'TXT Value';
                targetInput.placeholder = 'e.g. verification-token';
            }
        }

        async function submitAddHostOverride(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-save-host-override');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Saving...';

            const fqdn = document.getElementById('override-fqdn').value.trim();
            const type = document.getElementById('override-type').value;
            const target = document.getElementById('override-target').value.trim();
            const desc = document.getElementById('override-desc').value.trim();

            try {
                const res = await fetch(`${API_BASE}/dns/overrides/hosts`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ fqdn: fqdn, record_type: type, target: target, description: desc })
                });
                const data = await res.json();
                if (res.ok) {
                    closeAddHostOverrideModal();
                    fetchDnsOverrides();
                } else {
                    alert(`Failed to save host override: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerText = 'Save Override';
            }
        }

        async function deleteHostOverride(encFqdn, encType) {
            const fqdn = decodeURIComponent(encFqdn);
            const type = decodeURIComponent(encType);
            if (!confirm(`Are you sure you want to delete host override for '${fqdn}' (${type})?`)) return;

            try {
                const res = await fetch(`${API_BASE}/dns/overrides/hosts?fqdn=${encodeURIComponent(fqdn)}&record_type=${encodeURIComponent(type)}`, {
                    method: 'DELETE'
                });
                if (res.ok) {
                    fetchDnsOverrides();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting host override: ${err}`);
            }
        }

        function openAddDomainForwarderModal() {
            document.getElementById('domain-fwd-name').value = '';
            document.getElementById('domain-fwd-ips').value = '';
            document.getElementById('domain-fwd-policy').value = 'only';
            document.getElementById('domain-fwd-desc').value = '';
            document.getElementById('modal-domain-forwarder').classList.remove('hidden');
        }
        function closeAddDomainForwarderModal() {
            document.getElementById('modal-domain-forwarder').classList.add('hidden');
        }

        async function submitAddDomainForwarder(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-save-domain-forwarder');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Saving...';

            const domain = document.getElementById('domain-fwd-name').value.trim();
            const rawIps = document.getElementById('domain-fwd-ips').value;
            const fwds = rawIps.split(/[\n,\s]+/).map(s => s.trim()).filter(Boolean);
            const policy = document.getElementById('domain-fwd-policy').value;
            const desc = document.getElementById('domain-fwd-desc').value.trim();

            if (fwds.length === 0) {
                btn.disabled = false;
                btn.innerText = 'Save Domain Forwarder';
                return alert('At least one nameserver IP is required.');
            }

            try {
                const res = await fetch(`${API_BASE}/dns/overrides/domains`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ domain: domain, forwarders: fwds, policy: policy, description: desc })
                });
                const data = await res.json();
                if (res.ok) {
                    closeAddDomainForwarderModal();
                    fetchDnsOverrides();
                } else {
                    alert(`Failed to save domain forwarder: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerText = 'Save Domain Forwarder';
            }
        }

        async function deleteDomainForwarder(encDomain) {
            const domain = decodeURIComponent(encDomain);
            if (!confirm(`Are you sure you want to remove domain forwarding for '${domain}'?`)) return;

            try {
                const res = await fetch(`${API_BASE}/dns/overrides/domains?domain=${encodeURIComponent(domain)}`, {
                    method: 'DELETE'
                });
                if (res.ok) {
                    fetchDnsOverrides();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting domain forwarder: ${err}`);
            }
        }

        async function flushDnsCache() {
            const btn = document.getElementById('btn-flush-dns-cache');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Flushing...';
            }

            try {
                const res = await fetch(`${API_BASE}/dns/cache/flush`, { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    alert(`Success: ${data.message}`);
                    fetchDnsRecords();
                } else {
                    alert(`Cache flush failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error flushing DNS cache: ${err}`);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-broom"></i> Flush Cache';
                }
            }
        }

        function openForwardersModal() {
            fetch(`${API_BASE}/dns/forwarders`).then(r => r.json()).then(data => {
                document.getElementById('fwd-ips-input').value = data.forwarders.join('\n');
                document.getElementById('fwd-policy-select').value = data.policy || 'first';
                document.getElementById('forwarders-modal').classList.remove('hidden');
            });
        }
        function closeForwardersModal() { document.getElementById('forwarders-modal').classList.add('hidden'); }

        async function saveForwarders() {
            const raw = document.getElementById('fwd-ips-input').value;
            const ips = raw.split(/[\n,\s]+/).map(s => s.trim()).filter(Boolean);
            const policy = document.getElementById('fwd-policy-select').value;
            if (ips.length === 0) return alert('At least one forwarder IP is required.');

            try {
                const res = await fetch(`${API_BASE}/dns/forwarders`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ forwarders: ips, policy: policy })
                });
                const data = await res.json();
                if (res.ok) {
                    closeForwardersModal();
                    fetchDnsForwarders();
                } else {
                    alert(`Failed to save forwarders: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving forwarders: ${err}`);
            }
        }

        async function runDnsDiagnostics() {
            try {
                const res = await fetch(`${API_BASE}/dns/diagnostics`);
                const data = await res.json();
                if (data.diagnostics) {
                    data.diagnostics.forEach(d => {
                        if (d.service.includes('Kerberos KDC')) {
                            const el = document.getElementById('diag-kdc');
                            if (el) el.innerHTML = d.status === 'PASS' 
                                ? `<i class="fa-solid fa-circle-check text-emerald-400"></i> RESOLVING`
                                : `<i class="fa-solid fa-circle-xmark text-rose-400"></i> FAILED`;
                        } else if (d.service.includes('LDAP Directory')) {
                            const el = document.getElementById('diag-ldap');
                            if (el) el.innerHTML = d.status === 'PASS' 
                                ? `<i class="fa-solid fa-circle-check text-emerald-400"></i> RESOLVING`
                                : `<i class="fa-solid fa-circle-xmark text-rose-400"></i> FAILED`;
                        } else if (d.service.includes('Kerberos Password')) {
                            const el = document.getElementById('diag-kpasswd');
                            if (el) el.innerHTML = d.status === 'PASS' 
                                ? `<i class="fa-solid fa-circle-check text-emerald-400"></i> RESOLVING`
                                : `<i class="fa-solid fa-circle-xmark text-rose-400"></i> FAILED`;
                        } else if (d.service.includes('Forwarding')) {
                            const el = document.getElementById('diag-forward');
                            if (el) el.innerHTML = d.status === 'PASS' 
                                ? `<i class="fa-solid fa-circle-check text-emerald-400"></i> ACTIVE`
                                : `<i class="fa-solid fa-circle-xmark text-rose-400"></i> FAILED`;
                        }
                    });
                }
            } catch (err) {
                console.error('Error running diagnostics:', err);
            }
        }

        async function fetchDnsZones() {
            try {
                const res = await fetch(`${API_BASE}/dns/zones`);
                const data = await res.json();
                const sel = document.getElementById('dns-zone-select');
                if (sel && data.zones) {
                    sel.innerHTML = data.zones.map(z => `<option value="${escapeHtml(z)}">${escapeHtml(z)}</option>`).join('');
                }
            } catch (err) {
                console.error('Error fetching DNS zones:', err);
            }
        }

        async function fetchDnsRecords() {
            const zone = document.getElementById('dns-zone-select').value;
            const tbody = document.getElementById('dns-table-body');
            tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-4 text-center font-sans text-slate-500">Querying DNS database...</td></tr>`;

            try {
                const res = await fetch(`${API_BASE}/dns/records?zone=${zone}`);
                const data = await res.json();
                currentDnsRecords = data.records || [];
                const searchInput = document.getElementById('dns-search-input');
                if (searchInput && searchInput.value.trim()) {
                    filterDnsRecordsSearch();
                } else {
                    renderDnsTable(currentDnsRecords);
                }
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center text-rose-400">Failed to query records: ${escapeHtml(String(err))}</td></tr>`;
            }
        }

        function isDnsRecordProtected(r) {
            if (r.is_protected !== undefined) return r.is_protected;
            const name = (r.name || '').toLowerCase().trim();
            const type = (r.type || '').toUpperCase().trim();
            const zone = (r.zone || '').toLowerCase().trim();
            if (name === '@' || name === '') return true;
            if (type === 'SOA' || type === 'NS') return true;
            if (zone.startsWith('_msdcs')) return true;
            if (name.startsWith('_')) return true;
            const keywords = ['kerberos', 'kpasswd', 'ldap', 'gc', 'msdcs', 'vlmcs', 'domaindnszones', 'forestdnszones'];
            return keywords.some(k => name.includes(k));
        }

        function renderDnsTable(records) {
            const tbody = document.getElementById('dns-table-body');
            const countBadge = document.getElementById('dns-record-count-badge');
            if (countBadge) {
                countBadge.textContent = `${records.length} Record${records.length === 1 ? '' : 's'}`;
            }

            if (!records || records.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center font-sans text-slate-500">No records found matching search.</td></tr>`;
                return;
            }

            tbody.innerHTML = records.map(r => {
                const isProtected = isDnsRecordProtected(r);

                // Type styling
                let typeBadgeClass = 'bg-slate-800 text-slate-300 border-slate-700';
                if (r.type === 'A') typeBadgeClass = 'bg-emerald-950/80 text-emerald-400 border-emerald-800/60';
                else if (r.type === 'AAAA') typeBadgeClass = 'bg-teal-950/80 text-teal-400 border-teal-800/60';
                else if (r.type === 'SRV') typeBadgeClass = 'bg-indigo-950/80 text-indigo-400 border-indigo-800/60';
                else if (r.type === 'CNAME') typeBadgeClass = 'bg-amber-950/80 text-amber-400 border-amber-800/60';
                else if (r.type === 'TXT') typeBadgeClass = 'bg-sky-950/80 text-sky-400 border-sky-800/60';
                else if (r.type === 'MX') typeBadgeClass = 'bg-violet-950/80 text-violet-400 border-violet-800/60';
                else if (r.type === 'SOA' || r.type === 'NS') typeBadgeClass = 'bg-slate-800/80 text-slate-400 border-slate-700/60';

                // TTL badge
                let ttlVal = r.ttl || 900;
                let ttlDisplay = `${ttlVal}s`;
                if (ttlVal >= 86400 && ttlVal % 86400 === 0) ttlDisplay = `${ttlVal}s (${ttlVal/86400}d)`;
                else if (ttlVal >= 3600 && ttlVal % 3600 === 0) ttlDisplay = `${ttlVal}s (${ttlVal/3600}h)`;
                else if (ttlVal >= 60 && ttlVal % 60 === 0) ttlDisplay = `${ttlVal}s (${ttlVal/60}m)`;
                const ttlBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-950 border border-slate-800 text-slate-300 font-mono">${escapeHtml(ttlDisplay)}</span>`;

                // Scope badge
                const scopeBadge = isProtected
                    ? `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950/70 border border-amber-800/60 text-amber-300 font-semibold inline-flex items-center gap-1.5"><i class="fa-solid fa-shield text-[9px] text-amber-400"></i> Default Service</span>`
                    : `<span class="px-2 py-0.5 rounded text-[10px] font-mono bg-sky-950/70 border border-sky-800/60 text-sky-400 font-semibold inline-flex items-center gap-1.5"><i class="fa-solid fa-cube text-[9px]"></i> Custom</span>`;

                const safeZone = escapeHtml(r.zone || '');
                const safeName = escapeHtml(r.name || '');
                const safeType = escapeHtml(r.type || '');
                const safeData = escapeHtml(r.data || '');
                const safeTtl = escapeHtml(r.ttl || 900);

                // Action buttons: Protected records NEVER have delete! Custom records have BOTH Edit and Delete.
                let actionHtml = '';
                if (isProtected) {
                    actionHtml = `
                        <div class="flex items-center justify-end">
                            <span class="px-2.5 py-1 text-[10px] rounded bg-slate-950/80 border border-slate-800 text-slate-500 font-mono inline-flex items-center gap-1.5 cursor-not-allowed select-none" title="Protected Active Directory system service record - deletion disabled">
                                <i class="fa-solid fa-lock text-amber-500/70 text-[9px]"></i> Protected
                            </span>
                        </div>
                    `;
                } else {
                    actionHtml = `
                        <div class="flex items-center justify-end gap-2">
                            <button data-action="edit-dns-record" data-zone="${safeZone}" data-name="${safeName}" data-type="${safeType}" data-data="${safeData}" data-ttl="${safeTtl}" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-indigo-400 hover:text-indigo-300 rounded text-xs transition flex items-center gap-1 border border-slate-700" title="Edit Record">
                                <i class="fa-solid fa-pen-to-square"></i> Edit
                            </button>
                            <button data-action="delete-dns-record" data-zone="${safeZone}" data-name="${safeName}" data-type="${safeType}" data-data="${safeData}" class="px-2.5 py-1 bg-slate-800 hover:bg-rose-950/80 text-slate-400 hover:text-rose-400 rounded text-xs transition flex items-center gap-1 border border-slate-700 hover:border-rose-800" title="Delete Record">
                                <i class="fa-solid fa-trash-can"></i> Delete
                            </button>
                        </div>
                    `;
                }

                const nameHighlight = isProtected ? 'text-indigo-300 font-semibold' : 'text-white font-bold';

                return `
                    <tr class="hover:bg-slate-800/30 transition">
                        <td class="px-4 py-2.5 font-mono ${nameHighlight}">${safeName}</td>
                        <td class="px-4 py-2.5">
                            <span class="px-2 py-0.5 rounded text-[10px] font-mono border font-bold ${typeBadgeClass}">${safeType}</span>
                        </td>
                        <td class="px-4 py-2.5 text-slate-300 truncate max-w-xs font-mono" title="${safeData}">${safeData}</td>
                        <td class="px-4 py-2.5">${ttlBadge}</td>
                        <td class="px-4 py-2.5">${scopeBadge}</td>
                        <td class="px-4 py-2.5 text-right">${actionHtml}</td>
                    </tr>
                `;
            }).join('');
        }

        function filterDnsRecords(type) {
            // Maintained for backward compatibility: renders all records or type
            if (!type || type === 'ALL') {
                renderDnsTable(currentDnsRecords);
            } else {
                renderDnsTable(currentDnsRecords.filter(r => r.type === type));
            }
        }

        function filterDnsRecordsSearch() {
            const q = document.getElementById('dns-search-input').value.toLowerCase().trim();
            if (!q) {
                renderDnsTable(currentDnsRecords);
                return;
            }
            const filtered = currentDnsRecords.filter(r => 
                (r.name && r.name.toLowerCase().includes(q)) ||
                (r.type && r.type.toLowerCase().includes(q)) ||
                (r.data && r.data.toLowerCase().includes(q))
            );
            renderDnsTable(filtered);
        }

        function toggleDohTester() {
            const container = document.getElementById('doh-tester-container');
            if (container.classList.contains('hidden')) {
                container.classList.remove('hidden');
            } else {
                container.classList.add('hidden');
            }
        }

        async function executeDohTestQuery() {
            const qname = document.getElementById('doh-test-qname').value.trim();
            const rtype = document.getElementById('doh-test-rtype').value;
            const btn = document.getElementById('btn-run-doh-test');
            const resBox = document.getElementById('doh-test-result');
            const statusEl = document.getElementById('doh-res-status');
            const timeEl = document.getElementById('doh-res-time');
            const answersEl = document.getElementById('doh-res-answers');

            if (!qname) return alert('Please enter a domain name to test.');

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Resolving...`;

            try {
                const startTime = performance.now();
                const res = await fetch(`${API_BASE}/dns/doh/test`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ qname: qname, rtype: rtype })
                });
                const elapsed = (performance.now() - startTime).toFixed(1);
                const data = await res.json();

                resBox.classList.remove('hidden');
                if (data.status === 'ok') {
                    statusEl.className = 'text-emerald-400 font-bold';
                    statusEl.textContent = `HTTP ${data.http_status} OK (RFC 8484 NOERROR)`;
                    timeEl.textContent = `${data.latency_ms || elapsed} ms`;
                    if (data.answers && data.answers.length > 0) {
                        answersEl.innerHTML = data.answers.map(ans => 
                            `<div class="flex items-center gap-2"><span class="px-1.5 py-0.5 bg-slate-800 text-sky-300 rounded text-[10px]">${escapeHtml(data.rtype)}</span><span class="text-white">${escapeHtml(ans)}</span></div>`
                        ).join('');
                    } else {
                        answersEl.innerHTML = `<span class="text-slate-500 italic">No resource records returned for query.</span>`;
                    }
                } else {
                    statusEl.className = 'text-rose-400 font-bold';
                    statusEl.textContent = `Error: ${data.detail || data.status}`;
                    timeEl.textContent = `${elapsed} ms`;
                    answersEl.innerHTML = `<span class="text-rose-400">${escapeHtml(data.detail || 'DNS resolution failed.')}</span>`;
                }
            } catch (err) {
                resBox.classList.remove('hidden');
                statusEl.className = 'text-rose-400 font-bold';
                statusEl.textContent = `Network Error`;
                answersEl.innerHTML = `<span class="text-rose-400">${escapeHtml(String(err))}</span>`;
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-play"></i> Resolve`;
            }
        }

        function openDohClientGuideModal() {
            document.getElementById('modal-doh-guide').classList.remove('hidden');
        }

        function closeDohClientGuideModal() {
            document.getElementById('modal-doh-guide').classList.add('hidden');
        }

        const DNS_RECORD_CONFIG = {
            A: {
                desc: "Maps a domain name to an IPv4 address.",
                nameLabel: "Host / Subdomain Name",
                namePlaceholder: "web, vpn, mail, or @",
                nameHint: "Enter subdomain prefix or '@' for zone apex.",
                dataLabel: "IPv4 Address",
                dataPlaceholder: "192.168.1.50",
                dataHint: "Standard 32-bit dotted-decimal IPv4 address."
            },
            AAAA: {
                desc: "Maps a domain name to an IPv6 address.",
                nameLabel: "Host / Subdomain Name",
                namePlaceholder: "web, vpn, mail, or @",
                nameHint: "Enter subdomain prefix or '@' for zone apex.",
                dataLabel: "IPv6 Address",
                dataPlaceholder: "2001:db8:85a3::8a2e:370:7334",
                dataHint: "Standard 128-bit colon-separated IPv6 address."
            },
            CNAME: {
                desc: "Creates an alias that points one domain name to another canonical name.",
                nameLabel: "Alias Name",
                namePlaceholder: "www, portal, autoconfig",
                nameHint: "The alias hostname requesting redirection.",
                dataLabel: "Canonical Target FQDN",
                dataPlaceholder: "host.example.com",
                dataHint: "Fully qualified canonical domain name destination."
            },
            MX: {
                desc: "Directs email traffic to a domain's mail servers (with priority settings).",
                nameLabel: "Mail Domain / Subdomain",
                namePlaceholder: "@ or mail",
                nameHint: "Use '@' for root domain mail or specific subdomain.",
                dataLabel: "Mail Exchange Server FQDN",
                dataPlaceholder: "mail.example.com",
                dataHint: "FQDN of the receiving mail transfer agent (MTA).",
                showMx: true
            },
            TXT: {
                desc: "Stores text information, commonly used for domain verification and email security (SPF, DKIM, DMARC).",
                nameLabel: "Record Name",
                namePlaceholder: "@, _dmarc, or 202611._domainkey",
                nameHint: "Use '@' for SPF root or selector prefix for DKIM/DMARC.",
                dataLabel: "Text Value / SPF / DKIM String",
                dataPlaceholder: "v=spf1 ip4:192.0.2.0/24 -all",
                dataHint: "Arbitrary text data, security policy, or verification token."
            },
            NS: {
                desc: "Specifies the authoritative name servers for a domain.",
                nameLabel: "Delegated Zone / Subdomain",
                namePlaceholder: "@ or subzone",
                nameHint: "Zone apex '@' or delegated subzone.",
                dataLabel: "Authoritative Name Server FQDN",
                dataPlaceholder: "ns1.example.com",
                dataHint: "FQDN of the authoritative nameserver."
            },
            SOA: {
                desc: "Holds administrative and metadata information about a DNS zone.",
                nameLabel: "Zone Apex",
                namePlaceholder: "@",
                nameHint: "SOA records reside exclusively at zone apex root.",
                dataLabel: "Primary Nameserver & Admin Email",
                dataPlaceholder: "ns1.example.com hostmaster.example.com",
                dataHint: "Zone authority metadata (primary NS, contact email, serial, timers)."
            },
            PTR: {
                desc: "Used for reverse DNS lookups (resolving an IP address back to a hostname).",
                nameLabel: "Reverse IP Pointer / Host octet",
                namePlaceholder: "50 or 50.1.168.192.in-addr.arpa",
                nameHint: "Last octet in reverse zone, or full in-addr.arpa / ip6.arpa name.",
                dataLabel: "Target Host FQDN",
                dataPlaceholder: "srv01.example.com",
                dataHint: "Canonical hostname that the IP resolves to."
            },
            SRV: {
                desc: "Defines a specific service, port, and target host.",
                nameLabel: "Service & Protocol Name",
                namePlaceholder: "_kerberos._tcp or _ldap._tcp",
                nameHint: "Standard RFC 2782 format: _service._proto (e.g. _kerberos._tcp).",
                dataLabel: "Target Host FQDN",
                dataPlaceholder: "dc1.example.com",
                dataHint: "Host offering the service.",
                showSrv: true
            },
            CAA: {
                desc: "Specifies which Certificate Authorities are allowed to issue SSL/TLS certificates for the domain.",
                nameLabel: "Host / Domain",
                namePlaceholder: "@ or secure",
                nameHint: "Zone apex '@' or specific subdomain.",
                dataLabel: "CAA Policy Value",
                dataPlaceholder: '0 issue "letsencrypt.org"',
                dataHint: 'Flag, tag, and CA domain string (e.g. 0 issue "letsencrypt.org").'
            }
        };

        function onDnsTypeChange() {
            const typeSelect = document.getElementById('dns-type-select');
            if (!typeSelect) return;
            const type = typeSelect.value;
            const cfg = DNS_RECORD_CONFIG[type] || DNS_RECORD_CONFIG['A'];

            const descEl = document.getElementById('dns-type-desc-text');
            if (descEl) descEl.innerText = cfg.desc;

            const nameLabel = document.getElementById('dns-name-label');
            const nameInput = document.getElementById('dns-name-input');
            const nameHint = document.getElementById('dns-name-hint');
            if (nameLabel) nameLabel.innerText = cfg.nameLabel;
            if (nameInput) nameInput.placeholder = cfg.namePlaceholder;
            if (nameHint) nameHint.innerText = cfg.nameHint;

            const dataLabel = document.getElementById('dns-data-label');
            const dataInput = document.getElementById('dns-data-input');
            const dataHint = document.getElementById('dns-data-hint');
            if (dataLabel) dataLabel.innerText = cfg.dataLabel;
            if (dataInput) dataInput.placeholder = cfg.dataPlaceholder;
            if (dataHint) dataHint.innerText = cfg.dataHint;

            const srvBox = document.getElementById('srv-fields-container');
            if (srvBox) {
                if (cfg.showSrv) srvBox.classList.remove('hidden');
                else srvBox.classList.add('hidden');
            }

            const mxBox = document.getElementById('mx-fields-container');
            if (mxBox) {
                if (cfg.showMx) mxBox.classList.remove('hidden');
                else mxBox.classList.add('hidden');
            }
        }

        function openDnsModal() {
            document.getElementById('dns-modal').classList.remove('hidden');
            onDnsTypeChange();
        }
        function closeDnsModal() {
            document.getElementById('dns-modal').classList.add('hidden');
        }

        async function submitAddDnsRecord() {
            const zone = document.getElementById('dns-zone-select').value;
            const name = document.getElementById('dns-name-input').value.trim();
            const type = document.getElementById('dns-type-select').value;
            const data = document.getElementById('dns-data-input').value.trim();
            const port = parseInt(document.getElementById('dns-srv-port').value) || 88;
            const pri = parseInt(document.getElementById('dns-srv-priority').value) || 0;
            const wgt = parseInt(document.getElementById('dns-srv-weight').value) || 100;
            const mxPri = parseInt(document.getElementById('dns-mx-priority').value);
            const ttl = parseInt(document.getElementById('dns-ttl-input').value) || 900;

            if (!name || !data) return alert('Name and target data are required.');

            const payload = {
                zone: zone,
                record_name: name,
                record_type: type,
                record_data: data,
                ttl: ttl
            };

            if (type === 'SRV') {
                payload.port = port;
                payload.priority = pri;
                payload.weight = wgt;
            } else if (type === 'MX') {
                payload.priority = isNaN(mxPri) ? 10 : mxPri;
            }

            try {
                const res = await fetch(`${API_BASE}/dns/records`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const resData = await res.json();
                if (res.ok) {
                    closeDnsModal();
                    fetchDnsRecords();
                } else {
                    alert(`Failed to create record: ${resData.detail}`);
                }
            } catch (err) {
                alert(`Error creating record: ${err}`);
            }
        }

        function openEditDnsModal(encZone, encName, encType, encData, ttlVal) {
            const zone = decodeURIComponent(encZone);
            const name = decodeURIComponent(encName);
            const type = decodeURIComponent(encType);
            const data = decodeURIComponent(encData);

            document.getElementById('edit-dns-zone').value = zone;
            document.getElementById('edit-dns-old-data').value = data;
            document.getElementById('edit-dns-name').value = name;
            document.getElementById('edit-dns-type').value = type;
            const ttlInput = document.getElementById('edit-dns-ttl-input');
            if (ttlInput) ttlInput.value = ttlVal || 900;

            const srvBox = document.getElementById('edit-srv-fields');
            const dataInput = document.getElementById('edit-dns-new-data');
            const dataLabel = document.getElementById('edit-dns-data-label');

            if (type === 'SRV') {
                srvBox.classList.remove('hidden');
                dataLabel.innerText = 'Target Host FQDN';

                let target = data;
                let port = 88, pri = 0, wgt = 100;
                if (data.includes('(')) {
                    const parts = data.split('(');
                    target = parts[0].trim();
                    const sub = parts[1].replace(')', '').split(',');
                    if (sub.length === 3) {
                        port = parseInt(sub[0].trim()) || 88;
                        pri = parseInt(sub[1].trim()) || 0;
                        wgt = parseInt(sub[2].trim()) || 100;
                    }
                }
                dataInput.value = target;
                document.getElementById('edit-dns-srv-port').value = port;
                document.getElementById('edit-dns-srv-priority').value = pri;
                document.getElementById('edit-dns-srv-weight').value = wgt;
            } else if (type === 'MX') {
                srvBox.classList.add('hidden');
                dataLabel.innerText = 'Mail Server FQDN & Priority';
                let target = data;
                if (data.includes('(')) {
                    const parts = data.split('(');
                    target = parts[0].trim() + ' ' + parts[1].replace(')', '').trim();
                }
                dataInput.value = target;
            } else {
                srvBox.classList.add('hidden');
                dataLabel.innerText = 'Target IP / Host FQDN / Value';
                dataInput.value = data;
            }

            document.getElementById('modal-dns-edit').classList.remove('hidden');
        }

        function closeEditDnsModal() {
            document.getElementById('modal-dns-edit').classList.add('hidden');
        }

        async function submitUpdateDnsRecord(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-save-edit-dns');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Updating...';

            const zone = document.getElementById('edit-dns-zone').value;
            const name = document.getElementById('edit-dns-name').value;
            const type = document.getElementById('edit-dns-type').value;
            const oldData = document.getElementById('edit-dns-old-data').value;
            const newData = document.getElementById('edit-dns-new-data').value.trim();
            const ttlInput = document.getElementById('edit-dns-ttl-input');
            const ttl = ttlInput ? (parseInt(ttlInput.value) || 900) : 900;

            const payload = {
                zone: zone,
                record_name: name,
                record_type: type,
                old_data: oldData,
                new_data: newData,
                ttl: ttl
            };

            if (type === 'SRV') {
                payload.port = parseInt(document.getElementById('edit-dns-srv-port').value) || 88;
                payload.priority = parseInt(document.getElementById('edit-dns-srv-priority').value) || 0;
                payload.weight = parseInt(document.getElementById('edit-dns-srv-weight').value) || 100;
            }

            try {
                const res = await fetch(`${API_BASE}/dns/records`, {
                    method: 'PUT',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const resData = await res.json();
                if (res.ok) {
                    closeEditDnsModal();
                    fetchDnsRecords();
                } else {
                    alert(`Failed to update DNS record: ${resData.detail}`);
                }
            } catch (err) {
                alert(`Error updating DNS record: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Update Record';
            }
        }

        async function deleteDnsRecord(encZone, encName, encType, encData) {
            const zone = decodeURIComponent(encZone);
            const name = decodeURIComponent(encName);
            const type = decodeURIComponent(encType);
            const data = decodeURIComponent(encData);

            if (!confirm(`Are you sure you want to delete custom ${type} record '${name}' (${data})?`)) return;

            try {
                const url = `${API_BASE}/dns/records?zone=${encodeURIComponent(zone)}&record_name=${encodeURIComponent(name)}&record_type=${encodeURIComponent(type)}&record_data=${encodeURIComponent(data)}`;
                const res = await fetch(url, { method: 'DELETE' });
                if (res.ok) {
                    fetchDnsRecords();
                } else {
                    const err = await res.json();
                    alert(`Failed to delete record: ${err.detail}`);
                }
            } catch (err) {
                alert(`Error deleting record: ${err}`);
            }
        }

        function openNewZoneModal() { document.getElementById('zone-modal').classList.remove('hidden'); }
        function closeNewZoneModal() { document.getElementById('zone-modal').classList.add('hidden'); }

        async function submitCreateZone() {
            const zname = document.getElementById('new-zone-name-input').value.trim();
            if (!zname) return alert('Please enter a zone name.');
            try {
                const res = await fetch(`${API_BASE}/dns/zones`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ zone_name: zname })
                });
                const data = await res.json();
                if (res.ok) {
                    closeNewZoneModal();
                    fetchDnsZones();
                } else {
                    alert(`Failed to create zone: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error creating zone: ${err}`);
            }
        }

