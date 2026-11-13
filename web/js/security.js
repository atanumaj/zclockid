        let currentLogsSubTab = 'live';
        let cachedAuditRecords = [];

        function switchLogsSubTab(subtab) {
            currentLogsSubTab = subtab;
            const subtabs = ['live', 'compliance', 'forwarder', 'retention'];
            subtabs.forEach(s => {
                const view = document.getElementById(`logs-view-${s}`);
                const btn = document.getElementById(`logs-subtab-btn-${s}`);
                if (view) view.classList.add('hidden');
                if (btn) {
                    btn.classList.remove('bg-sky-600', 'bg-emerald-600', 'bg-indigo-600', 'bg-amber-600', 'text-white', 'shadow-sm');
                    btn.classList.add('bg-slate-800', 'text-slate-300');
                }
            });

            const activeView = document.getElementById(`logs-view-${subtab}`);
            const activeBtn = document.getElementById(`logs-subtab-btn-${subtab}`);
            if (activeView) activeView.classList.remove('hidden');
            if (activeBtn) {
                activeBtn.classList.remove('bg-slate-800', 'text-slate-300');
                if (subtab === 'live') {
                    activeBtn.classList.add('bg-sky-600', 'text-white', 'shadow-sm');
                    fetchLogRetentionSettings().then(() => fetchLiveSyslog());
                } else if (subtab === 'compliance') {
                    activeBtn.classList.add('bg-emerald-600', 'text-white', 'shadow-sm');
                    fetchAuditEvents();
                } else if (subtab === 'forwarder') {
                    activeBtn.classList.add('bg-indigo-600', 'text-white', 'shadow-sm');
                    fetchSyslogSettings();
                } else if (subtab === 'retention') {
                    activeBtn.classList.add('bg-amber-600', 'text-white', 'shadow-sm');
                    fetchLogRetentionSettings();
                }
            }
        }

        function refreshActiveLogsView() {
            if (currentLogsSubTab === 'compliance') {
                fetchAuditEvents();
            } else if (currentLogsSubTab === 'forwarder') {
                fetchSyslogSettings();
            } else if (currentLogsSubTab === 'retention') {
                fetchLogRetentionSettings();
            } else {
                fetchLiveSyslog();
            }
        }

        async function fetchAuditEvents() {
            try {
                const [res] = await Promise.all([
                    fetch(`${API_BASE}/reports/audit-events`, { headers: getAuthHeaders() }),
                    fetchLogRetentionSettings()
                ]);
                const data = await res.json();
                cachedAuditRecords = data.events || [];
                const countBadge = document.getElementById('audit-total-count');
                if (countBadge) countBadge.innerText = (data.total_count ?? data.count ?? cachedAuditRecords.length).toLocaleString();
                filterAuditEvents();
            } catch (err) {
                console.error('Error fetching audit events:', err);
                const tbody = document.getElementById('audit-table-body');
                if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center font-sans text-rose-400">Failed to load audit records: ${escapeHtml(err.message)}</td></tr>`;
            }
        }

        function filterAuditEvents() {
            const tbody = document.getElementById('audit-table-body');
            if (!tbody) return;

            const searchInput = document.getElementById('audit-filter-input');
            const statusSelect = document.getElementById('audit-status-filter');
            const search = (searchInput ? searchInput.value : '').toLowerCase().trim();
            const statusFilter = statusSelect ? statusSelect.value : 'ALL';

            const filtered = cachedAuditRecords.filter(e => {
                if (statusFilter !== 'ALL' && e.status !== statusFilter) return false;
                if (!search) return true;
                const matchType = (e.event_type || '').toLowerCase().includes(search);
                const matchActor = (e.actor || '').toLowerCase().includes(search);
                const matchTarget = (e.target || '').toLowerCase().includes(search);
                const matchDetails = (e.details || '').toLowerCase().includes(search);
                return matchType || matchActor || matchTarget || matchDetails;
            });

            if (filtered.length > 0) {
                tbody.innerHTML = filtered.map(e => {
                    const d = new Date(e.timestamp * 1000);
                    const dateStr = escapeHtml(d.toLocaleDateString() + ' ' + d.toLocaleTimeString());
                    let detailsFormatted = e.details || '-';
                    try {
                        const parsed = JSON.parse(e.details);
                        if (typeof parsed === 'object' && Object.keys(parsed).length > 0) {
                            detailsFormatted = Object.entries(parsed).map(([k, v]) => `${k}=${v}`).join(', ');
                        }
                    } catch (_) {}

                    const safeType = escapeHtml(e.event_type);
                    const safeActor = escapeHtml(e.actor || 'system');
                    const safeTarget = escapeHtml(e.target);
                    const safeStatus = escapeHtml(e.status);
                    const safeDetails = escapeHtml(detailsFormatted);
                    const rawDetailsAttr = escapeHtml(e.details || '');

                    return `
                        <tr class="hover:bg-slate-800/30 transition">
                            <td class="px-4 py-2.5 text-slate-400 whitespace-nowrap">${dateStr}</td>
                            <td class="px-4 py-2.5 font-bold text-white">${safeType}</td>
                            <td class="px-4 py-2.5 text-indigo-400 font-semibold">${safeActor}</td>
                            <td class="px-4 py-2.5 text-cyan-300 font-semibold">${safeTarget}</td>
                            <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-[10px] font-bold ${e.status === 'SUCCESS' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-rose-950 text-rose-400 border border-rose-800'}">${safeStatus}</span></td>
                            <td class="px-4 py-2.5 text-slate-400 max-w-xs truncate font-mono text-[10px]" title="${rawDetailsAttr}">${safeDetails}</td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center font-sans text-slate-500">No matching audit records found.</td></tr>`;
            }
        }

        function exportAuditCsv() {
            window.location.href = `${API_BASE}/reports/export/csv`;
        }

        async function fetchRbacMappings() {
            const tbody = document.getElementById('rbac-mappings-tbody');
            if (!tbody) return;
            try {
                const res = await fetch(`${API_BASE}/rbac/mappings`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to load RBAC mappings');
                const data = await res.json();
                const mappings = data.mappings || [];

                document.getElementById('rbac-total-mappings').innerText = mappings.length;
                document.getElementById('rbac-mapping-count-pill').innerText = `${mappings.length} mappings`;

                if (mappings.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="6" class="py-6 text-center text-slate-500">No role mappings configured yet. Click "Add Role Mapping" to map an AD group.</td></tr>';
                    return;
                }

                tbody.innerHTML = mappings.map(m => {
                    const typeBadge = m.principal_type === 'group'
                        ? '<span class="px-2 py-0.5 text-[10px] rounded bg-indigo-950 border border-indigo-800 text-indigo-400 font-mono"><i class="fa-solid fa-users mr-1"></i> GROUP</span>'
                        : '<span class="px-2 py-0.5 text-[10px] rounded bg-sky-950 border border-sky-800 text-sky-400 font-mono"><i class="fa-solid fa-user mr-1"></i> USER</span>';

                    let roleColor = 'text-slate-300 bg-slate-800 border-slate-700';
                    if (m.role === 'fulladmin') roleColor = 'text-emerald-400 bg-emerald-950 border-emerald-800';
                    else if (m.role === 'operator') roleColor = 'text-indigo-400 bg-indigo-950 border-indigo-800';
                    else if (m.role === 'report') roleColor = 'text-cyan-400 bg-cyan-950 border-cyan-800';

                    const safeRole = escapeHtml(m.role);
                    const safeName = escapeHtml(m.principal_name);
                    const safeDesc = escapeHtml(m.description || '--');
                    const roleBadge = `<span class="px-2 py-0.5 text-[10px] rounded border font-mono font-bold ${roleColor}">${safeRole}</span>`;
                    const dateStr = m.created_at ? escapeHtml(new Date(m.created_at * 1000).toLocaleDateString()) : '--';
                    const isProtected = (m.principal_name === 'Domain Admins' && m.principal_type === 'group');

                    return `
                        <tr class="hover:bg-slate-800/30 transition">
                            <td class="py-3 px-4">${typeBadge}</td>
                            <td class="py-3 px-4 font-mono font-bold text-white flex items-center gap-2">
                                ${safeName}
                                ${isProtected ? '<span class="text-[10px] text-amber-400" title="Protected core group mapping"><i class="fa-solid fa-lock"></i></span>' : ''}
                            </td>
                            <td class="py-3 px-4">${roleBadge}</td>
                            <td class="py-3 px-4 text-slate-400 text-xs">${safeDesc}</td>
                            <td class="py-3 px-4 text-slate-500 font-mono text-[11px]">${dateStr}</td>
                            <td class="py-3 px-4 text-right">
                                ${isProtected ? '<span class="text-[11px] text-slate-600 font-mono">LOCKED</span>' : `
                                    <button data-action="delete-rbac-mapping" data-id="${m.id}" data-principal="${safeName}" class="px-2.5 py-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded transition text-xs">
                                        <i class="fa-solid fa-trash-can mr-1"></i> Delete
                                    </button>
                                `}
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" class="py-6 text-center text-rose-400 font-mono">Error: ${escapeHtml(err.message)}</td></tr>`;
            }
        }

        let adPrincipalsCache = { groups: [], users: [] };
        let isCustomPrincipalMode = false;

        async function loadAdPrincipals() {
            const loadingSpan = document.getElementById('rbac-principals-loading');
            if (loadingSpan) loadingSpan.classList.remove('hidden');
            try {
                const res = await fetch(`${API_BASE}/rbac/principals`, { headers: getAuthHeaders() });
                if (res.ok) {
                    adPrincipalsCache = await res.json();
                }
            } catch (e) {
                console.error('Failed to load AD principals:', e);
            } finally {
                if (loadingSpan) loadingSpan.classList.add('hidden');
                populatePrincipalDropdown();
            }
        }

        function onRbacPrincipalTypeChange() {
            populatePrincipalDropdown();
        }

        function populatePrincipalDropdown(selectedValue = '') {
            const type = document.getElementById('rbac-principal-type').value;
            const select = document.getElementById('rbac-principal-select');
            const label = document.getElementById('rbac-principal-label');
            const hint = document.getElementById('rbac-principal-hint');
            if (!select) return;

            if (type === 'group') {
                if (label) label.textContent = 'Select Active Directory Security Group';
                if (hint) hint.textContent = 'Security groups discovered live from Active Directory (sam.ldb).';
                const list = adPrincipalsCache.groups || [];
                select.innerHTML = '<option value="">-- Select Active Directory Group --</option>' +
                    list.map(g => {
                        const safeGName = escapeHtml(g.name);
                        const safeGDesc = g.description ? ' — ' + escapeHtml(g.description) : '';
                        return `<option value="${safeGName}" ${g.name === selectedValue ? 'selected' : ''}>${safeGName}${safeGDesc}</option>`;
                    }).join('');
            } else {
                if (label) label.textContent = 'Select Active Directory User Account';
                if (hint) hint.textContent = 'User accounts discovered live from Active Directory (sam.ldb).';
                const list = adPrincipalsCache.users || [];
                select.innerHTML = '<option value="">-- Select Active Directory User --</option>' +
                    list.map(u => {
                        const safeUName = escapeHtml(u.name);
                        const safeUDisp = u.display_name ? ' — ' + escapeHtml(u.display_name) : '';
                        return `<option value="${safeUName}" ${u.name === selectedValue ? 'selected' : ''}>${safeUName}${safeUDisp}</option>`;
                    }).join('');
            }
        }

        function onRbacPrincipalSelectChange() {
            const select = document.getElementById('rbac-principal-select');
            const descInput = document.getElementById('rbac-description');
            if (select && select.value && descInput && !descInput.value) {
                const type = document.getElementById('rbac-principal-type').value;
                if (type === 'group') {
                    const match = (adPrincipalsCache.groups || []).find(g => g.name === select.value);
                    if (match && match.description) descInput.value = match.description;
                }
            }
        }

        function toggleCustomPrincipalInput() {
            isCustomPrincipalMode = !isCustomPrincipalMode;
            const customInput = document.getElementById('rbac-principal-custom');
            const select = document.getElementById('rbac-principal-select');
            const toggleText = document.getElementById('rbac-custom-toggle-text');
            if (isCustomPrincipalMode) {
                customInput.classList.remove('hidden');
                select.classList.add('hidden');
                toggleText.innerText = '← Select from AD dropdown';
                customInput.focus();
            } else {
                customInput.classList.add('hidden');
                select.classList.remove('hidden');
                toggleText.innerText = '+ Enter custom name';
            }
        }

        function openRbacMappingModal() {
            document.getElementById('rbac-edit-id').value = '';
            document.getElementById('rbac-description').value = '';
            document.getElementById('modal-rbac-title').innerText = 'Add Role Mapping';
            isCustomPrincipalMode = false;
            document.getElementById('rbac-principal-custom').classList.add('hidden');
            document.getElementById('rbac-principal-select').classList.remove('hidden');
            document.getElementById('rbac-custom-toggle-text').innerText = '+ Enter custom name';

            document.getElementById('modal-rbac-mapping').classList.remove('hidden');
            loadAdPrincipals();
        }

        function closeRbacMappingModal() {
            document.getElementById('modal-rbac-mapping').classList.add('hidden');
        }

        async function handleSaveRbacMapping(e) {
            e.preventDefault();
            const btn = document.getElementById('rbac-save-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Saving...';

            let principalName = '';
            if (isCustomPrincipalMode) {
                principalName = document.getElementById('rbac-principal-custom').value.trim();
            } else {
                principalName = document.getElementById('rbac-principal-select').value.trim();
            }

            if (!principalName) {
                alert('Please select or enter an Active Directory principal name.');
                btn.disabled = false;
                btn.innerHTML = 'Save Role Mapping';
                return;
            }

            const payload = {
                principal_type: document.getElementById('rbac-principal-type').value,
                principal_name: principalName,
                role: document.getElementById('rbac-assigned-role').value,
                description: document.getElementById('rbac-description').value.trim()
            };

            try {
                const res = await fetch(`${API_BASE}/rbac/mappings`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to save mapping');
                closeRbacMappingModal();
                fetchRbacMappings();
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = 'Save Role Mapping';
            }
        }

        async function deleteRbacMapping(id, name) {
            if (!confirm(`Are you sure you want to remove the role mapping for '${name}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/rbac/mappings/${id}`, {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to delete mapping');
                fetchRbacMappings();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        // ==================== SYSTEM ACCESS CONTROL & SECURITY CONTROLS ====================
        let currentRbacSubTab = 'mappings';

        function switchRbacSubTab(tabName) {
            currentRbacSubTab = tabName;
            const subtabs = ['mappings', 'timeout', 'sessions', 'hardening'];
            subtabs.forEach(t => {
                const view = document.getElementById(`rbac-view-${t}`);
                const btn = document.getElementById(`rbac-subtab-btn-${t}`);
                if (view) view.classList.add('hidden');
                if (btn) {
                    btn.classList.remove('bg-amber-600', 'text-white', 'shadow-sm');
                    btn.classList.add('bg-slate-800', 'text-slate-300');
                }
            });

            const activeView = document.getElementById(`rbac-view-${tabName}`);
            const activeBtn = document.getElementById(`rbac-subtab-btn-${tabName}`);
            if (activeView) activeView.classList.remove('hidden');
            if (activeBtn) {
                activeBtn.classList.remove('bg-slate-800', 'text-slate-300');
                activeBtn.classList.add('bg-amber-600', 'text-white', 'shadow-sm');
            }

            const actionsDiv = document.getElementById('rbac-header-actions');
            if (actionsDiv) {
                if (tabName === 'mappings') {
                    actionsDiv.innerHTML = `
                        <button onclick="fetchRbacMappings()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition flex items-center gap-1.5 border border-slate-700">
                            <i class="fa-solid fa-arrows-rotate"></i> Refresh
                        </button>
                        <button onclick="openRbacMappingModal()" class="px-3.5 py-2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-semibold rounded-lg shadow-lg shadow-amber-600/30 transition flex items-center gap-1.5">
                            <i class="fa-solid fa-plus"></i> Add Role Mapping
                        </button>
                    `;
                } else if (tabName === 'sessions') {
                    actionsDiv.innerHTML = `
                        <button onclick="fetchActiveSessions()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition flex items-center gap-1.5 border border-slate-700">
                            <i class="fa-solid fa-arrows-rotate"></i> Refresh Sessions
                        </button>
                    `;
                } else if (tabName === 'hardening') {
                    actionsDiv.innerHTML = `
                        <button onclick="fetchSecuritySettings(); fetchFirewallStatus();" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition flex items-center gap-1.5 border border-slate-700">
                            <i class="fa-solid fa-arrows-rotate"></i> Refresh Hardening & Firewall
                        </button>
                    `;
                } else {
                    actionsDiv.innerHTML = `
                        <button onclick="fetchSecuritySettings()" class="px-3 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition flex items-center gap-1.5 border border-slate-700">
                            <i class="fa-solid fa-arrows-rotate"></i> Reload Baseline
                        </button>
                    `;
                }
            }

            if (tabName === 'mappings') fetchRbacMappings();
            else if (tabName === 'sessions') fetchActiveSessions();
            else fetchSecuritySettings();
        }

        let cachedSecuritySettings = {};

        async function fetchSecuritySettings() {
            try {
                const res = await fetch(`${API_BASE}/security/settings`, { headers: getAuthHeaders() });
                if (!res.ok) return;
                const data = await res.json();
                cachedSecuritySettings = data;

                // Client IP & Status
                const ipEl = document.getElementById('sec-current-client-ip');
                if (ipEl) ipEl.innerText = data.current_client_ip || '127.0.0.1';

                const sshStat = document.getElementById('sec-stat-ssh');
                if (sshStat) {
                    sshStat.innerHTML = data.ssh_service_active
                        ? '<i class="fa-solid fa-circle-check text-emerald-400"></i> <span class="text-emerald-400">ACTIVE</span>'
                        : '<i class="fa-solid fa-circle-xmark text-rose-400"></i> <span class="text-rose-400">INACTIVE</span>';
                }
                const snmpStat = document.getElementById('sec-stat-snmp');
                if (snmpStat) {
                    snmpStat.innerHTML = data.snmp_service_active
                        ? '<i class="fa-solid fa-circle-check text-emerald-400"></i> <span class="text-emerald-400">ACTIVE</span>'
                        : '<i class="fa-solid fa-circle-xmark text-rose-400"></i> <span class="text-rose-400">INACTIVE</span>';
                }

                // Timeout form
                const idleEl = document.getElementById('sec-idle-timeout');
                if (idleEl) idleEl.value = data.session_idle_timeout_min.toString();
                const lifeEl = document.getElementById('sec-max-lifetime');
                if (lifeEl) lifeEl.value = data.session_max_lifetime_hours.toString();
                const failEl = document.getElementById('sec-max-failed');
                if (failEl) failEl.value = data.max_failed_logins.toString();
                const lockEl = document.getElementById('sec-lockout-duration');
                if (lockEl) lockEl.value = data.lockout_duration_min.toString();

                // Save idle timeout to localStorage for instant client monitor update
                localStorage.setItem('zclockid_idle_timeout_min', data.session_idle_timeout_min.toString());

                // Subnets form
                const guiSub = document.getElementById('sec-subnets-gui');
                if (guiSub) guiSub.value = data.allowed_subnets_gui;
                const sshSub = document.getElementById('sec-subnets-ssh');
                if (sshSub) sshSub.value = data.allowed_subnets_ssh;
                const snmpSub = document.getElementById('sec-subnets-snmp');
                if (snmpSub) snmpSub.value = data.allowed_subnets_snmp;

                // Hardening form
                const rootEl = document.getElementById('sec-ssh-permit-root');
                if (rootEl) rootEl.value = data.ssh_permit_root.toString();
                const passEl = document.getElementById('sec-ssh-password-auth');
                if (passEl) passEl.value = data.ssh_password_auth.toString();
                const commEl = document.getElementById('sec-snmp-community');
                if (commEl) commEl.value = data.snmp_community || 'zclock_public';

                // Also refresh firewall status
                fetchFirewallStatus();

            } catch (err) {
                console.error("fetchSecuritySettings error:", err);
            }
        }

        function insertCurrentClientIp(targetId) {
            const ipEl = document.getElementById('sec-current-client-ip');
            const target = document.getElementById(targetId);
            if (!ipEl || !target) return;
            const ip = ipEl.innerText.trim();
            if (!ip || ip.includes('...')) return;

            const cidr = ip.includes(':') ? `${ip}/128` : `${ip}/32`;
            let cur = target.value.trim();
            if (cur === '0.0.0.0/0, ::/0' || cur === '0.0.0.0/0') {
                target.value = cidr;
            } else if (!cur.includes(ip)) {
                target.value = cur ? `${cur}, ${cidr}` : cidr;
            }
        }

        function insertCurrentClientIpIntoFirewall() {
            const ipEl = document.getElementById('sec-current-client-ip');
            const target = document.getElementById('fw-rule-source');
            if (!ipEl || !target) return;
            const ip = ipEl.innerText.trim();
            if (!ip || ip.includes('...')) return;

            const cidr = ip.includes(':') ? `${ip}/128` : `${ip}/32`;
            let cur = target.value.trim();
            if (cur.toLowerCase() === 'any' || cur === '0.0.0.0/0, ::/0' || cur === '0.0.0.0/0') {
                target.value = cidr;
            } else if (!cur.includes(ip)) {
                target.value = cur ? `${cur}, ${cidr}` : cidr;
            }
        }

        async function saveSecuritySettings(section) {
            const btn = document.getElementById(`btn-save-${section}`);
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Applying Security Baseline...';
            }

            const payload = {
                session_idle_timeout_min: parseInt(document.getElementById('sec-idle-timeout')?.value || cachedSecuritySettings.session_idle_timeout_min || 15, 10),
                session_max_lifetime_hours: parseInt(document.getElementById('sec-max-lifetime')?.value || cachedSecuritySettings.session_max_lifetime_hours || 8, 10),
                allowed_subnets_gui: document.getElementById('sec-subnets-gui')?.value.trim() || cachedSecuritySettings.allowed_subnets_gui || '0.0.0.0/0, ::/0',
                allowed_subnets_ssh: document.getElementById('sec-subnets-ssh')?.value.trim() || cachedSecuritySettings.allowed_subnets_ssh || '0.0.0.0/0, ::/0',
                allowed_subnets_snmp: document.getElementById('sec-subnets-snmp')?.value.trim() || cachedSecuritySettings.allowed_subnets_snmp || '192.168.1.0/24, 10.10.0.0/24, 127.0.0.1/32',
                snmp_community: document.getElementById('sec-snmp-community')?.value.trim() || cachedSecuritySettings.snmp_community || 'zclock_public',
                max_failed_logins: parseInt(document.getElementById('sec-max-failed')?.value || cachedSecuritySettings.max_failed_logins || 5, 10),
                lockout_duration_min: parseInt(document.getElementById('sec-lockout-duration')?.value || cachedSecuritySettings.lockout_duration_min || 15, 10),
                ssh_permit_root: parseInt(document.getElementById('sec-ssh-permit-root')?.value || cachedSecuritySettings.ssh_permit_root || 0, 10),
                ssh_password_auth: parseInt(document.getElementById('sec-ssh-password-auth')?.value || cachedSecuritySettings.ssh_password_auth || 1, 10)
            };

            try {
                const res = await fetch(`${API_BASE}/security/settings`, {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to update security settings');

                if (section === 'hardening') {
                    alert(`OpenSSH Hardening Baseline Updated!\n\nOpenSSH Service: ${data.ssh_result}`);
                } else {
                    alert(`Security Baseline Updated!\n\n${data.message}`);
                }
                fetchSecuritySettings();
            } catch (err) {
                alert(`Security Update Rejected:\n${err.message}`);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    if (section === 'timeout') btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Save Session & Timeout Policy';
                    else if (section === 'subnets') btn.innerHTML = '<i class="fa-solid fa-network-wired"></i> Apply Network Access ACLs';
                    else if (section === 'hardening') btn.innerHTML = '<i class="fa-solid fa-user-shield"></i> Apply OpenSSH Hardening Baseline';
                }
            }
        }

        async function fetchActiveSessions() {
            const tbody = document.getElementById('sec-sessions-tbody');
            if (!tbody) return;
            try {
                const res = await fetch(`${API_BASE}/security/sessions`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to load active sessions');
                const sessions = await res.json();

                if (sessions.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="8" class="py-6 text-center text-slate-500">No active administrative sessions found.</td></tr>';
                    return;
                }

                tbody.innerHTML = sessions.map(s => {
                    const loggedInStr = escapeHtml(new Date(s.created_at * 1000).toLocaleString());
                    const lastActiveStr = escapeHtml(new Date(s.last_active * 1000).toLocaleTimeString());
                    const safeUser = escapeHtml(s.username);
                    const safeRole = escapeHtml(s.role);
                    const safeIp = escapeHtml(s.ip_address);
                    const safeUa = escapeHtml(s.user_agent || 'Unknown');
                    const safeToken = escapeHtml(s.token_prefix);

                    const statusBadge = s.is_current
                        ? '<span class="px-2 py-0.5 text-[10px] rounded bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono font-bold"><i class="fa-solid fa-circle mr-1 text-[8px] animate-pulse"></i> CURRENT SESSION</span>'
                        : '<span class="px-2 py-0.5 text-[10px] rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">ACTIVE</span>';

                    const actionBtn = s.is_current
                        ? '<span class="text-[11px] text-slate-600 font-mono italic">Current User</span>'
                        : `<button data-action="terminate-session" data-token="${safeToken}" class="px-2 py-1 bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded text-[11px] transition flex items-center gap-1 ml-auto"><i class="fa-solid fa-power-off"></i> Revoke</button>`;

                    let userBadge = s.username === 'admin'
                        ? `<span class="font-bold text-white">${safeUser}</span> <span class="px-1.5 py-0.2 text-[9px] rounded bg-amber-950/80 text-amber-400 border border-amber-800/40 ml-1 font-mono">BREAK-GLASS</span>`
                        : `<span class="font-bold text-white">${safeUser}</span>`;

                    return `
                        <tr class="hover:bg-slate-800/30 transition">
                            <td class="py-3 px-4">${userBadge}</td>
                            <td class="py-3 px-4 font-mono text-indigo-400 font-semibold">${safeRole}</td>
                            <td class="py-3 px-4 font-mono text-slate-300">${safeIp}</td>
                            <td class="py-3 px-4 text-slate-400 max-w-xs truncate" title="${safeUa}">${safeUa}</td>
                            <td class="py-3 px-4 text-slate-400 whitespace-nowrap">${loggedInStr}</td>
                            <td class="py-3 px-4 text-slate-400 whitespace-nowrap">${lastActiveStr}</td>
                            <td class="py-3 px-4">${statusBadge}</td>
                            <td class="py-3 px-4 text-right">${actionBtn}</td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="8" class="py-6 text-center text-rose-400">Error loading sessions: ${escapeHtml(err.message)}</td></tr>`;
            }
        }

        async function terminateSession(tokenPrefix) {
            if (!confirm(`Are you sure you want to terminate administrative session (${tokenPrefix})? The administrator will be immediately disconnected.`)) return;
            try {
                const res = await fetch(`${API_BASE}/security/sessions/${encodeURIComponent(tokenPrefix)}`, {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to terminate session');
                fetchActiveSessions();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        async function terminateAllOtherSessions() {
            if (!confirm("Are you sure you want to terminate ALL other active administrator sessions across all devices? All other admins will be logged out.")) return;
            try {
                const res = await fetch(`${API_BASE}/security/sessions/terminate-others`, {
                    method: 'POST',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to terminate sessions');
                alert(data.message);
                fetchActiveSessions();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        // ==================== APPLIANCE HOST FIREWALL & PORT PROTECTION ====================
        let cachedFirewallRules = [];

        function escapeFwText(str) {
            if (!str) return '';
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;');
        }

        function updateFirewallToggleVisual(isEnabled) {
            const track = document.getElementById('fw-toggle-track');
            const stateText = document.getElementById('fw-toggle-state-text');
            if (track) {
                if (isEnabled) {
                    track.classList.remove('bg-rose-600', 'bg-rose-700', 'bg-slate-700');
                    track.classList.add('bg-emerald-600');
                } else {
                    track.classList.remove('bg-emerald-600');
                    track.classList.add('bg-rose-600');
                }
            }
            if (stateText) {
                stateText.innerText = isEnabled ? 'ON' : 'OFF';
                stateText.className = isEnabled
                    ? 'text-xs font-mono font-bold text-emerald-400'
                    : 'text-xs font-mono font-bold text-rose-400';
            }
        }

        async function fetchFirewallStatus() {
            try {
                const res = await fetch(`${API_BASE}/security/firewall/status`, { headers: getAuthHeaders() });
                if (!res.ok) return;
                const data = await res.json();
                
                // Master switch
                const toggle = document.getElementById('fw-master-toggle');
                if (toggle) toggle.checked = !!data.is_enabled;
                updateFirewallToggleVisual(!!data.is_enabled);

                // Status badge
                const badge = document.getElementById('fw-status-badge');
                if (badge) {
                    if (data.is_enabled) {
                        badge.className = "px-2.5 py-0.5 text-xs rounded-full bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 font-mono font-bold flex items-center gap-1.5";
                        badge.innerHTML = '<i class="fa-solid fa-circle text-[8px] animate-pulse"></i> ACTIVE (ENFORCING)';
                    } else {
                        badge.className = "px-2.5 py-0.5 text-xs rounded-full bg-slate-800 border border-slate-700 text-slate-400 font-mono font-bold flex items-center gap-1.5";
                        badge.innerHTML = '<i class="fa-solid fa-circle text-[8px]"></i> DISABLED';
                    }
                }

                // KPIs
                const kpiCount = document.getElementById('fw-rules-kpi-count');
                if (kpiCount) {
                    kpiCount.innerHTML = `<i class="fa-solid fa-list-check"></i> ${escapeHtml(data.total_rules_count || 0)} Rules (${escapeHtml(data.active_rules_count || 0)} Active)`;
                }
                const badgeCount = document.getElementById('fw-rules-badge-count');
                if (badgeCount) badgeCount.textContent = data.total_rules_count || 0;

                cachedFirewallRules = data.rules || [];
                const searchVal = document.getElementById('fw-search-input')?.value || '';
                renderFirewallRules(searchVal);
            } catch (err) {
                console.error("fetchFirewallStatus error:", err);
            }
        }

        function filterFirewallRules() {
            const query = document.getElementById('fw-search-input')?.value || '';
            renderFirewallRules(query);
        }

        function renderFirewallRules(query = '') {
            const tbody = document.getElementById('fw-rules-body');
            if (!tbody) return;

            let rules = cachedFirewallRules;
            const q = query.trim().toLowerCase();
            if (q) {
                rules = rules.filter(r =>
                    (r.port && r.port.toLowerCase().includes(q)) ||
                    (r.source && r.source.toLowerCase().includes(q)) ||
                    (r.protocol && r.protocol.toLowerCase().includes(q)) ||
                    (r.action && r.action.toLowerCase().includes(q)) ||
                    (r.comment && r.comment.toLowerCase().includes(q))
                );
            }

            if (rules.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" class="py-8 text-center text-slate-500 font-sans">
                            <i class="fa-solid fa-shield text-slate-600 text-2xl block mb-2"></i>
                            ${q ? 'No rules matched your search filter.' : 'No firewall rules configured.'}
                            <br><span class="text-[11px] text-slate-400">Click <b>Add Rule</b> above or <b>Revert to Default Template</b> to restore recommended baseline ports.</span>
                        </td>
                    </tr>
                `;
                return;
            }

            tbody.innerHTML = rules.map(r => {
                const actionBadge = r.action === 'ALLOW'
                    ? `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 font-mono"><i class="fa-solid fa-check mr-1"></i>ALLOW</span>`
                    : `<span class="px-2 py-0.5 text-[10px] font-bold rounded bg-rose-950/80 border border-rose-800/60 text-rose-400 font-mono"><i class="fa-solid fa-ban mr-1"></i>DENY</span>`;

                const stateBadge = r.is_enabled
                    ? `<button data-action="toggle-fw-rule" data-id="${r.id}" data-enable="false" title="Click to disable rule" class="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 border border-emerald-800 text-emerald-400 hover:bg-emerald-900/60 transition"><i class="fa-solid fa-power-off mr-1"></i>ENABLED</button>`
                    : `<button data-action="toggle-fw-rule" data-id="${r.id}" data-enable="true" title="Click to enable rule" class="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 border border-slate-700 text-slate-400 hover:bg-slate-700 transition"><i class="fa-solid fa-pause mr-1"></i>DISABLED</button>`;

                const protoBadge = `<span class="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">${escapeHtml(r.protocol)}</span>`;
                const portDisplay = `<span class="font-bold text-white font-mono">${escapeHtml(r.port)}</span>`;
                const sourceDisplay = r.source === 'Any'
                    ? `<span class="text-slate-400">Any (0.0.0.0/0)</span>`
                    : `<span class="text-amber-400 font-mono">${escapeHtml(r.source)}</span>`;

                return `
                    <tr class="hover:bg-slate-800/30 transition">
                        <td class="py-3 px-3">${actionBadge}</td>
                        <td class="py-3 px-3">${protoBadge}</td>
                        <td class="py-3 px-3">${portDisplay}</td>
                        <td class="py-3 px-3">${sourceDisplay}</td>
                        <td class="py-3 px-3 text-slate-300 font-sans text-xs">${r.comment ? escapeHtml(r.comment) : '<span class="text-slate-500 italic">No description</span>'}</td>
                        <td class="py-3 px-3">${stateBadge}</td>
                        <td class="py-3 px-3 text-right">
                            <div class="flex items-center justify-end gap-1.5">
                                <button data-action="edit-fw-rule" data-id="${r.id}" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition flex items-center gap-1 border border-slate-700" title="Edit Rule">
                                    <i class="fa-solid fa-pen-to-square text-indigo-400"></i> Edit
                                </button>
                                <button data-action="delete-fw-rule" data-id="${r.id}" class="px-2.5 py-1 bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 rounded text-xs transition flex items-center gap-1" title="Delete Rule">
                                    <i class="fa-solid fa-trash-can"></i> Delete
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        async function resetFirewallTemplate() {
            if (!confirm("Are you sure you want to revert all firewall rules to the recommended Active Directory default template?\n\nThis will restore the 20 standard ports required for domain controller, DNS, Kerberos, SMB, RPC, and FreeRADIUS functions.")) return;
            try {
                const res = await fetch(`${API_BASE}/security/firewall/reset-template`, {
                    method: 'POST',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to reset rules template');
                alert(data.message || 'Firewall rules reverted to recommended template.');
                fetchFirewallStatus();
            } catch (err) {
                alert(`Error resetting template: ${err.message}`);
            }
        }

        async function toggleFirewallMaster(enable) {
            updateFirewallToggleVisual(enable);
            const stateText = document.getElementById('fw-toggle-state-text');
            if (stateText) {
                stateText.innerText = enable ? 'ENABLING...' : 'DISABLING...';
                stateText.className = 'text-xs font-mono font-bold text-amber-400';
            }
            try {
                const res = await fetch(`${API_BASE}/security/firewall/toggle`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ is_enabled: enable, enabled: enable })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to toggle firewall state');
                alert(data.message || (enable ? 'Firewall enabled.' : 'Firewall disabled.'));
                fetchFirewallStatus();
            } catch (err) {
                alert(`Error changing firewall state: ${err.message}`);
                fetchFirewallStatus();
            }
        }

        async function applyFirewallChanges() {
            try {
                const res = await fetch(`${API_BASE}/security/firewall/apply`, {
                    method: 'POST',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to synchronize firewall');
                alert(data.message || 'Firewall rules synchronized successfully.');
                fetchFirewallStatus();
            } catch (err) {
                alert(`Firewall synchronization error: ${err.message}`);
            }
        }

        function openFirewallRuleModal(ruleId = null) {
            const modal = document.getElementById('modal-firewall-rule');
            const title = document.getElementById('fw-modal-title');
            const editId = document.getElementById('fw-rule-edit-id');
            const action = document.getElementById('fw-rule-action');
            const proto = document.getElementById('fw-rule-proto');
            const port = document.getElementById('fw-rule-port');
            const source = document.getElementById('fw-rule-source');
            const comment = document.getElementById('fw-rule-comment');
            const enabled = document.getElementById('fw-rule-enabled');

            if (!modal) return;

            if (ruleId) {
                const rule = cachedFirewallRules.find(r => r.id === ruleId);
                if (!rule) return;
                if (title) title.innerText = "Edit Firewall Rule";
                if (editId) editId.value = rule.id;
                if (action) action.value = rule.action;
                if (proto) proto.value = rule.protocol;
                if (port) port.value = rule.port;
                if (source) source.value = rule.source;
                if (comment) comment.value = rule.comment || '';
                if (enabled) enabled.checked = !!rule.is_enabled;
            } else {
                if (title) title.innerText = "Add Firewall Rule";
                if (editId) editId.value = "";
                if (action) action.value = "ALLOW";
                if (proto) proto.value = "TCP";
                if (port) port.value = "";
                if (source) source.value = "Any";
                if (comment) comment.value = "";
                if (enabled) enabled.checked = true;
            }

            modal.classList.remove('hidden');
        }

        function closeFirewallRuleModal() {
            const modal = document.getElementById('modal-firewall-rule');
            if (modal) modal.classList.add('hidden');
        }

        function editFirewallRule(ruleId) {
            openFirewallRuleModal(ruleId);
        }

        async function handleFirewallRuleSubmit(event) {
            event.preventDefault();
            const editId = document.getElementById('fw-rule-edit-id')?.value;
            const action = document.getElementById('fw-rule-action')?.value || 'ALLOW';
            const protocol = document.getElementById('fw-rule-proto')?.value || 'TCP';
            const port = document.getElementById('fw-rule-port')?.value.trim();
            const source = document.getElementById('fw-rule-source')?.value.trim() || 'Any';
            const comment = document.getElementById('fw-rule-comment')?.value.trim() || '';
            const is_enabled = document.getElementById('fw-rule-enabled')?.checked ?? true;

            if (!port) {
                alert('Port or port range is required (e.g. 8080 or 3000-3005).');
                return;
            }

            const payload = { action, protocol, port, source, comment, is_enabled };
            const btn = document.getElementById('btn-fw-rule-submit');
            if (btn) btn.disabled = true;

            try {
                const url = editId
                    ? `${API_BASE}/security/firewall/rules/${editId}`
                    : `${API_BASE}/security/firewall/rules`;
                const method = editId ? 'PUT' : 'POST';

                const res = await fetch(url, {
                    method: method,
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to save firewall rule');

                closeFirewallRuleModal();
                fetchFirewallStatus();
            } catch (err) {
                alert(`Error saving rule: ${err.message}`);
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        async function deleteFirewallRule(ruleId) {
            if (!confirm("Are you sure you want to permanently delete this firewall rule?")) return;
            try {
                const res = await fetch(`${API_BASE}/security/firewall/rules/${ruleId}`, {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to delete rule');
                fetchFirewallStatus();
            } catch (err) {
                alert(`Error deleting rule: ${err.message}`);
            }
        }

        async function toggleFwRuleState(ruleId, newState) {
            try {
                const res = await fetch(`${API_BASE}/security/firewall/rules/${ruleId}/toggle`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ is_enabled: newState })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to toggle rule');
                fetchFirewallStatus();
            } catch (err) {
                alert(`Error toggling rule: ${err.message}`);
            }
        }

        // ==================== MVP 3: API KEYS & TOKENS ====================
        async function fetchApiKeys() {
            const tbody = document.getElementById('api-keys-tbody');
            if (!tbody) return;
            try {
                const res = await fetch(`${API_BASE}/api-keys`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to load API keys');
                const keys = await res.json();

                document.getElementById('api-keys-count-pill').textContent = `${keys.length} keys`;

                if (keys.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="7" class="py-6 text-center text-slate-500">No API keys issued. Click "Generate New Key" to create a programmatic token.</td></tr>';
                    return;
                }

                tbody.innerHTML = keys.map(k => {
                    const scopesBadges = k.scopes.map(s => {
                        let color = 'bg-slate-800 text-slate-300 border-slate-700';
                        if (s === 'admin:all') color = 'bg-yellow-950 text-yellow-400 border-yellow-800';
                        else if (s.includes('manage')) color = 'bg-indigo-950 text-indigo-400 border-indigo-800';
                        else if (s.includes('read')) color = 'bg-emerald-950 text-emerald-400 border-emerald-800';
                        return `<span class="px-1.5 py-0.5 text-[9px] rounded border font-mono ${color}">${escapeHtml(s)}</span>`;
                    }).join(' ');

                    const expiryStr = k.expires_at ? escapeHtml(new Date(k.expires_at * 1000).toLocaleDateString()) : 'Never';
                    const lastUsedStr = k.last_used_at ? escapeHtml(new Date(k.last_used_at * 1000).toLocaleString()) : 'Never';
                    const safeName = escapeHtml(k.name);
                    const safeKeyPrefix = escapeHtml(k.key_prefix);
                    const safeCidr = escapeHtml(k.cidr_whitelist || '');

                    return `
                        <tr class="hover:bg-slate-800/30 transition">
                            <td class="py-3 px-4 font-semibold text-white">${safeName}</td>
                            <td class="py-3 px-4 font-mono text-yellow-400 font-bold">${safeKeyPrefix}</td>
                            <td class="py-3 px-4"><div class="flex flex-wrap gap-1">${scopesBadges}</div></td>
                            <td class="py-3 px-4 font-mono text-slate-400">${safeCidr}</td>
                            <td class="py-3 px-4 font-mono text-slate-400">${expiryStr}</td>
                            <td class="py-3 px-4 font-mono text-slate-500 text-[11px]">${lastUsedStr}</td>
                            <td class="py-3 px-4 text-right">
                                <button data-action="revoke-api-key" data-id="${k.id}" data-name="${safeName}" class="px-2.5 py-1 text-slate-400 hover:text-rose-400 hover:bg-rose-950/30 rounded transition text-xs">
                                    <i class="fa-solid fa-ban mr-1"></i> Revoke
                                </button>
                            </td>
                        </tr>
                    `;
                }).join('');
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-rose-400 font-mono">Error: ${escapeHtml(err.message)}</td></tr>`;
            }
        }

        function openApiKeyCreateModal() {
            document.getElementById('apikey-name').value = '';
            document.getElementById('apikey-cidr').value = '0.0.0.0/0';
            document.getElementById('modal-api-key-create').classList.remove('hidden');
        }

        function closeApiKeyCreateModal() {
            document.getElementById('modal-api-key-create').classList.add('hidden');
        }

        async function handleCreateApiKey(e) {
            e.preventDefault();
            const checkedScopes = Array.from(document.querySelectorAll('input[name="api_scope"]:checked')).map(cb => cb.value);
            if (checkedScopes.length === 0) {
                alert('Please select at least one permission scope.');
                return;
            }

            const btn = document.getElementById('apikey-submit-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Generating...';

            const daysVal = parseInt(document.getElementById('apikey-expires').value);

            const payload = {
                name: document.getElementById('apikey-name').value.trim(),
                scopes: checkedScopes,
                cidr_whitelist: document.getElementById('apikey-cidr').value.trim() || '0.0.0.0/0',
                expires_days: daysVal > 0 ? daysVal : null
            };

            try {
                const res = await fetch(`${API_BASE}/api-keys`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to create API key');

                closeApiKeyCreateModal();
                fetchApiKeys();

                // Show token reveal modal
                document.getElementById('reveal-token-input').value = data.full_api_key;
                document.getElementById('modal-api-key-token-reveal').classList.remove('hidden');
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = 'Generate Token';
            }
        }

        function closeApiKeyTokenRevealModal() {
            document.getElementById('modal-api-key-token-reveal').classList.add('hidden');
        }

        function copyRevealedToken() {
            const input = document.getElementById('reveal-token-input');
            input.select();
            navigator.clipboard.writeText(input.value).then(() => {
                const btn = document.getElementById('reveal-copy-btn');
                btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
                setTimeout(() => { btn.innerHTML = '<i class="fa-solid fa-copy"></i> Copy'; }, 2000);
            });
        }

        async function revokeApiKey(id, name) {
            if (!confirm(`Permanently revoke and invalidate API key '${name}'? Any service using this key will immediately fail authentication.`)) return;
            try {
                const res = await fetch(`${API_BASE}/api-keys/${id}`, {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to revoke API key');
                fetchApiKeys();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        // ==================== MVP 3: SSL/TLS CERTIFICATES ====================
        async function fetchActiveCert() {
            try {
                const res = await fetch(`${API_BASE}/certificates/active`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to inspect active certificate');
                const cert = await res.json();

                // Update Inspector Card
                document.getElementById('cert-subject-cn').innerText = cert.subject;
                document.getElementById('cert-issuer').innerText = `Issuer: ${cert.issuer}`;
                document.getElementById('cert-valid-from').innerText = `Valid from: ${cert.valid_from}`;
                document.getElementById('cert-valid-to').innerText = cert.valid_to;
                document.getElementById('cert-days-remaining').innerText = `${cert.days_remaining} days remaining`;
                document.getElementById('cert-sig-alg').innerText = cert.signature_algorithm;
                document.getElementById('cert-serial').innerText = cert.serial_number;

                const statusBadge = document.getElementById('cert-status-badge');
                if (cert.status === 'VALID') {
                    statusBadge.className = 'px-2.5 py-1 text-xs font-bold rounded-full bg-emerald-950 border border-emerald-800 text-emerald-400 font-mono';
                    statusBadge.innerText = 'VALID';
                } else if (cert.status === 'EXPIRING_SOON') {
                    statusBadge.className = 'px-2.5 py-1 text-xs font-bold rounded-full bg-amber-950 border border-amber-800 text-amber-400 font-mono';
                    statusBadge.innerText = 'EXPIRING SOON';
                } else {
                    statusBadge.className = 'px-2.5 py-1 text-xs font-bold rounded-full bg-rose-950 border border-rose-800 text-rose-400 font-mono';
                    statusBadge.innerText = 'EXPIRED';
                }

                const typeBadge = document.getElementById('cert-type-badge');
                typeBadge.innerText = cert.is_self_signed ? 'SELF-SIGNED' : 'CA-SIGNED / ENTERPRISE';

                const sansBox = document.getElementById('cert-sans-container');
                if (cert.san_list && cert.san_list.length > 0) {
                    sansBox.innerHTML = cert.san_list.map(s => `
                        <span class="px-2 py-0.5 text-[10px] rounded bg-slate-800 border border-slate-700 text-teal-300 font-mono">${escapeHtml(s)}</span>
                    `).join('');
                } else {
                    sansBox.innerHTML = '<span class="text-slate-500 text-[11px]">No SANs found</span>';
                }
            } catch (err) {
                console.error('Cert inspection error:', err);
            }
        }

        async function handleGenerateSelfSignedCert(e) {
            e.preventDefault();
            if (!confirm('Generating a new self-signed certificate will restart HTTPS sessions. Proceed?')) return;

            const btn = document.getElementById('cert-gen-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Generating & Reloading Nginx...';

            const sans = document.getElementById('cert-gen-sans').value.split(',').map(s => s.trim()).filter(Boolean);
            const payload = {
                common_name: document.getElementById('cert-gen-cn').value.trim(),
                san_list: sans,
                validity_days: parseInt(document.getElementById('cert-gen-days').value) || 365,
                organization: document.getElementById('cert-gen-org').value.trim() || 'ZclockID Enterprise'
            };

            try {
                const res = await fetch(`${API_BASE}/certificates/self-signed`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to generate self-signed certificate');
                alert(data.message || 'New self-signed certificate generated and activated.');
                fetchActiveCert();
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-rotate"></i> Generate & Reload Nginx';
            }
        }

        async function handleUploadCustomCert(e) {
            e.preventDefault();
            const certPem = document.getElementById('cert-upload-cert').value.trim();
            const keyPem = document.getElementById('cert-upload-key').value.trim();
            const chainPem = document.getElementById('cert-upload-chain').value.trim();

            if (!certPem || !keyPem) {
                alert('Both Certificate PEM and Private Key PEM are required.');
                return;
            }

            const btn = document.getElementById('cert-upload-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Validating & Installing...';

            const payload = { cert_pem: certPem, key_pem: keyPem, chain_pem: chainPem || null };

            try {
                const res = await fetch(`${API_BASE}/certificates/upload`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to install custom certificate');
                alert(data.message || 'Enterprise certificate validated and installed successfully.');
                document.getElementById('cert-upload-cert').value = '';
                document.getElementById('cert-upload-key').value = '';
                document.getElementById('cert-upload-chain').value = '';
                fetchActiveCert();
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-shield-check"></i> Validate & Install';
            }
        }

        async function handleGenerateCsr(e) {
            e.preventDefault();
            const btn = document.getElementById('csr-gen-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Generating CSR...';

            const sans = document.getElementById('csr-sans').value.split(',').map(s => s.trim()).filter(Boolean);
            const payload = {
                common_name: document.getElementById('csr-cn').value.trim(),
                organization: document.getElementById('csr-org').value.trim(),
                city: document.getElementById('csr-city').value.trim(),
                state: document.getElementById('csr-state').value.trim(),
                country: document.getElementById('csr-country').value.trim().toUpperCase(),
                san_list: sans
            };

            try {
                const res = await fetch(`${API_BASE}/certificates/csr`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to generate CSR');

                document.getElementById('csr-output-textarea').value = data.csr_pem;
                document.getElementById('modal-cert-csr-view').classList.remove('hidden');
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-file-pen"></i> Generate Request (CSR)';
            }
        }

        function closeCsrModal() {
            document.getElementById('modal-cert-csr-view').classList.add('hidden');
        }

        function copyCsrText() {
            const ta = document.getElementById('csr-output-textarea');
            ta.select();
            navigator.clipboard.writeText(ta.value).then(() => {
                alert('CSR copied to clipboard.');
            });
        }

        // ==================== MVP 3: SYSLOG & LIVE LOG STREAMING ====================
        let currentLogCategory = 'samba';
        let logFilterTimer = null;

        async function fetchSyslogSettings() {
            try {
                const res = await fetch(`${API_BASE}/syslog/settings`, { headers: getAuthHeaders() });
                if (!res.ok) return;
                const data = await res.json();

                const toggle = document.getElementById('syslog-enabled-toggle');
                if (toggle) toggle.checked = !!data.enabled;
                const label = document.getElementById('syslog-toggle-label');
                if (label) label.innerText = data.enabled ? 'Active Forwarding' : 'Disabled';

                document.getElementById('syslog-host').value = data.remote_host || '';
                document.getElementById('syslog-port').value = data.remote_port || 514;
                document.getElementById('syslog-protocol').value = data.protocol || 'UDP';
                document.getElementById('syslog-format').value = data.log_format || 'RFC5424';

                document.getElementById('syslog-send-samba').checked = !!data.send_samba_logs;
                document.getElementById('syslog-send-radius').checked = !!data.send_radius_logs;
                document.getElementById('syslog-send-auth').checked = !!data.send_auth_logs;
                document.getElementById('syslog-send-system').checked = !!data.send_system_logs;
            } catch (err) {
                console.error('Syslog settings error:', err);
            }
        }

        async function handleSaveSyslogConfig(e) {
            e.preventDefault();
            const payload = {
                enabled: document.getElementById('syslog-enabled-toggle').checked,
                remote_host: document.getElementById('syslog-host').value.trim(),
                remote_port: parseInt(document.getElementById('syslog-port').value) || 514,
                protocol: document.getElementById('syslog-protocol').value,
                facility: 'local0',
                log_format: document.getElementById('syslog-format').value,
                send_samba_logs: document.getElementById('syslog-send-samba').checked,
                send_radius_logs: document.getElementById('syslog-send-radius').checked,
                send_auth_logs: document.getElementById('syslog-send-auth').checked,
                send_system_logs: document.getElementById('syslog-send-system').checked
            };

            try {
                const res = await fetch(`${API_BASE}/syslog/settings`, {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to save settings');
                alert('Syslog forwarder configuration saved successfully.');
                fetchSyslogSettings();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        async function sendSyslogTestProbe() {
            try {
                const res = await fetch(`${API_BASE}/syslog/test`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ message: 'ZclockID Syslog Test Probe Event' })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to transmit probe');
                alert(data.message || 'Probe packet transmitted successfully!');
            } catch (err) {
                alert(`Syslog Probe Failed: ${err.message}`);
            }
        }

        function setLogCategory(cat) {
            currentLogCategory = cat;
            ['samba', 'radius', 'auth', 'audit', 'system'].forEach(c => {
                const btn = document.getElementById(`logcat-${c}`);
                if (btn) {
                    if (c === cat) {
                        btn.className = 'px-3 py-1.5 rounded-lg bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 transition';
                    } else {
                        btn.className = 'px-3 py-1.5 rounded-lg text-slate-400 hover:text-slate-200 transition';
                    }
                }
            });
            fetchLiveSyslog();
        }

        async function fetchLiveSyslog() {
            const terminal = document.getElementById('live-log-terminal');
            if (!terminal) return;

            const lines = document.getElementById('live-log-lines').value || 100;
            const filter = document.getElementById('live-log-filter').value.trim();

            let url = `${API_BASE}/syslog/logs?category=${currentLogCategory}&lines=${lines}`;
            if (filter) url += `&filter=${encodeURIComponent(filter)}`;

            try {
                const res = await fetch(url, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to fetch daemon logs');
                const data = await res.json();
                const logs = data.logs || [];

                if (logs.length === 0) {
                    terminal.innerHTML = `<div class="text-slate-500 text-center py-8">No log entries found for [${escapeHtml(currentLogCategory)}]${filter ? ' matching filter' : ''}.</div>`;
                    return;
                }

                terminal.innerHTML = logs.map(l => {
                    let levelColor = 'text-emerald-400';
                    let levelBg = 'bg-emerald-950/40 border-emerald-800/40';
                    if (l.level === 'ERROR') {
                        levelColor = 'text-rose-400';
                        levelBg = 'bg-rose-950/40 border-rose-800/40';
                    } else if (l.level === 'WARN') {
                        levelColor = 'text-amber-400';
                        levelBg = 'bg-amber-950/40 border-amber-800/40';
                    }

                    return `
                        <div class="flex items-start gap-2 py-0.5 hover:bg-slate-900/50 rounded px-1">
                            <span class="text-slate-500 shrink-0 text-[11px]">${escapeHtml(l.timestamp)}</span>
                            <span class="px-1.5 py-0.2 rounded text-[9px] font-bold border ${levelBg} ${levelColor}">${escapeHtml(l.level)}</span>
                            <span class="text-slate-300 break-all">${escapeHtml(l.message)}</span>
                        </div>
                    `;
                }).join('');
                terminal.scrollTop = terminal.scrollHeight;
            } catch (err) {
                terminal.innerHTML = `<div class="text-rose-400 text-center py-6 font-mono">Error: ${escapeHtml(err.message)}</div>`;
            }
        }

        function debounceFilterLogs() {
            clearTimeout(logFilterTimer);
            logFilterTimer = setTimeout(fetchLiveSyslog, 300);
        }

        function copyLiveLogs() {
            const terminal = document.getElementById('live-log-terminal');
            if (!terminal) return;
            navigator.clipboard.writeText(terminal.innerText).then(() => {
                alert('Logs copied to clipboard.');
            });
        }

        function applyLiveLogLimitOptions(settings) {
            const sel = document.getElementById('live-log-lines');
            if (!sel || !settings) return;
            const maxLines = parseInt(settings.live_log_max_lines || 1000);
            const defLines = parseInt(settings.live_log_default_lines || 100);
            const candidates = [50, 100, 250, 500, 1000, 2000, 5000].filter(v => v <= maxLines);
            if (!candidates.includes(maxLines)) candidates.push(maxLines);
            const prevVal = parseInt(sel.value || defLines);
            sel.innerHTML = candidates.map(v => `<option value="${escapeHtml(v)}">${escapeHtml(v.toLocaleString())} lines</option>`).join('');
            const target = candidates.includes(prevVal) ? prevVal : (candidates.includes(defLines) ? defLines : candidates[0]);
            sel.value = String(target);
        }

        function _formatRetentionBadge(days) {
            const d = parseInt(days || 0);
            if (d === 0) return 'Unlimited';
            if (d % 30 === 0 && d >= 90) return `${d} Days (${d / 30} Mo)`;
            return `${d} Days Active`;
        }

        async function fetchLogRetentionSettings() {
            try {
                const res = await fetch(`${API_BASE}/syslog/retention`, { headers: getAuthHeaders() });
                if (!res.ok) return;
                const data = await res.json();
                const s = data.settings || {};
                const c = data.counts || {};

                // Update Compliance KPI card
                const retLbl = document.getElementById('audit-retention-label');
                const retSub = document.getElementById('audit-retention-sublabel');
                if (retLbl) retLbl.innerText = _formatRetentionBadge(s.audit_retention_days);
                if (retSub) {
                    const maxTxt = parseInt(s.audit_max_entries) === 0 ? 'Unlimited entries' : `Max ${parseInt(s.audit_max_entries).toLocaleString()} entries`;
                    retSub.innerText = `${maxTxt} • Click to configure`;
                }

                // Update Live Log dropdown limits
                applyLiveLogLimitOptions(s);

                // Update Retention Sub-Tab Volume Cards
                const setText = (id, val) => { const el = document.getElementById(id); if (el) el.innerText = val; };
                setText('ret-count-audit', (c.audit_events ?? 0).toLocaleString());
                setText('ret-count-reg', (c.self_registrations ?? 0).toLocaleString());
                setText('ret-count-sspr', (c.self_service_password_logs ?? 0).toLocaleString());
                setText('ret-count-radius', (c.radius_accounting ?? 0).toLocaleString());
                setText('ret-count-failed', (c.failed_login_attempts ?? 0).toLocaleString());
                setText('ret-last-pruned', s.last_pruned_at > 0 ? new Date(s.last_pruned_at * 1000).toLocaleString() : 'Never');

                // Populate form controls
                const setVal = (id, val) => { const el = document.getElementById(id); if (el && val !== undefined && val !== null) el.value = String(val); };
                setVal('ret-audit-days', s.audit_retention_days);
                setVal('ret-audit-max', s.audit_max_entries);
                setVal('ret-audit-ui', s.audit_ui_fetch_limit);
                setVal('ret-ss-days', s.self_service_retention_days);
                setVal('ret-ss-max', s.self_service_max_entries);
                setVal('ret-ss-ui', s.self_service_ui_fetch_limit);
                setVal('ret-live-default', s.live_log_default_lines);
                setVal('ret-live-max', s.live_log_max_lines);
                setVal('ret-radius-days', s.radius_retention_days);
                setVal('ret-radius-max', s.radius_max_entries);
                setVal('ret-radius-ui', s.radius_ui_fetch_limit);

                const autoToggle = document.getElementById('ret-auto-prune');
                if (autoToggle) autoToggle.checked = !!s.auto_prune_enabled;
                const autoLbl = document.getElementById('ret-auto-prune-label');
                if (autoLbl) autoLbl.innerText = s.auto_prune_enabled ? 'Auto-Prune Hourly' : 'Auto-Prune Paused';
            } catch (err) {
                console.error('Failed to load log retention settings:', err);
            }
        }

        async function handleSaveLogRetention(e) {
            e.preventDefault();
            const payload = {
                audit_retention_days: parseInt(document.getElementById('ret-audit-days').value),
                audit_max_entries: parseInt(document.getElementById('ret-audit-max').value),
                audit_ui_fetch_limit: parseInt(document.getElementById('ret-audit-ui').value),
                self_service_retention_days: parseInt(document.getElementById('ret-ss-days').value),
                self_service_max_entries: parseInt(document.getElementById('ret-ss-max').value),
                self_service_ui_fetch_limit: parseInt(document.getElementById('ret-ss-ui').value),
                live_log_default_lines: parseInt(document.getElementById('ret-live-default').value),
                live_log_max_lines: parseInt(document.getElementById('ret-live-max').value),
                radius_retention_days: parseInt(document.getElementById('ret-radius-days').value),
                radius_max_entries: parseInt(document.getElementById('ret-radius-max').value),
                radius_ui_fetch_limit: parseInt(document.getElementById('ret-radius-ui').value),
                auto_prune_enabled: document.getElementById('ret-auto-prune').checked
            };

            try {
                const res = await fetch(`${API_BASE}/syslog/retention`, {
                    method: 'PUT',
                    headers: getAuthHeaders(),
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to save retention policy');
                alert('Log retention & query limit policies saved successfully.');
                fetchLogRetentionSettings();
            } catch (err) {
                alert(`Error: ${err.message}`);
            }
        }

        async function runLogRetentionPruneNow() {
            if (!confirm('Run log retention cleanup now? Entries older than the configured retention period or exceeding max stored entries will be permanently deleted.')) return;
            try {
                const res = await fetch(`${API_BASE}/syslog/retention/prune`, {
                    method: 'POST',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Cleanup failed');
                alert(data.message || 'Retention cleanup completed.');
                fetchLogRetentionSettings();
            } catch (err) {
                alert(`Cleanup Error: ${err.message}`);
            }
        }

