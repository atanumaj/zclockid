        // Primary Tabs in RADIUS: General & Advance
        let currentRadiusMainTab = 'general';
        let currentRadiusGeneralSub = 'clients';
        let currentRadiusAdvanceSub = 'mab';

        function switchRadiusMainTab(mainTab) {
            currentRadiusMainTab = mainTab;
            const btnGen = document.getElementById('rad-main-tab-general');
            const btnAdv = document.getElementById('rad-main-tab-advance');
            const subGen = document.getElementById('rad-subnav-general');
            const subAdv = document.getElementById('rad-subnav-advance');

            if (mainTab === 'general') {
                if (btnGen) btnGen.className = 'px-4 py-2 rounded-lg text-xs font-bold bg-amber-600/20 text-amber-400 border border-amber-500/30 flex items-center gap-2 transition';
                if (btnAdv) btnAdv.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 border border-transparent flex items-center gap-2 transition';
                if (subGen) subGen.classList.remove('hidden');
                if (subAdv) subAdv.classList.add('hidden');
                switchRadiusSubTab(currentRadiusGeneralSub || 'clients');
            } else {
                if (btnGen) btnGen.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 border border-transparent flex items-center gap-2 transition';
                if (btnAdv) btnAdv.className = 'px-4 py-2 rounded-lg text-xs font-bold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center gap-2 transition';
                if (subGen) subGen.classList.add('hidden');
                if (subAdv) subAdv.classList.remove('hidden');
                switchRadiusSubTab(currentRadiusAdvanceSub || 'mab');
            }
        }

        // Sub-tabs in RADIUS (General & Advance)
        function switchRadiusSubTab(sub) {
            const allSubs = ['clients', 'bandwidth', 'eap', 'accounting', 'mab', 'custom', 'settings', 'config'];
            const isAdvance = ['mab', 'custom', 'settings', 'config'].includes(sub);

            // Synchronize primary mode tab if deep linked or switched directly
            if (isAdvance) {
                currentRadiusAdvanceSub = sub;
                if (currentRadiusMainTab !== 'advance') {
                    currentRadiusMainTab = 'advance';
                    const btnGen = document.getElementById('rad-main-tab-general');
                    const btnAdv = document.getElementById('rad-main-tab-advance');
                    const subGen = document.getElementById('rad-subnav-general');
                    const subAdv = document.getElementById('rad-subnav-advance');
                    if (btnGen) btnGen.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 border border-transparent flex items-center gap-2 transition';
                    if (btnAdv) btnAdv.className = 'px-4 py-2 rounded-lg text-xs font-bold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center gap-2 transition';
                    if (subGen) subGen.classList.add('hidden');
                    if (subAdv) subAdv.classList.remove('hidden');
                }
            } else {
                currentRadiusGeneralSub = sub;
                if (currentRadiusMainTab !== 'general') {
                    currentRadiusMainTab = 'general';
                    const btnGen = document.getElementById('rad-main-tab-general');
                    const btnAdv = document.getElementById('rad-main-tab-advance');
                    const subGen = document.getElementById('rad-subnav-general');
                    const subAdv = document.getElementById('rad-subnav-advance');
                    if (btnGen) btnGen.className = 'px-4 py-2 rounded-lg text-xs font-bold bg-amber-600/20 text-amber-400 border border-amber-500/30 flex items-center gap-2 transition';
                    if (btnAdv) btnAdv.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 border border-transparent flex items-center gap-2 transition';
                    if (subGen) subGen.classList.remove('hidden');
                    if (subAdv) subAdv.classList.add('hidden');
                }
            }

            allSubs.forEach(s => {
                const sec = document.getElementById(`radius-sec-${s}`);
                if (sec) sec.classList.add('hidden');

                const btn = document.getElementById(`rad-tab-${s}`);
                if (btn) {
                    btn.classList.remove('bg-amber-600/20', 'text-amber-400', 'bg-indigo-600/20', 'text-indigo-400', 'border', 'border-amber-500/30', 'border-indigo-500/30', 'font-bold');
                    btn.classList.add('text-slate-400', 'font-medium');
                }
            });

            const activeSec = document.getElementById(`radius-sec-${sub}`);
            if (activeSec) activeSec.classList.remove('hidden');

            const activeBtn = document.getElementById(`rad-tab-${sub}`);
            if (activeBtn) {
                activeBtn.classList.remove('text-slate-400', 'font-medium');
                const colorClass = isAdvance ? 'bg-indigo-600/20 text-indigo-400 border border-indigo-500/30' : 'bg-amber-600/20 text-amber-400 border border-amber-500/30';
                activeBtn.className = `px-3.5 py-2 rounded-lg text-xs font-bold ${colorClass} transition flex items-center gap-1.5`;
            }

            // Lazy data fetch on sub-tab switch
            if (sub === 'clients') fetchRadiusClients();
            else if (sub === 'bandwidth') fetchRadiusBandwidth();
            else if (sub === 'eap') fetchRadiusEap();
            else if (sub === 'accounting') fetchRadiusSessions();
            else if (sub === 'mab') fetchRadiusMab();
            else if (sub === 'custom') fetchRadiusCustom();
            else if (sub === 'settings') fetchRadiusSettings();
            else if (sub === 'config') loadRawRadiusConfig('clients');
        }

        // 4. FreeRADIUS 802.1X NAS Clients, Secrets & Accounting (pfSense Style)
        async function fetchRadiusClients() {
            try {
                const res = await fetch(`${API_BASE}/radius/clients`);
                const data = await res.json();
                const tbody = document.getElementById('radius-table-body');
                if (data.clients && data.clients.length > 0) {
                    tbody.innerHTML = data.clients.map((c, idx) => {
                        const safeName = escapeHtml(c.name);
                        const safeIp = escapeHtml(c.ipaddr);
                        const safeType = escapeHtml(c.nas_type || 'other');
                        const safeSecret = escapeHtml(c.secret || '');
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-white">${safeName}</td>
                                <td class="px-4 py-2.5 text-cyan-400 font-semibold">${safeIp}</td>
                                <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 uppercase">${safeType}</span></td>
                                <td class="px-4 py-2.5">
                                    <div class="flex items-center gap-2">
                                        <span id="secret-disp-${idx}" class="text-slate-400">••••••••••••••••</span>
                                        <button data-action="toggle-radius-secret" data-idx="${idx}" data-secret="${safeSecret}" class="text-slate-500 hover:text-amber-400" title="Toggle Visibility">
                                            <i class="fa-solid fa-eye text-xs"></i>
                                        </button>
                                        <button data-action="copy-radius-secret" data-secret="${safeSecret}" class="text-slate-500 hover:text-white" title="Copy Secret">
                                            <i class="fa-solid fa-copy text-xs"></i>
                                        </button>
                                    </div>
                                </td>
                                <td class="px-4 py-2.5 text-right">
                                    <button data-action="delete-radius-client" data-name="${safeName}" class="text-slate-500 hover:text-rose-400 transition" title="Delete Client">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="5" class="px-4 py-4 text-center font-sans text-slate-500">No NAS clients configured.</td></tr>`;
                }
            } catch (err) {
                console.error('Error fetching RADIUS clients:', err);
            }
        }

        function openRadiusModal() {
            document.getElementById('radius-modal').classList.remove('hidden');
            generateSecretForModal();
        }
        function closeRadiusModal() { document.getElementById('radius-modal').classList.add('hidden'); }

        async function generateSecretForModal() {
            try {
                const res = await fetch(`${API_BASE}/radius/secret/generate`, { method: 'POST' });
                const data = await res.json();
                document.getElementById('rad-secret-input').value = data.secret;
            } catch (err) {
                console.error('Error generating secret:', err);
            }
        }

        function copyModalSecret() {
            const sec = document.getElementById('rad-secret-input').value;
            copyToClipboard(sec);
        }

        async function submitAddRadiusClient() {
            const name = document.getElementById('rad-name-input').value.trim();
            const ip = document.getElementById('rad-ip-input').value.trim();
            const type = document.getElementById('rad-type-select').value;
            const secret = document.getElementById('rad-secret-input').value.trim();

            if (!name || !ip || !secret) return alert('Name, IP, and Secret are required.');

            try {
                const res = await fetch(`${API_BASE}/radius/clients`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        client_name: name,
                        ip_subnet: ip,
                        nas_type: type,
                        shared_secret: secret
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeRadiusModal();
                    fetchRadiusClients();
                } else {
                    alert(`Failed to add client: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving NAS client: ${err}`);
            }
        }

        async function deleteRadiusClient(name) {
            if (!confirm(`Delete NAS client '${name}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/radius/clients/${name}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchRadiusClients();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting client: ${err}`);
            }
        }

        // Live Accounting Sessions (pfSense Style)
        async function fetchRadiusSessions() {
            try {
                const res = await fetch(`${API_BASE}/radius/accounting/sessions`);
                const data = await res.json();
                const tbody = document.getElementById('radius-acct-table-body');
                if (data.sessions && data.sessions.length > 0) {
                    tbody.innerHTML = data.sessions.map(s => {
                        const inMb = (s.input_octets / (1024 * 1024)).toFixed(1);
                        const outMb = (s.output_octets / (1024 * 1024)).toFixed(1);
                        const durH = Math.floor(s.acct_session_time / 3600);
                        const durM = Math.floor((s.acct_session_time % 3600) / 60);
                        const durS = s.acct_session_time % 60;
                        const durStr = escapeHtml(`${durH}h ${durM}m ${durS}s`);
                        const safeUser = escapeHtml(s.username);
                        const safeNas = escapeHtml(s.nas_name || s.nas_ip);
                        const safeCalling = escapeHtml(s.calling_station_id || '-');
                        const safeFramed = escapeHtml(s.framed_ip || '-');
                        const safeStatus = escapeHtml(s.acct_status_type);
                        const safeSessionId = escapeHtml(s.session_id || '');

                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-white">${safeUser}</td>
                                <td class="px-4 py-2.5 text-slate-300">${safeNas}</td>
                                <td class="px-4 py-2.5 text-indigo-400 font-semibold">${safeCalling}</td>
                                <td class="px-4 py-2.5 text-cyan-300 font-semibold">${safeFramed}</td>
                                <td class="px-4 py-2.5 text-slate-400">${durStr}</td>
                                <td class="px-4 py-2.5 text-slate-300">▲ ${inMb} MB / ▼ ${outMb} MB</td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-[10px] ${s.acct_status_type === 'Active' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-slate-800 text-slate-400'}">${safeStatus}</span>
                                </td>
                                <td class="px-4 py-2.5 text-right">
                                    ${s.acct_status_type === 'Active' ? `
                                        <button data-action="disconnect-radius-session" data-session-id="${safeSessionId}" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900/60 text-rose-400 border border-rose-800/60 rounded text-[10px] transition" title="Disconnect Session">
                                            <i class="fa-solid fa-power-off mr-1"></i> Disconnect
                                        </button>
                                    ` : '<span class="text-slate-600">-</span>'}
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-4 text-center font-sans text-slate-500">No active RADIUS sessions.</td></tr>`;
                }
            } catch (err) {
                console.error('Error fetching accounting sessions:', err);
            }
        }

        async function disconnectSession(sessionId) {
            if (!confirm(`Force disconnect session '${sessionId}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/radius/accounting/disconnect?session_id=${sessionId}`, { method: 'POST' });
                if (res.ok) {
                    fetchRadiusSessions();
                } else {
                    const data = await res.json();
                    alert(`Disconnect failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error disconnecting session: ${err}`);
            }
        }

        let globalBandwidthProfiles = [];
        let globalUsers = [];
        let globalGroups = [];

        function populateBandwidthSelects() {
            const groupSelects = [
                document.getElementById('grp-bw-profile-input'),
                document.getElementById('edit-grp-bw-profile')
            ];
            const userSelects = [
                document.getElementById('usr-bw-profile-input'),
                document.getElementById('edit-usr-bandwidth-profile')
            ];

            const groupOptionsHtml = '<option value="0">None (Standard Group - No Bandwidth Policy)</option>' +
                globalBandwidthProfiles.map(p => {
                    const downStr = p.download_mbps > 0 ? `${p.download_mbps}M Down` : 'Unlimited Down';
                    const upStr = p.upload_mbps > 0 ? `${p.upload_mbps}M Up` : 'Unlimited Up';
                    return `<option value="${p.id}">${p.name} (${downStr} / ${upStr})${p.is_default ? ' [Default Portal]' : ''}</option>`;
                }).join('');

            const userOptionsHtml = '<option value="0">None (No Override - Inherit from Group / Default)</option>' +
                globalBandwidthProfiles.map(p => {
                    const downStr = p.download_mbps > 0 ? `${p.download_mbps}M Down` : 'Unlimited Down';
                    const upStr = p.upload_mbps > 0 ? `${p.upload_mbps}M Up` : 'Unlimited Up';
                    return `<option value="${p.id}">${p.name} (${downStr} / ${upStr})${p.is_default ? ' [Default Portal]' : ''}</option>`;
                }).join('');

            groupSelects.forEach(s => {
                if (s) {
                    const currentVal = s.value;
                    s.innerHTML = groupOptionsHtml;
                    if (currentVal !== undefined && currentVal !== '') s.value = currentVal;
                }
            });

            userSelects.forEach(s => {
                if (s) {
                    const currentVal = s.value;
                    s.innerHTML = userOptionsHtml;
                    if (currentVal !== undefined && currentVal !== '') s.value = currentVal;
                }
            });
        }

        // Captive Portal Bandwidth Management & Rate Limiting
        async function fetchRadiusBandwidth() {
            try {
                const res = await fetch(`${API_BASE}/radius/bandwidth-profiles`);
                const data = await res.json();
                globalBandwidthProfiles = data.profiles || [];
                populateBandwidthSelects();
                const tbody = document.getElementById('radius-bandwidth-table-body');
                if (!tbody) return;
                if (data.profiles && data.profiles.length > 0) {
                    tbody.innerHTML = data.profiles.map(p => {
                        const sessStr = p.session_timeout_mins > 0 ? `${escapeHtml(p.session_timeout_mins)}m` : 'Unlimited';
                        const idleStr = p.idle_timeout_mins > 0 ? `${escapeHtml(p.idle_timeout_mins)}m` : 'None';
                        const quotaStr = p.daily_quota_mb > 0 ? `${escapeHtml(p.daily_quota_mb)} MB` : 'Unlimited';
                        const targetBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-cyan-300 font-sans border border-slate-700/60 font-medium">Policy Object</span>';

                        const downStr = p.download_mbps > 0 
                            ? `▼ ${escapeHtml(p.download_mbps)} Mbps` 
                            : '<span class="text-emerald-400 font-bold flex items-center gap-1"><i class="fa-solid fa-infinity"></i> Unlimited</span>';
                        const upStr = p.upload_mbps > 0 
                            ? `▲ ${escapeHtml(p.upload_mbps)} Mbps` 
                            : '<span class="text-emerald-400 font-bold flex items-center gap-1"><i class="fa-solid fa-infinity"></i> Unlimited</span>';

                        let attrDisplay = '';
                        if (p.download_mbps <= 0 && p.upload_mbps <= 0) {
                            attrDisplay = '<div class="text-[10px] text-emerald-400 font-mono flex items-center gap-1"><i class="fa-solid fa-bolt"></i> Uncapped Wire Speed (No Limits)</div>';
                        } else {
                            const wDown = p.download_mbps > 0 ? `▼${escapeHtml(p.download_mbps)}M` : 'Unlimited';
                            const wUp = p.upload_mbps > 0 ? `▲${escapeHtml(p.upload_mbps)}M` : 'Unlimited';
                            const mkDown = p.download_mbps > 0 ? `${escapeHtml(p.download_mbps)}M` : '0';
                            const mkUp = p.upload_mbps > 0 ? `${escapeHtml(p.upload_mbps)}M` : '0';
                            attrDisplay = `
                                <div>WISPr: <span class="text-slate-400">${wDown} / ${wUp}</span></div>
                                <div>MikroTik: <span class="text-cyan-400 font-bold">"${mkUp}/${mkDown}"</span></div>
                            `;
                        }

                        const safeName = escapeHtml(p.name);
                        const safeDesc = escapeHtml(p.description || '-');

                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5">
                                    <div class="font-bold text-white flex items-center gap-2">
                                        <i class="fa-solid fa-gauge text-cyan-400"></i> ${safeName}
                                    </div>
                                    <div class="text-[10px] text-slate-400">${safeDesc}</div>
                                </td>
                                <td class="px-4 py-2.5 text-cyan-300 font-mono font-bold">${downStr}</td>
                                <td class="px-4 py-2.5 text-amber-300 font-mono font-bold">${upStr}</td>
                                <td class="px-4 py-2.5 text-slate-300 font-mono">${sessStr} / ${idleStr}</td>
                                <td class="px-4 py-2.5 text-emerald-400 font-mono font-semibold">${quotaStr}</td>
                                <td class="px-4 py-2.5">${targetBadge}</td>
                                <td class="px-4 py-2.5">
                                    <div class="text-[10px] font-mono text-slate-300 space-y-0.5">
                                        ${attrDisplay}
                                    </div>
                                </td>
                                <td class="px-4 py-2.5 text-right whitespace-nowrap">
                                    <button data-action="edit-bandwidth-profile" data-id="${p.id}" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 font-sans font-semibold text-[10px] transition mr-1" title="Edit Bandwidth Profile">
                                        <i class="fa-solid fa-pen-to-square"></i> Edit
                                    </button>
                                    <button data-action="delete-bandwidth-profile" data-id="${p.id}" data-name="${safeName}" class="text-slate-500 hover:text-rose-400 p-1 transition" title="Delete Profile">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-4 text-center font-sans text-slate-500">No bandwidth profiles configured.</td></tr>`;
                }
                if (typeof renderUsersTable === 'function' && typeof globalUsers !== 'undefined' && globalUsers.length > 0) {
                    renderUsersTable();
                }
            } catch (err) {
                console.error('Error fetching bandwidth profiles:', err);
            }
        }

        function openAddBandwidthModal() {
            document.getElementById('rad-bw-id-input').value = '';
            document.getElementById('rad-bw-modal-title').innerHTML = '<i class="fa-solid fa-gauge-high text-cyan-400"></i> Create Captive Portal Bandwidth Profile';
            const btn = document.getElementById('btn-save-bw-profile');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-plus"></i> Create Bandwidth Tier';
            document.getElementById('rad-bw-name-input').value = '';
            document.getElementById('rad-bw-down-input').value = '10.0';
            document.getElementById('rad-bw-up-input').value = '5.0';
            document.getElementById('rad-bw-sess-input').value = '120';
            document.getElementById('rad-bw-idle-input').value = '30';
            document.getElementById('rad-bw-quota-input').value = '0';
            document.getElementById('rad-bw-desc-input').value = '';
            document.getElementById('radius-bandwidth-modal').classList.remove('hidden');
        }

        function openBandwidthModal() { openAddBandwidthModal(); }

        function openEditBandwidthModal(id) {
            const p = globalBandwidthProfiles.find(x => x.id === id);
            if (!p) return alert(`Bandwidth profile ID ${id} not found.`);

            document.getElementById('rad-bw-id-input').value = p.id;
            document.getElementById('rad-bw-modal-title').innerHTML = `<i class="fa-solid fa-pen-to-square text-cyan-400"></i> Edit Bandwidth Profile: <span class="text-white">${escapeHtml(p.name)}</span>`;
            const btn = document.getElementById('btn-save-bw-profile');
            if (btn) btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Update Bandwidth Tier';
            document.getElementById('rad-bw-name-input').value = p.name || '';
            document.getElementById('rad-bw-down-input').value = p.download_mbps || 0;
            document.getElementById('rad-bw-up-input').value = p.upload_mbps || 0;
            document.getElementById('rad-bw-sess-input').value = p.session_timeout_mins || 0;
            document.getElementById('rad-bw-idle-input').value = p.idle_timeout_mins || 0;
            document.getElementById('rad-bw-quota-input').value = p.daily_quota_mb || 0;
            document.getElementById('rad-bw-desc-input').value = p.description || '';
            document.getElementById('radius-bandwidth-modal').classList.remove('hidden');
        }

        function closeBandwidthModal() { document.getElementById('radius-bandwidth-modal').classList.add('hidden'); }

        async function submitSaveBandwidthProfile() {
            const idVal = document.getElementById('rad-bw-id-input').value;
            const profileId = idVal ? parseInt(idVal, 10) : null;
            const name = document.getElementById('rad-bw-name-input').value.trim();
            const down = parseFloat(document.getElementById('rad-bw-down-input').value);
            const up = parseFloat(document.getElementById('rad-bw-up-input').value);
            const sess = parseInt(document.getElementById('rad-bw-sess-input').value) || 0;
            const idle = parseInt(document.getElementById('rad-bw-idle-input').value) || 0;
            const quota = parseInt(document.getElementById('rad-bw-quota-input').value) || 0;
            const desc = document.getElementById('rad-bw-desc-input').value.trim();

            if (!name || isNaN(down) || isNaN(up) || down < 0 || up < 0) return alert('Profile name, Download speed, and Upload speed are required (must be 0 or greater, where 0 = Unlimited).');

            const btn = document.getElementById('btn-save-bw-profile');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving...`;

            try {
                const url = profileId ? `${API_BASE}/radius/bandwidth-profiles/${profileId}` : `${API_BASE}/radius/bandwidth-profiles`;
                const method = profileId ? 'PUT' : 'POST';
                const res = await fetch(url, {
                    method: method,
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        id: profileId,
                        name: name,
                        download_mbps: down,
                        upload_mbps: up,
                        session_timeout_mins: sess,
                        idle_timeout_mins: idle,
                        daily_quota_mb: quota,
                        is_default: isDef,
                        description: desc,
                        is_active: true
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeBandwidthModal();
                    fetchRadiusBandwidth();
                } else {
                    alert(`Failed to save profile: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving bandwidth profile: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = profileId ? '<i class="fa-solid fa-floppy-disk"></i> Update Bandwidth Tier' : '<i class="fa-solid fa-plus"></i> Create Bandwidth Tier';
            }
        }

        async function deleteBandwidthProfile(id, name) {
            if (!confirm(`Delete bandwidth profile '${name}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/radius/bandwidth-profiles/${id}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchRadiusBandwidth();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting bandwidth profile: ${err}`);
            }
        }

        // EAP & Certificates
        async function fetchRadiusEap() {
            try {
                const res = await fetch(`${API_BASE}/radius/eap`);
                const data = await res.json();
                if (data.certificates) {
                    const c = data.certificates;
                    document.getElementById('rad-cert-subject').innerText = c.subject || 'radius.local';
                    document.getElementById('rad-cert-issuer').innerText = c.issuer || 'ZclockID Root CA';
                    document.getElementById('rad-cert-algo').innerText = c.key_algorithm || 'RSA 4096-bit';
                    document.getElementById('rad-cert-validity').innerText = `Valid (${c.days_remaining || '3650'} days remaining)`;
                }
            } catch (err) {
                console.error('Error fetching RADIUS EAP profile:', err);
            }
        }

        async function renewRadiusCert() {
            if (!confirm('Re-issue and renew FreeRADIUS 802.1X Server TLS Certificate? Services will be reloaded.')) return;
            try {
                const res = await fetch(`${API_BASE}/radius/eap/renew-cert`, { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    alert('802.1X Server TLS certificate renewed successfully!');
                    fetchRadiusEap();
                } else {
                    alert(`Renewal failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error renewing cert: ${err}`);
            }
        }

        // MAC Authentication Bypass (MAB)
        async function fetchRadiusMab() {
            try {
                const res = await fetch(`${API_BASE}/radius/mab`);
                const data = await res.json();
                const tbody = document.getElementById('radius-mab-table-body');
                if (data.devices && data.devices.length > 0) {
                    tbody.innerHTML = data.devices.map(d => {
                        const safeMac = escapeHtml(d.mac_address);
                        const safeName = escapeHtml(d.device_name);
                        const safeVlan = escapeHtml(d.vlan_id);
                        const safeIp = escapeHtml(d.static_ip || '-');
                        const safeDesc = escapeHtml(d.description || '-');
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-indigo-400 font-mono">${safeMac}</td>
                                <td class="px-4 py-2.5 text-white font-semibold">${safeName}</td>
                                <td class="px-4 py-2.5 text-cyan-400 font-mono font-bold">VLAN ${safeVlan}</td>
                                <td class="px-4 py-2.5 text-slate-300 font-mono">${safeIp}</td>
                                <td class="px-4 py-2.5 text-slate-400">${safeDesc}</td>
                                <td class="px-4 py-2.5 text-right">
                                    <button data-action="delete-mab-device" data-id="${d.id}" class="text-slate-500 hover:text-rose-400 transition" title="Delete Device">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center font-sans text-slate-500">No MAB bypass devices configured.</td></tr>`;
                }
            } catch (err) {
                console.error('Error fetching MAB devices:', err);
            }
        }

        function openMabModal() { document.getElementById('radius-mab-modal').classList.remove('hidden'); }
        function closeMabModal() { document.getElementById('radius-mab-modal').classList.add('hidden'); }

        async function submitSaveMabDevice() {
            const mac = document.getElementById('rad-mab-mac-input').value.trim();
            const name = document.getElementById('rad-mab-name-input').value.trim();
            const vlan = parseInt(document.getElementById('rad-mab-vlan-input').value);
            const ip = document.getElementById('rad-mab-ip-input').value.trim();
            const desc = document.getElementById('rad-mab-desc-input').value.trim();

            if (!mac || !name || isNaN(vlan)) return alert('MAC address, Device name, and VLAN ID are required.');

            try {
                const res = await fetch(`${API_BASE}/radius/mab`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        mac_address: mac,
                        device_name: name,
                        vlan_id: vlan,
                        static_ip: ip,
                        description: desc,
                        is_active: true
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeMabModal();
                    fetchRadiusMab();
                } else {
                    alert(`Failed to save MAB device: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving MAB device: ${err}`);
            }
        }

        async function deleteMabDevice(id) {
            if (!confirm('Delete this MAB device entry?')) return;
            try {
                const res = await fetch(`${API_BASE}/radius/mab/${id}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchRadiusMab();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting MAB device: ${err}`);
            }
        }

        // Custom RADIUS Attributes & Policies
        async function fetchRadiusCustom() {
            try {
                const res = await fetch(`${API_BASE}/radius/custom-attributes`);
                const data = await res.json();
                const tbody = document.getElementById('radius-custom-table-body');
                if (data.attributes && data.attributes.length > 0) {
                    tbody.innerHTML = data.attributes.map(a => {
                        const safeTargetType = escapeHtml(a.target_type);
                        const safeTargetName = escapeHtml(a.target_name || 'ALL');
                        const safeAttrName = escapeHtml(a.attribute_name);
                        const safeOp = escapeHtml(a.operator || '=');
                        const safeAttrVal = escapeHtml(a.attribute_value);
                        const safeDesc = escapeHtml(a.description || '-');
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-slate-800 text-slate-300">${safeTargetType}</span>
                                </td>
                                <td class="px-4 py-2.5 font-bold text-white font-mono">${safeTargetName}</td>
                                <td class="px-4 py-2.5 text-amber-400 font-mono font-semibold">${safeAttrName}</td>
                                <td class="px-4 py-2.5 text-slate-400 font-mono">${safeOp}</td>
                                <td class="px-4 py-2.5 text-cyan-300 font-mono">${safeAttrVal}</td>
                                <td class="px-4 py-2.5 text-slate-400">${safeDesc}</td>
                                <td class="px-4 py-2.5 text-right">
                                    <button data-action="delete-custom-attr" data-id="${a.id}" class="text-slate-500 hover:text-rose-400 transition" title="Delete Attribute">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-4 text-center font-sans text-slate-500">No custom vendor attributes configured.</td></tr>`;
                }
            } catch (err) {
                console.error('Error fetching custom attributes:', err);
            }
        }

        function openCustomAttrModal() { document.getElementById('radius-custom-modal').classList.remove('hidden'); }
        function closeCustomAttrModal() { document.getElementById('radius-custom-modal').classList.add('hidden'); }

        async function submitSaveCustomAttr() {
            const scope = document.getElementById('rad-attr-scope-select').value;
            const scopeName = document.getElementById('rad-attr-scopename-input').value.trim() || 'ALL';
            const name = document.getElementById('rad-attr-name-input').value.trim();
            const op = document.getElementById('rad-attr-op-select').value;
            const val = document.getElementById('rad-attr-val-input').value.trim();
            const desc = document.getElementById('rad-attr-desc-input').value.trim();

            if (!name || !val) return alert('Attribute Name and Value are required.');

            try {
                const res = await fetch(`${API_BASE}/radius/custom-attributes`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        target_type: scope,
                        target_name: scopeName,
                        attribute_name: name,
                        operator: op,
                        attribute_value: val,
                        description: desc,
                        is_active: true
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeCustomAttrModal();
                    fetchRadiusCustom();
                } else {
                    alert(`Failed to save attribute: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving custom attribute: ${err}`);
            }
        }

        async function deleteCustomAttr(id) {
            if (!confirm('Delete this custom attribute?')) return;
            try {
                const res = await fetch(`${API_BASE}/radius/custom-attributes/${id}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchRadiusCustom();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting attribute: ${err}`);
            }
        }

        // Engine Parameters & Logging
        async function fetchRadiusSettings() {
            try {
                const res = await fetch(`${API_BASE}/radius/settings`);
                const data = await res.json();
                if (data) {
                    document.getElementById('rad-cfg-auth-port').value = data.auth_port || 1812;
                    document.getElementById('rad-cfg-acct-port').value = data.acct_port || 1813;
                    document.getElementById('rad-cfg-listen-ip').value = data.listen_ip || '0.0.0.0';
                    document.getElementById('rad-cfg-interval').value = data.interim_interval || 300;
                    document.getElementById('rad-cfg-max-requests').value = data.max_requests || 1024;
                    document.getElementById('rad-cfg-max-servers').value = data.max_servers || 32;
                    document.getElementById('rad-cfg-log-auth').checked = Boolean(data.log_auth !== 0);
                    document.getElementById('rad-cfg-log-badpass').checked = Boolean(data.log_badpass !== 0);
                }
            } catch (err) {
                console.error('Error fetching RADIUS settings:', err);
            }
        }

        async function saveRadiusSettings() {
            const authPort = parseInt(document.getElementById('rad-cfg-auth-port').value) || 1812;
            const acctPort = parseInt(document.getElementById('rad-cfg-acct-port').value) || 1813;
            const listenIp = document.getElementById('rad-cfg-listen-ip').value.trim() || '0.0.0.0';
            const interval = parseInt(document.getElementById('rad-cfg-interval').value) || 300;
            const maxReq = parseInt(document.getElementById('rad-cfg-max-requests').value) || 1024;
            const maxServ = parseInt(document.getElementById('rad-cfg-max-servers').value) || 32;
            const logAuth = document.getElementById('rad-cfg-log-auth').checked;
            const logBadPass = document.getElementById('rad-cfg-log-badpass').checked;

            try {
                const res = await fetch(`${API_BASE}/radius/settings`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        auth_port: authPort,
                        acct_port: acctPort,
                        acct_enabled: true,
                        listen_ip: listenIp,
                        interim_interval: interval,
                        max_requests: maxReq,
                        max_servers: maxServ,
                        log_auth: logAuth,
                        log_badpass: logBadPass
                    })
                });
                if (res.ok) {
                    alert('FreeRADIUS engine settings saved and applied!');
                } else {
                    const data = await res.json();
                    alert(`Save failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving settings: ${err}`);
            }
        }

        // Raw Configuration Inspector (pfSense Style)
        let activeRawConfigFile = 'clients';
        async function loadRawRadiusConfig(file) {
            activeRawConfigFile = file;
            ['clients', 'authorize', 'mschap', 'eap'].forEach(f => {
                const btn = document.getElementById(`rad-cfgfile-${f}`);
                if (btn) {
                    if (f === file) {
                        btn.className = 'px-2.5 py-1 rounded bg-amber-600/20 text-amber-400 font-semibold font-mono';
                    } else {
                        btn.className = 'px-2.5 py-1 rounded text-slate-400 hover:text-white font-mono';
                    }
                }
            });

            const pre = document.getElementById('radius-raw-config-display');
            pre.innerText = `Loading ${file}...`;
            try {
                const res = await fetch(`${API_BASE}/radius/config/view?file=${file}`);
                const data = await res.json();
                pre.innerText = data.content || `# No content returned for ${file}`;
            } catch (err) {
                pre.innerText = `Error loading ${file}: ${err}`;
            }
        }

        function copyRawConfigToClipboard() {
            const pre = document.getElementById('radius-raw-config-display');
            copyToClipboard(pre.innerText, `Copied ${activeRawConfigFile} config to clipboard!`);
        }

        // 5. Users, Groups & Computers
        let globalComputers = [];
        let currentDirectorySubtab = 'users';

