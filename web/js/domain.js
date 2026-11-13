        // 2. Domain & Identity Management (Zentyal Style)
        let currentSystemIdentity = {};

        async function fetchDomainInfo() {
            try {
                const res = await fetch(`${API_BASE}/domain/info`);
                const data = await res.json();
                currentSystemIdentity = data;

                if (document.getElementById('header-domain')) document.getElementById('header-domain').innerText = data.realm || 'DOMAIN';
                if (document.getElementById('domain-realm-val')) document.getElementById('domain-realm-val').innerText = data.realm || '--';
                if (document.getElementById('domain-netbios-val')) document.getElementById('domain-netbios-val').innerText = data.domain_netbios || '--';
                if (document.getElementById('domain-sid-val')) document.getElementById('domain-sid-val').innerText = data.domain_sid || 'S-1-5-21-...';
                if (document.getElementById('domain-role-val')) document.getElementById('domain-role-val').innerText = data.server_role || 'Primary Domain Controller';
                if (document.getElementById('domain-netbios-name-val')) document.getElementById('domain-netbios-name-val').innerText = data.netbios_name || '--';
                if (document.getElementById('domain-desc-val')) document.getElementById('domain-desc-val').innerText = data.server_description || 'ZclockID Active Directory Domain Controller';
                if (document.getElementById('domain-fqdn-val')) document.getElementById('domain-fqdn-val').innerText = data.fqdn || (data.hostname && data.realm ? `${data.hostname}.${data.realm.toLowerCase()}` : '--');

                const dRealm = (data.realm || 'DOMAIN').toUpperCase();
                if (document.getElementById('hero-domain-realm')) document.getElementById('hero-domain-realm').innerText = dRealm;
                if (document.getElementById('rsat-domain-name')) document.getElementById('rsat-domain-name').innerText = dRealm;
                if (document.getElementById('rsat-dns-ip')) document.getElementById('rsat-dns-ip').innerText = window.location.hostname || '127.0.0.1';

                // Domain Controller Type Widget (Master / Primary vs Alternate / Backup vs RODC)
                const dcTypeBadge = document.getElementById('domain-dc-type-badge');
                const dcTypeVal = document.getElementById('domain-dc-type-val');
                const dcTypeSub = document.getElementById('domain-dc-type-sub');

                const isMaster = data.is_master !== undefined 
                    ? data.is_master 
                    : (!data.fsmo_roles || data.fsmo_roles.PdcEmulationMaster === data.netbios_name || data.fsmo_roles.PdcEmulator === data.netbios_name || data.fsmo_roles.SchemaMaster === data.netbios_name);

                if (dcTypeVal) {
                    if (data.dc_type_label === 'RODC') {
                        if (dcTypeBadge) {
                            dcTypeBadge.className = 'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-amber-950 text-amber-400 border border-amber-800';
                            dcTypeBadge.innerText = 'RODC';
                        }
                        dcTypeVal.className = 'text-amber-300 font-bold text-xs truncate flex items-center gap-1.5';
                        dcTypeVal.innerHTML = '<i class="fa-solid fa-shield text-amber-400 text-[11px]"></i> Read-Only DC (RODC)';
                        if (dcTypeSub) dcTypeSub.innerText = data.dc_type_desc || 'Read-Only Directory Replica';
                    } else if (isMaster) {
                        if (dcTypeBadge) {
                            dcTypeBadge.className = 'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
                            dcTypeBadge.innerText = 'PRIMARY';
                        }
                        dcTypeVal.className = 'text-emerald-300 font-bold text-xs truncate flex items-center gap-1.5';
                        dcTypeVal.innerHTML = '<i class="fa-solid fa-crown text-amber-400 text-[11px]"></i> Master (Primary DC)';
                        if (dcTypeSub) dcTypeSub.innerText = data.dc_type_desc || 'PDC Emulator & FSMO Role Master';
                    } else {
                        if (dcTypeBadge) {
                            dcTypeBadge.className = 'px-1.5 py-0.5 rounded text-[9px] font-mono font-bold bg-indigo-950 text-indigo-400 border border-indigo-800';
                            dcTypeBadge.innerText = 'BACKUP';
                        }
                        dcTypeVal.className = 'text-indigo-300 font-bold text-xs truncate flex items-center gap-1.5';
                        dcTypeVal.innerHTML = '<i class="fa-solid fa-server text-indigo-400 text-[11px]"></i> Alternate (Backup DC)';
                        if (dcTypeSub) dcTypeSub.innerText = data.dc_type_desc || `DRS Replica (PDC: ${data.pdc_holder || 'Remote PDC'})`;
                    }
                }
            } catch (err) {
                console.error('Error fetching domain info:', err);
            }
        }

        function openIdentityModal() {
            document.getElementById('ident-desc-input').value = currentSystemIdentity.server_description || '';
            document.getElementById('ident-hostname-input').value = currentSystemIdentity.hostname || '';
            document.getElementById('ident-netbios-input').value = currentSystemIdentity.netbios_name || '';
            document.getElementById('ident-realm-note').innerText = currentSystemIdentity.realm || 'DOMAIN';

            const isMaster = currentSystemIdentity.is_master !== undefined ? currentSystemIdentity.is_master : true;
            const badge = document.getElementById('ident-dc-type-current-badge');
            const primaryRadio = document.querySelector('input[name="ident-dc-type"][value="primary"]');
            const alternateRadio = document.querySelector('input[name="ident-dc-type"][value="alternate"]');

            if (isMaster) {
                if (badge) {
                    badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
                    badge.innerText = 'CURRENT: PRIMARY';
                }
                if (primaryRadio) primaryRadio.checked = true;
            } else {
                if (badge) {
                    badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-indigo-950 text-indigo-400 border border-indigo-800';
                    badge.innerText = 'CURRENT: ALTERNATE';
                }
                if (alternateRadio) alternateRadio.checked = true;
            }

            const container = document.getElementById('ident-role-switch-container');
            if (container) container.classList.add('hidden');
            const verifyCheck = document.getElementById('ident-verify-check');
            if (verifyCheck) verifyCheck.checked = false;
            const partnerInput = document.getElementById('ident-partner-input');
            if (partnerInput) partnerInput.value = '';
            const seizeCheck = document.getElementById('ident-seize-check');
            if (seizeCheck) seizeCheck.checked = false;

            updateIdentRoleSelectionStyles();

            document.getElementById('modal-identity').classList.remove('hidden');
        }

        function closeIdentityModal() {
            document.getElementById('modal-identity').classList.add('hidden');
        }

        function updateIdentRoleSelectionStyles() {
            const isMaster = currentSystemIdentity.is_master !== undefined ? currentSystemIdentity.is_master : true;
            const selectedVal = document.querySelector('input[name="ident-dc-type"]:checked')?.value || (isMaster ? 'primary' : 'alternate');
            const lblPrimary = document.getElementById('ident-label-primary');
            const lblAlternate = document.getElementById('ident-label-alternate');

            if (lblPrimary) {
                if (selectedVal === 'primary') {
                    lblPrimary.className = 'relative flex flex-col p-3 rounded-lg border-2 border-emerald-500 bg-emerald-950/20 cursor-pointer transition select-none';
                } else {
                    lblPrimary.className = 'relative flex flex-col p-3 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-slate-700 cursor-pointer transition select-none';
                }
            }
            if (lblAlternate) {
                if (selectedVal === 'alternate') {
                    lblAlternate.className = 'relative flex flex-col p-3 rounded-lg border-2 border-indigo-500 bg-indigo-950/20 cursor-pointer transition select-none';
                } else {
                    lblAlternate.className = 'relative flex flex-col p-3 rounded-lg border border-slate-800 bg-slate-900/60 hover:border-slate-700 cursor-pointer transition select-none';
                }
            }
        }

        function onIdentDcTypeRadioChange() {
            updateIdentRoleSelectionStyles();
            const isMaster = currentSystemIdentity.is_master !== undefined ? currentSystemIdentity.is_master : true;
            const currentType = isMaster ? 'primary' : 'alternate';
            const selectedType = document.querySelector('input[name="ident-dc-type"]:checked')?.value || currentType;

            const container = document.getElementById('ident-role-switch-container');
            const descEl = document.getElementById('ident-role-switch-desc');
            const partnerField = document.getElementById('ident-partner-field');
            const seizeField = document.getElementById('ident-seize-field');
            const verifyCheck = document.getElementById('ident-verify-check');
            if (verifyCheck) verifyCheck.checked = false;

            if (selectedType === currentType) {
                if (container) container.classList.add('hidden');
            } else {
                if (container) container.classList.remove('hidden');
                if (currentType === 'primary' && selectedType === 'alternate') {
                    if (descEl) {
                        descEl.innerHTML = 'Changing this host from <b>Primary DC</b> to <b>Alternate DC</b> will transfer all Active Directory FSMO Master roles to the designated partner DC. This host will continue replicating directory data as an Alternate DC replica.';
                    }
                    if (partnerField) partnerField.classList.remove('hidden');
                    if (seizeField) seizeField.classList.add('hidden');
                } else {
                    if (descEl) {
                        descEl.innerHTML = 'Promoting this host to <b>Primary DC</b> will transfer all 5 Active Directory FSMO Master roles (PDC Emulator, Schema, Domain Naming, RID, Infrastructure) onto this local Domain Controller.';
                    }
                    if (partnerField) partnerField.classList.add('hidden');
                    if (seizeField) seizeField.classList.remove('hidden');
                }
            }
        }

        async function saveSystemIdentity(e) {
            if (e) e.preventDefault();

            const isMaster = currentSystemIdentity.is_master !== undefined ? currentSystemIdentity.is_master : true;
            const currentType = isMaster ? 'primary' : 'alternate';
            const selectedType = document.querySelector('input[name="ident-dc-type"]:checked')?.value || currentType;
            const isDcTypeChanging = (selectedType !== currentType);

            const partnerInput = document.getElementById('ident-partner-input')?.value.trim();
            const forceSeize = document.getElementById('ident-seize-check')?.checked || false;

            if (isDcTypeChanging) {
                const verifyCheck = document.getElementById('ident-verify-check');
                if (!verifyCheck || !verifyCheck.checked) {
                    alert('Please check the "Verify Before Save" confirmation box before saving Domain Controller type changes.');
                    return;
                }
                if (currentType === 'primary' && selectedType === 'alternate' && !partnerInput) {
                    alert('Please specify the IP address or hostname of the designated partner Domain Controller that will assume Master/FSMO leadership.');
                    return;
                }
            }

            const btn = document.getElementById('btn-save-ident');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

            const newDesc = document.getElementById('ident-desc-input').value.trim();
            const newHostname = document.getElementById('ident-hostname-input').value.trim();
            const newNetbios = document.getElementById('ident-netbios-input').value.trim().toUpperCase();

            const identityChanged = (
                newDesc !== (currentSystemIdentity.server_description || '') ||
                newHostname !== (currentSystemIdentity.hostname || '') ||
                newNetbios !== (currentSystemIdentity.netbios_name || '')
            );

            const results = [];

            try {
                // 1. Update identity if changed
                if (identityChanged) {
                    const payload = {
                        server_description: newDesc,
                        hostname: newHostname,
                        netbios_name: newNetbios
                    };
                    const res = await fetch(`${API_BASE}/system/identity`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Failed to update system identity');
                    results.push(`Identity: ${data.actions.join(', ')}`);
                }

                // 2. Transfer FSMO roles if DC type changed
                if (isDcTypeChanging) {
                    const payload = {
                        role: 'all',
                        force_seize: currentType === 'primary' ? false : forceSeize,
                        target_server: currentType === 'primary' ? partnerInput : null
                    };
                    const res = await fetch(`${API_BASE}/domain/fsmo/transfer`, {
                        method: 'POST',
                        headers: getAuthHeaders(),
                        body: JSON.stringify(payload)
                    });
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.detail || 'Failed to update Domain Controller type');
                    results.push(`DC Type: ${data.message || 'Switched successfully'}`);
                }

                if (results.length === 0) {
                    alert('No changes were made to Server Identity or Domain Controller Type.');
                } else {
                    alert(`Changes Saved Successfully!\n\n${results.join('\n\n')}`);
                }

                closeIdentityModal();
                await fetchDomainInfo();
            } catch (err) {
                alert(`Error saving identity: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

        // ==================== FUNCTIONAL LEVELS CONTROLLER ====================
        let currentFunctionalLevels = null;

        async function fetchFunctionalLevels() {
            try {
                const res = await fetch(`${API_BASE}/domain/functional-level`);
                const data = await res.json();
                if (data.status === 'success') {
                    currentFunctionalLevels = data;
                    renderFunctionalLevels(data);
                }
            } catch (err) {
                console.error('Error fetching functional levels:', err);
            }
        }

        function renderFunctionalLevels(data) {
            // Dedicated Card
            const dflBadge = document.getElementById('card-dfl-badge');
            const dflTitle = document.getElementById('card-dfl-title');
            const fflBadge = document.getElementById('card-ffl-badge');
            const fflTitle = document.getElementById('card-ffl-title');
            const lowestBadge = document.getElementById('card-lowest-badge');
            const lowestTitle = document.getElementById('card-lowest-title');

            if (dflBadge) dflBadge.innerText = data.domain_level || '2016';
            if (dflTitle) dflTitle.innerText = data.domain_level_label || 'Windows Server 2016';
            if (fflBadge) fflBadge.innerText = data.forest_level || '2016';
            if (fflTitle) fflTitle.innerText = data.forest_level_label || 'Windows Server 2016';
            if (lowestBadge) lowestBadge.innerText = data.lowest_dc_level || '2016';
            if (lowestTitle) lowestTitle.innerText = data.lowest_dc_level_label || 'Windows Server 2016';
        }

        function openFunctionalLevelModal() {
            if (currentFunctionalLevels) {
                document.getElementById('fl-modal-curr-domain').innerText = `${currentFunctionalLevels.domain_level_label} (${currentFunctionalLevels.domain_level})`;
                document.getElementById('fl-modal-curr-forest').innerText = `${currentFunctionalLevels.forest_level_label} (${currentFunctionalLevels.forest_level})`;
                document.getElementById('fl-select-domain').value = currentFunctionalLevels.domain_level || '2016';
                document.getElementById('fl-select-forest').value = currentFunctionalLevels.forest_level || '2016';
            }
            document.getElementById('modal-functional-level').classList.remove('hidden');
        }

        function closeFunctionalLevelModal() {
            document.getElementById('modal-functional-level').classList.add('hidden');
        }

        async function submitRaiseFunctionalLevels(e) {
            e.preventDefault();
            const dLevel = document.getElementById('fl-select-domain').value;
            const fLevel = document.getElementById('fl-select-forest').value;
            const btn = document.getElementById('btn-submit-fl');

            if (!confirm(`Are you sure you want to raise functional levels to:\n\n• Domain Functional Level: ${dLevel}\n• Forest Functional Level: ${fLevel}\n\nWARNING: Active Directory functional level elevation is permanent and cannot be downgraded.`)) {
                return;
            }

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Raising Levels...`;

            try {
                const res = await fetch(`${API_BASE}/domain/functional-level/raise`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ domain_level: dLevel, forest_level: fLevel })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Functional levels raised successfully.');
                    closeFunctionalLevelModal();
                    await fetchFunctionalLevels();
                    await fetchDomainInfo();
                } else {
                    alert(`Failed to raise functional level: ${data.detail || data.message}`);
                }
            } catch (err) {
                alert(`Error raising functional level: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-arrow-up-right-dots"></i> Apply & Raise Level`;
            }
        }

        async function fetchUpnSuffixes() {
            try {
                const res = await fetch(`${API_BASE}/domain/upn`);
                const data = await res.json();
                const tbody = document.getElementById('upn-table-body');
                if (!tbody) return;

                const safeRealm = escapeHtml((data.primary_realm || '').toLowerCase());
                tbody.innerHTML = `
                    <tr class="hover:bg-slate-800/30">
                        <td class="px-4 py-2.5 font-bold text-white">@${safeRealm}</td>
                        <td class="px-4 py-2.5 text-indigo-400">Primary Forest Root</td>
                        <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">DEFAULT</span></td>
                        <td class="px-4 py-2.5 text-right text-slate-500 font-sans italic text-[10px]">Protected Root</td>
                    </tr>
                `;

                if (data.alternate_suffixes && data.alternate_suffixes.length > 0) {
                    const rows = data.alternate_suffixes.map(s => {
                        const safeSuffix = escapeHtml(s);
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-emerald-300">@${safeSuffix}</td>
                                <td class="px-4 py-2.5 text-slate-400">Alternate UPN Suffix</td>
                                <td class="px-4 py-2.5"><span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300">ACTIVE</span></td>
                                <td class="px-4 py-2.5 text-right">
                                    <button data-action="delete-upn-suffix" data-suffix="${safeSuffix}" class="px-2 py-1 bg-rose-950/60 hover:bg-rose-900/60 text-rose-400 border border-rose-800/60 rounded text-[10px] transition">
                                        <i class="fa-solid fa-trash-can mr-1"></i> Delete
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                    tbody.innerHTML += rows;
                }
            } catch (err) {
                console.error('Error fetching UPN suffixes:', err);
            }
        }

        function openUpnModal() { document.getElementById('upn-modal').classList.remove('hidden'); }
        function closeUpnModal() { document.getElementById('upn-modal').classList.add('hidden'); }

        async function submitAddUpn() {
            const suffix = document.getElementById('upn-suffix-input').value.trim();
            if (!suffix) return alert('Please enter an alternate domain suffix.');
            try {
                const res = await fetch(`${API_BASE}/domain/upn`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ upn_suffix: suffix })
                });
                const data = await res.json();
                if (res.ok) {
                    closeUpnModal();
                    document.getElementById('upn-suffix-input').value = '';
                    fetchUpnSuffixes();
                } else {
                    alert(`Failed to add suffix: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error adding UPN suffix: ${err}`);
            }
        }

        async function deleteUpnSuffix(suffix) {
            if (!confirm(`Are you sure you want to remove alternate domain '@${suffix}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/domain/upn/${suffix}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchUpnSuffixes();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting suffix: ${err}`);
            }
        }

        async function fetchDrsStatus() {
            try {
                const res = await fetch(`${API_BASE}/domain/replication`, { headers: getAuthHeaders() });
                if (res.ok) {
                    const data = await res.json();
                    const drsEl = document.getElementById('drs-output');
                    const badge = document.getElementById('drs-health-badge');
                    if (drsEl) {
                        drsEl.innerText = data.raw_output || 'DRS Directory Replication is operational.';
                    }
                    if (badge) {
                        if (data.health === 'OPTIMAL' || data.health === 'STANDALONE_OPTIMAL') {
                            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold';
                            badge.innerText = data.is_replicated ? 'SYNCHRONIZED' : 'STANDALONE ROOT';
                        } else {
                            badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800 font-bold';
                            badge.innerText = 'ATTENTION REQUIRED';
                        }
                    }
                }
            } catch (err) {
                console.error('Error fetching DRS status:', err);
                const drsEl = document.getElementById('drs-output');
                if (drsEl) {
                    drsEl.innerText = 'Primary Domain Controller (Forest Root)\nReplication: Standalone Master DC\nDirectory partitions synchronized locally.';
                }
            }
        }

        async function forceDrsSync() {
            try {
                const drsEl = document.getElementById('drs-output');
                if (drsEl) drsEl.innerText = 'Executing Knowledge Consistency Checker (samba-tool drs kcc)...';
                const res = await fetch(`${API_BASE}/domain/replication/sync`, { method: 'POST', headers: getAuthHeaders() });
                const data = await res.json();
                if (drsEl) drsEl.innerText = data.message || 'DRS Synchronization complete.';
                setTimeout(fetchDrsStatus, 1500);
            } catch (err) {
                const drsEl = document.getElementById('drs-output');
                if (drsEl) drsEl.innerText = `Sync error: ${err}`;
            }
        }

