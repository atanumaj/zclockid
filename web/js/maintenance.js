        // ==================== BACKUP & RESTORE JAVASCRIPT CONTROLLER ====================
        let currentBackups = [];
        let backupToRestore = null;

        async function fetchBackups() {
            const tbody = document.getElementById('backups-table-body');
            tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center font-sans text-slate-500">Querying backup archives...</td></tr>`;

            try {
                const res = await fetch(`${API_BASE}/backups`);
                const data = await res.json();
                currentBackups = data.backups || [];

                document.getElementById('backup-stat-count').innerText = data.total_backups || 0;
                document.getElementById('backup-stat-size').innerText = `${data.total_size_mb || 0} MB`;
                if (data.last_backup) {
                    const d = new Date(data.last_backup);
                    document.getElementById('backup-stat-last').innerText = `${d.toLocaleDateString()} ${d.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}`;
                } else {
                    document.getElementById('backup-stat-last').innerText = 'Never';
                }

                renderBackupsTable(currentBackups);
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center text-rose-400">Failed to load backups: ${err}</td></tr>`;
            }
        }

        function renderBackupsTable(backups) {
            const tbody = document.getElementById('backups-table-body');
            if (backups.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center font-sans text-slate-500">No backup archives found. Click "Create Backup" to generate one.</td></tr>`;
                return;
            }

            tbody.innerHTML = backups.map(b => {
                const isFull = b.backup_type === 'full';
                const createdDate = b.created_at ? new Date(b.created_at).toLocaleString() : '-';
                return `
                    <tr class="hover:bg-slate-800/30">
                        <td class="px-4 py-3">
                            <div class="font-bold text-white flex items-center gap-2">
                                <i class="fa-solid fa-file-zipper ${isFull ? 'text-amber-400' : 'text-emerald-400'}"></i>
                                <span>${b.filename}</span>
                            </div>
                            <span class="text-[10px] text-slate-400 font-sans block pt-0.5">${b.description || 'Appliance backup'}</span>
                        </td>
                        <td class="px-4 py-3">
                            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${isFull ? 'bg-amber-950 text-amber-300 border border-amber-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}">
                                ${isFull ? 'FULL DISASTER RECOVERY' : 'CONFIGURATION ONLY'}
                            </span>
                        </td>
                        <td class="px-4 py-3 text-cyan-300 font-semibold">${b.size_human}</td>
                        <td class="px-4 py-3 text-slate-300 text-[11px]">${createdDate}</td>
                        <td class="px-4 py-3 text-slate-400">
                            <div class="text-white font-semibold">${b.realm}</div>
                            <div class="text-[10px] text-slate-500">${b.hostname}</div>
                        </td>
                        <td class="px-4 py-3 text-right">
                            <div class="flex items-center justify-end gap-2">
                                <button onclick="downloadBackup('${b.filename}')" class="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs transition" title="Download to PC">
                                    <i class="fa-solid fa-download"></i>
                                </button>
                                <button onclick="inspectBackup('${b.filename}')" class="p-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs transition" title="Inspect Manifest">
                                    <i class="fa-solid fa-magnifying-glass"></i>
                                </button>
                                <button onclick="confirmRestoreBackup('${b.filename}')" class="p-1.5 bg-slate-800 hover:bg-rose-900/60 text-amber-400 hover:text-white rounded text-xs transition" title="Restore this Backup">
                                    <i class="fa-solid fa-rotate-left"></i>
                                </button>
                                <button onclick="deleteBackup('${b.filename}')" class="p-1.5 bg-slate-800 hover:bg-rose-800 text-slate-400 hover:text-white rounded text-xs transition" title="Delete Archive">
                                    <i class="fa-solid fa-trash-can"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            }).join('');
        }

        function openCreateBackupModal() {
            document.getElementById('modal-create-backup').classList.remove('hidden');
        }

        function closeCreateBackupModal() {
            document.getElementById('modal-create-backup').classList.add('hidden');
        }

        async function submitCreateBackup(e) {
            e.preventDefault();
            const bType = document.querySelector('input[name="backup_type"]:checked').value;
            const desc = document.getElementById('backup-desc-input').value.trim();
            const btn = document.getElementById('btn-submit-backup');

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Generating Archive...`;

            try {
                const res = await fetch(`${API_BASE}/backups/create`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ backup_type: bType, description: desc })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Backup archive created successfully!');
                    closeCreateBackupModal();
                    fetchBackups();
                } else {
                    alert(`Failed to create backup: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error creating backup: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-box-archive"></i> Generate Backup Archive`;
            }
        }

        function downloadBackup(filename) {
            window.location.href = `${API_BASE}/backups/download/${encodeURIComponent(filename)}`;
        }

        function openUploadBackupModal() {
            document.getElementById('modal-upload-backup').classList.remove('hidden');
        }

        function closeUploadBackupModal() {
            document.getElementById('modal-upload-backup').classList.add('hidden');
        }

        async function submitUploadBackup(e) {
            e.preventDefault();
            const fileInput = document.getElementById('backup-file-upload');
            if (!fileInput.files || fileInput.files.length === 0) {
                return alert('Please select a backup archive to upload.');
            }

            const file = fileInput.files[0];
            const formData = new FormData();
            formData.append('file', file);

            const btn = document.getElementById('btn-submit-upload');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Uploading Archive...`;

            const token = localStorage.getItem('zclockid_token');
            const authHeaders = {};
            if (token) authHeaders['Authorization'] = `Bearer ${token}`;

            try {
                const res = await fetch(`${API_BASE}/backups/upload`, {
                    method: 'POST',
                    headers: authHeaders,
                    body: formData
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Backup uploaded successfully!');
                    closeUploadBackupModal();
                    fileInput.value = '';
                    fetchBackups();
                } else {
                    const detail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
                    alert(`Upload failed: ${detail}`);
                }
            } catch (err) {
                alert(`Error uploading file: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-upload"></i> Upload & Verify`;
            }
        }

        async function inspectBackup(filename) {
            try {
                const res = await fetch(`${API_BASE}/backups/inspect`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ filename: filename })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Inspection failed');

                document.getElementById('inspect-modal-title').innerText = `Manifest: ${filename}`;
                const m = data.manifest || {};
                const grid = document.getElementById('inspect-meta-grid');
                grid.innerHTML = `
                    <div class="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                        <div><span class="text-slate-500 text-[10px] block">TYPE</span><span class="font-bold text-emerald-400 uppercase">${m.backup_type || 'Unknown'}</span></div>
                        <div><span class="text-slate-500 text-[10px] block">REALM</span><span class="font-bold text-white">${m.realm || 'Unknown'}</span></div>
                        <div><span class="text-slate-500 text-[10px] block">HOSTNAME</span><span class="font-bold text-cyan-300">${m.hostname || 'Unknown'}</span></div>
                        <div><span class="text-slate-500 text-[10px] block">VERSION</span><span class="font-bold text-indigo-300">${m.appliance_version || '1.1.0'}</span></div>
                    </div>
                `;

                document.getElementById('inspect-modal-json').innerText = JSON.stringify(m, null, 2);

                const cBox = document.getElementById('inspect-modal-contents');
                if (data.contents && data.contents.length > 0) {
                    cBox.innerHTML = data.contents.map(c => `
                        <div class="flex items-center justify-between py-0.5 border-b border-slate-900">
                            <span class="${c.is_dir ? 'text-indigo-300 font-bold' : 'text-slate-300'}">${c.name}</span>
                            <span class="text-slate-500 text-[10px]">${c.is_dir ? 'DIR' : `${(c.size/1024).toFixed(1)} KB`}</span>
                        </div>
                    `).join('');
                } else {
                    cBox.innerHTML = `<span class="text-slate-500">Archive file tree not available.</span>`;
                }

                document.getElementById('modal-inspect-backup').classList.remove('hidden');
            } catch (err) {
                alert(`Failed to inspect backup: ${err.message}`);
            }
        }

        function closeInspectBackupModal() {
            document.getElementById('modal-inspect-backup').classList.add('hidden');
        }

        function confirmRestoreBackup(filename) {
            const b = currentBackups.find(x => x.filename === filename);
            backupToRestore = filename;
            document.getElementById('restore-target-filename').innerText = filename;
            document.getElementById('restore-info-filename').innerText = filename;
            document.getElementById('restore-info-date').innerText = b ? new Date(b.created_at).toLocaleString() : '-';
            document.getElementById('restore-info-type').innerText = b ? b.backup_type : 'config_only';
            document.getElementById('restore-skip-ad').checked = false;
            document.getElementById('modal-confirm-restore').classList.remove('hidden');
        }

        function closeRestoreModal() {
            document.getElementById('modal-confirm-restore').classList.add('hidden');
            backupToRestore = null;
        }

        async function executeRestore() {
            if (!backupToRestore) return;
            const skipAd = document.getElementById('restore-skip-ad').checked;
            const btn = document.getElementById('btn-run-restore');

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Restoring Appliance...`;

            try {
                const res = await fetch(`${API_BASE}/backups/restore`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ filename: backupToRestore, skip_ad_restore: skipAd })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`Appliance Restored Successfully!\n\n${data.message}\n\nComponents restored:\n• ${data.restored_components.join('\n• ')}`);
                    closeRestoreModal();
                    fetchBackups();
                    fetchSystemStatus();
                } else {
                    alert(`Restore failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error executing restore: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-rotate-left"></i> Restore Appliance Now`;
            }
        }

        async function deleteBackup(filename) {
            if (!confirm(`Delete backup archive '${filename}'?\n\nThis cannot be undone.`)) return;
            try {
                const res = await fetch(`${API_BASE}/backups/${encodeURIComponent(filename)}`, {
                    method: 'DELETE',
                    headers: getAuthHeaders()
                });
                const data = await res.json();
                if (res.ok) {
                    fetchBackups();
                } else {
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting backup: ${err}`);
            }
        }

        // ==================== Self-Registration & OTP Logic ====================
        let currentRegFilter = 'all';

        function copyRegistrationLink() {
            const url = `${window.location.origin}/register.html`;
            navigator.clipboard.writeText(url).then(() => {
                alert(`Self-Registration Portal link copied to clipboard:\n\n${url}`);
            }).catch(() => {
                prompt("Copy registration URL:", url);
            });
        }

        async function fetchRegistrationSettings() {
            try {
                // Concurrently fetch settings, UPN suffixes, AD groups, and Bandwidth Profiles
                const [resSettings, resUpn, resGroups, resBw] = await Promise.all([
                    fetch(`${API_BASE}/registrations/settings`).then(r => r.json()),
                    fetch(`${API_BASE}/domain/upn`).then(r => r.json()).catch(() => ({ primary_realm: '', alternate_suffixes: [] })),
                    fetch(`${API_BASE}/groups`).then(r => r.json()).catch(() => ({ groups: [] })),
                    fetch(`${API_BASE}/radius/bandwidth-profiles`).then(r => r.json()).catch(() => ({ profiles: [] }))
                ]);

                if (resSettings && resSettings.settings) {
                    const s = resSettings.settings;

                    // 1. Populate Default Provisioning Domain Dropdown (Primary Realm + Alternate UPN suffixes)
                    const domSelect = document.getElementById('reg-cfg-domain');
                    if (domSelect) {
                        const primRealm = (resUpn.primary_realm || (currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : '')).toLowerCase();
                        let domOptions = primRealm ? `<option value="${primRealm}">${primRealm} (Primary Forest Root)</option>` : '<option value="">(No Realm Configured)</option>';
                        if (resUpn.alternate_suffixes && Array.isArray(resUpn.alternate_suffixes)) {
                            resUpn.alternate_suffixes.forEach(suf => {
                                const sufClean = suf.toLowerCase();
                                if (sufClean !== primRealm) {
                                    domOptions += `<option value="${sufClean}">${sufClean} (Alternate Domain / SPN)</option>`;
                                }
                            });
                        }
                        domSelect.innerHTML = domOptions;
                        domSelect.value = s.default_domain ? s.default_domain.toLowerCase() : primRealm;
                    }

                    // 2. Populate Default Security Group Dropdown
                    const grpSelect = document.getElementById('reg-cfg-group');
                    if (grpSelect) {
                        let grpOptions = `<option value="Domain Users">Domain Users (Default)</option>`;
                        if (resGroups.groups && Array.isArray(resGroups.groups)) {
                            resGroups.groups.forEach(g => {
                                if (g.group_name && g.group_name.toLowerCase() !== 'domain users' && !g.is_built_in) {
                                    grpOptions += `<option value="${g.group_name}">${g.group_name}</option>`;
                                }
                            });
                        }
                        grpSelect.innerHTML = grpOptions;
                        grpSelect.value = s.default_group || 'Domain Users';
                    }

                    // 3. Populate Default Bandwidth Profile Dropdown
                    const bwSelect = document.getElementById('reg-cfg-bw-profile');
                    if (bwSelect) {
                        let bwOptions = `<option value="0">None (No Bandwidth Rate Limit)</option>`;
                        if (resBw.profiles && Array.isArray(resBw.profiles)) {
                            resBw.profiles.forEach(p => {
                                const downStr = p.download_mbps > 0 ? `${p.download_mbps}M` : 'Unlimited';
                                const upStr = p.upload_mbps > 0 ? `${p.upload_mbps}M` : 'Unlimited';
                                bwOptions += `<option value="${p.id}">${p.name} (${downStr} / ${upStr})</option>`;
                            });
                        }
                        bwSelect.innerHTML = bwOptions;
                        bwSelect.value = s.default_bandwidth_profile_id || 0;
                    }

                    document.getElementById('reg-cfg-enabled').checked = s.enabled !== 0;
                    document.getElementById('reg-cfg-otp').checked = s.require_mobile_otp !== 0;
                    document.getElementById('reg-cfg-sms-type').value = s.sms_gateway_type || 'simulated';
                    document.getElementById('reg-cfg-sms-url').value = s.sms_gateway_url || '';
                    document.getElementById('reg-cfg-sms-key').value = s.sms_api_key || '';
                    document.getElementById('reg-cfg-sender').value = s.sms_sender_id || 'ZCLOCK';
                    document.getElementById('reg-cfg-sms-template').value = s.sms_template || 'Your ZclockID verification code is {otp}. Valid for 10 minutes.';
                    document.getElementById('reg-cfg-smtp-enabled').checked = s.email_smtp_enabled !== 0;
                    document.getElementById('reg-cfg-smtp-host').value = s.smtp_host || '';
                    document.getElementById('reg-cfg-smtp-port').value = s.smtp_port || 587;
                    document.getElementById('reg-cfg-smtp-user').value = s.smtp_user || '';
                    document.getElementById('reg-cfg-smtp-pass').value = s.smtp_pass || '';
                    document.getElementById('reg-cfg-smtp-from').value = s.smtp_from || '';

                    toggleSmsProviderFields();
                    toggleSmtpFields();

                    const modeEl = document.getElementById('reg-stat-mode');
                    if (!s.enabled) {
                        modeEl.innerHTML = '<span class="text-rose-400 font-semibold"><i class="fa-solid fa-ban"></i> Portal Disabled</span>';
                    } else if (s.require_mobile_otp) {
                        modeEl.innerHTML = '<span class="text-cyan-400 font-semibold"><i class="fa-solid fa-mobile-screen"></i> Mobile OTP Active (Auto-Approve)</span>';
                    } else {
                        modeEl.innerHTML = '<span class="text-amber-400 font-semibold"><i class="fa-solid fa-user-clock"></i> Manual Admin Approval</span>';
                    }

                    document.getElementById('reg-stat-sms').innerText = (s.sms_gateway_type || 'simulated').toUpperCase();
                    document.getElementById('reg-queue-domain').innerText = s.default_domain || (currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : '--');

                    // Populate organization departments tag manager
                    const rawDepts = s.allowed_departments || 'Engineering,IT Operations,Finance,Human Resources,Sales & Marketing,Operations';
                    currentRegDepartments = rawDepts.split(',').map(d => d.trim()).filter(Boolean);
                    renderRegDeptTags();
                }
            } catch (err) {
                console.error('Error fetching registration settings:', err);
            }
        }

        let currentRegDepartments = [];

        function renderRegDeptTags() {
            const container = document.getElementById('reg-dept-tags-container');
            const badge = document.getElementById('reg-dept-count-badge');
            if (badge) badge.innerText = `${currentRegDepartments.length} / 100 configured`;
            if (!container) return;
            if (currentRegDepartments.length === 0) {
                container.innerHTML = '<span class="text-slate-500 text-[11px] italic p-1">No departments configured. Default "General" will be used.</span>';
                return;
            }
            container.innerHTML = currentRegDepartments.map(d => `
                <span class="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-slate-200 text-[11px] font-sans flex items-center gap-1.5 shadow-sm">
                    <i class="fa-solid fa-briefcase text-[9px] text-indigo-400"></i> ${d}
                    <button type="button" onclick="removeRegistrationDepartment('${d.replace(/'/g, "\\'")}')" class="text-slate-400 hover:text-rose-400 transition ml-0.5" title="Remove ${d}">
                        <i class="fa-solid fa-xmark text-[10px]"></i>
                    </button>
                </span>
            `).join('');
        }

        function addRegistrationDepartment() {
            const input = document.getElementById('reg-new-dept-input');
            if (!input) return;
            const val = input.value.trim();
            if (!val) return;
            if (currentRegDepartments.length >= 100) {
                alert('Maximum 100 departments allowed. Please remove a department before adding another.');
                return;
            }
            if (currentRegDepartments.some(d => d.toLowerCase() === val.toLowerCase())) {
                alert(`Department "${val}" already exists in the list.`);
                return;
            }
            currentRegDepartments.push(val);
            input.value = '';
            renderRegDeptTags();
        }

        function removeRegistrationDepartment(deptName) {
            currentRegDepartments = currentRegDepartments.filter(d => d.toLowerCase() !== deptName.toLowerCase());
            renderRegDeptTags();
        }

        function resetDefaultRegistrationDepartments() {
            currentRegDepartments = ['Engineering', 'IT Operations', 'Finance', 'Human Resources', 'Sales & Marketing', 'Operations'];
            renderRegDeptTags();
        }

        function toggleSmsProviderFields() {
            const type = document.getElementById('reg-cfg-sms-type').value;
            const extSec = document.getElementById('sec-sms-ext');
            if (type === 'simulated') {
                extSec.classList.add('hidden');
            } else {
                extSec.classList.remove('hidden');
            }
        }

        function toggleSmtpFields() {
            const enabled = document.getElementById('reg-cfg-smtp-enabled').checked;
            const sec = document.getElementById('sec-smtp-fields');
            if (enabled) sec.classList.remove('hidden');
            else sec.classList.add('hidden');
        }

        function openRegistrationSettingsModal() {
            fetchRegistrationSettings();
            if (typeof fetchPortalTemplateStatus === 'function') fetchPortalTemplateStatus('registration');
            document.getElementById('modal-registration-settings').classList.remove('hidden');
        }

        function closeRegistrationSettingsModal() {
            document.getElementById('modal-registration-settings').classList.add('hidden');
        }

        async function saveRegistrationSettings(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-save-reg-settings');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving...`;

            const payload = {
                enabled: document.getElementById('reg-cfg-enabled').checked,
                require_mobile_otp: document.getElementById('reg-cfg-otp').checked,
                auto_approve_with_otp: document.getElementById('reg-cfg-otp').checked,
                default_domain: (document.getElementById('reg-cfg-domain').value || (currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : '')).trim(),
                default_group: (document.getElementById('reg-cfg-group').value || 'Domain Users').trim(),
                default_bandwidth_profile_id: parseInt(document.getElementById('reg-cfg-bw-profile').value, 10) || 0,
                allowed_departments: currentRegDepartments.join(','),
                sms_gateway_type: document.getElementById('reg-cfg-sms-type').value,
                sms_gateway_url: document.getElementById('reg-cfg-sms-url').value.trim(),
                sms_api_key: document.getElementById('reg-cfg-sms-key').value.trim(),
                sms_sender_id: document.getElementById('reg-cfg-sender').value.trim(),
                sms_template: document.getElementById('reg-cfg-sms-template').value.trim(),
                email_smtp_enabled: document.getElementById('reg-cfg-smtp-enabled').checked,
                smtp_host: document.getElementById('reg-cfg-smtp-host').value.trim(),
                smtp_port: parseInt(document.getElementById('reg-cfg-smtp-port').value || 587),
                smtp_user: document.getElementById('reg-cfg-smtp-user').value.trim(),
                smtp_pass: document.getElementById('reg-cfg-smtp-pass').value.trim(),
                smtp_from: document.getElementById('reg-cfg-smtp-from').value.trim()
            };

            try {
                const res = await fetch(`${API_BASE}/registrations/settings`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Registration & OTP verification policies updated successfully!');
                    closeRegistrationSettingsModal();
                    fetchRegistrationSettings();
                    fetchRegistrations(currentRegFilter);
                } else {
                    alert(`Failed to save settings: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving settings: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save Settings`;
            }
        }

        async function fetchRegistrations(filter = 'all') {
            currentRegFilter = filter;
            ['all', 'PENDING_APPROVAL', 'PENDING_OTP', 'VERIFIED_AUTO_PROVISIONED', 'APPROVED'].forEach(f => {
                const b = document.getElementById(`reg-filter-${f}`);
                if (b) {
                    if (f === filter) {
                        b.className = 'px-2.5 py-1 rounded-md text-[11px] font-semibold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30';
                    } else {
                        b.className = 'px-2.5 py-1 rounded-md text-[11px] text-slate-400 hover:text-white hover:bg-slate-800';
                    }
                }
            });

            const tbody = document.getElementById('registrations-table-body');
            try {
                const res = await fetch(`${API_BASE}/registrations/requests?status_filter=${encodeURIComponent(filter)}&_t=${Date.now()}`);
                const data = await res.json();

                if (res.ok && data.requests) {
                    let pendingCount = 0;
                    let autoCount = 0;
                    data.requests.forEach(r => {
                        if (r.status === 'PENDING_APPROVAL') pendingCount++;
                        if (r.status === 'VERIFIED_AUTO_PROVISIONED') autoCount++;
                    });
                    document.getElementById('reg-stat-pending').innerText = pendingCount;
                    document.getElementById('reg-stat-auto').innerText = autoCount;

                    if (data.requests.length === 0) {
                        tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No registration requests found matching filter '${filter}'.</td></tr>`;
                        return;
                    }

                    tbody.innerHTML = data.requests.map(r => {
                        let statusBadge = '';
                        if (r.status === 'VERIFIED_AUTO_PROVISIONED') {
                            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">OTP AUTO-PROVISIONED</span>';
                        } else if (r.status === 'PENDING_APPROVAL') {
                            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-semibold animate-pulse">PENDING REVIEW</span>';
                        } else if (r.status === 'PENDING_OTP') {
                            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800">AWAITING OTP</span>';
                        } else if (r.status === 'APPROVED') {
                            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800">APPROVED BY ADMIN</span>';
                        } else if (r.status === 'REJECTED') {
                            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800">REJECTED</span>';
                        } else {
                            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">${r.status}</span>`;
                        }

                        const dateStr = r.created_at ? new Date(r.created_at * 1000).toLocaleString() : '-';

                        let actionButtons = '';
                        if (r.status === 'PENDING_APPROVAL') {
                            actionButtons = `
                                <button onclick="approveRegistration(${r.id}, '${r.username}')" class="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-sans font-semibold text-[11px] transition mr-1" title="Approve & Provision into AD">
                                    <i class="fa-solid fa-check"></i> Approve
                                </button>
                                <button onclick="rejectRegistration(${r.id}, '${r.username}')" class="px-2 py-1 rounded bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 border border-rose-500/30 font-sans text-[11px] transition mr-1" title="Reject Request">
                                    <i class="fa-solid fa-xmark"></i> Reject
                                </button>
                            `;
                        } else if (r.status === 'VERIFIED_AUTO_PROVISIONED' || r.status === 'APPROVED') {
                            actionButtons = `
                                <button onclick="openChangeUpnModal('${r.username}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 text-[10px] transition mr-1" title="Change UserPrincipalName (UPN)">
                                    <i class="fa-solid fa-at"></i> UPN
                                </button>
                            `;
                        }
                        actionButtons += `
                            <button onclick="deleteRegistration(${r.id}, '${r.username}')" class="text-slate-500 hover:text-rose-400 transition ml-1" title="Delete Log Entry">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        `;

                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-3">
                                    <div class="font-bold text-white">${r.username}</div>
                                    <div class="text-[10px] text-slate-400">${r.given_name || ''} ${r.surname || ''}</div>
                                </td>
                                <td class="px-4 py-3 text-cyan-300 font-mono text-xs">${r.mobile || '-'}</td>
                                <td class="px-4 py-3 text-slate-300 font-sans">${r.email || '-'}</td>
                                <td class="px-4 py-3 text-slate-400 font-sans">${r.department || '-'}</td>
                                <td class="px-4 py-3 whitespace-nowrap">${statusBadge}</td>
                                <td class="px-4 py-3 text-slate-500 font-mono text-[10px]">${dateStr}</td>
                                <td class="px-4 py-3 text-right whitespace-nowrap">${actionButtons}</td>
                            </tr>
                        `;
                    }).join('');
                }
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-4 text-center text-rose-400">Failed to load registration queue: ${err}</td></tr>`;
            }
        }

        async function approveRegistration(id, username) {
            if (!confirm(`Approve registration for user '${username}'?\n\nThis will provision the user in Active Directory under primary domain and dispatch an activation confirmation.`)) return;

            try {
                const res = await fetch(`${API_BASE}/registrations/requests/${id}/approve`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ notes: "Approved by administrator" })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || `User '${username}' approved successfully!`);
                    fetchRegistrations(currentRegFilter);
                    fetchUsers();
                } else {
                    alert(`Approval failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error approving registration: ${err}`);
            }
        }

        async function rejectRegistration(id, username) {
            const reason = prompt(`Reject registration for user '${username}'.\nEnter rejection reason for user notification:`, "Account request did not meet security requirements.");
            if (reason === null) return;

            try {
                const res = await fetch(`${API_BASE}/registrations/requests/${id}/reject`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ notes: reason })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || `Request for '${username}' rejected.`);
                    fetchRegistrations(currentRegFilter);
                } else {
                    alert(`Rejection failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error rejecting registration: ${err}`);
            }
        }

        async function deleteRegistration(id, username) {
            if (!confirm(`Delete registration record for '${username}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/registrations/requests/${id}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchRegistrations(currentRegFilter);
                } else {
                    alert('Failed to delete registration record.');
                }
            } catch (err) {
                alert(`Error deleting record: ${err}`);
            }
        }

        // ==================== SOFTWARE UPDATES & UPGRADE SUBSYSTEM ====================
        let stagedDebFile = null;
        let updatePollInterval = null;
        let cachedLatestRelease = null;
        let currentUpdateSubTab = 'appliance';
        let currentUpdateLogType = 'appliance';
        let cachedOsPackages = [];
        let osUpgradePollInterval = null;

        function switchUpdateSubTab(sub) {
            currentUpdateSubTab = sub;
            const btnApp = document.getElementById('btn-subtab-update-appliance');
            const btnOs = document.getElementById('btn-subtab-update-os');
            const viewApp = document.getElementById('subtab-view-appliance');
            const viewOs = document.getElementById('subtab-view-os');
            const osActions = document.getElementById('subtab-os-actions');

            if (sub === 'appliance') {
                if (btnApp) {
                    btnApp.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-violet-600/20 text-violet-400 border border-violet-500/30 transition flex items-center gap-1.5';
                }
                if (btnOs) {
                    btnOs.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition flex items-center gap-1.5';
                }
                if (viewApp) viewApp.classList.remove('hidden');
                if (viewOs) viewOs.classList.add('hidden');
                if (osActions) osActions.classList.add('hidden');
            } else {
                if (btnApp) {
                    btnApp.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium text-slate-400 hover:text-white transition flex items-center gap-1.5';
                }
                if (btnOs) {
                    btnOs.className = 'px-3.5 py-1.5 rounded-lg text-xs font-bold bg-orange-600/20 text-orange-400 border border-orange-500/30 transition flex items-center gap-1.5';
                }
                if (viewApp) viewApp.classList.add('hidden');
                if (viewOs) viewOs.classList.remove('hidden');
                if (osActions) osActions.classList.remove('hidden');
                loadOsUpdateInfo();
            }
        }

        function switchUpdateLogType(logType) {
            currentUpdateLogType = logType;
            const btnApp = document.getElementById('btn-log-tab-appliance');
            const btnOs = document.getElementById('btn-log-tab-os');
            const label = document.getElementById('update-terminal-log-label');

            if (logType === 'appliance') {
                if (btnApp) btnApp.className = 'px-2.5 py-1 rounded-md bg-violet-600/30 text-violet-300 font-semibold transition';
                if (btnOs) btnOs.className = 'px-2.5 py-1 rounded-md text-slate-400 hover:text-white transition';
                if (label) label.innerText = '/var/log/zclock-update.log';
            } else {
                if (btnApp) btnApp.className = 'px-2.5 py-1 rounded-md text-slate-400 hover:text-white transition';
                if (btnOs) btnOs.className = 'px-2.5 py-1 rounded-md bg-orange-600/30 text-orange-300 font-semibold transition';
                if (label) label.innerText = '/var/log/zclock-os-update.log';
            }
            fetchCurrentUpdateLog();
        }

        async function fetchCurrentUpdateLog() {
            if (currentUpdateLogType === 'os') {
                await fetchOsUpdateLog();
            } else {
                await fetchUpdateLog();
            }
        }

        async function fetchOsUpdateLog() {
            try {
                const res = await fetch(`${API_BASE}/system/os-updates/log`);
                if (!res.ok) return;
                const data = await res.json();
                if (data.log) {
                    const pre = document.getElementById('update-terminal-pre');
                    pre.innerText = data.log;
                    pre.scrollTop = pre.scrollHeight;
                    const lines = data.log.split('\n').filter(l => l.trim().length > 0);
                    const lineCountEl = document.getElementById('update-terminal-line-count');
                    if (lineCountEl) lineCountEl.innerText = `${lines.length} lines`;
                }
            } catch (err) {
                console.warn("Could not fetch OS update log:", err);
            }
        }

        async function loadOsUpdateInfo() {
            try {
                const res = await fetch(`${API_BASE}/system/os-updates/info`);
                if (!res.ok) return;
                const data = await res.json();

                renderOsUpdateState(data);

                if ((!data.packages || data.packages.length === 0) && (!data.last_checked || data.last_checked === 0)) {
                    checkOsPackages();
                }
            } catch (err) {
                console.error("Error loading OS update info:", err);
            }
        }

        function renderOsUpdateState(data) {
            cachedOsPackages = data.packages || [];
            const total = data.total_upgrades !== undefined ? data.total_upgrades : cachedOsPackages.length;
            const sec = data.security_upgrades || 0;

            const badgeCount = document.getElementById('badge-os-update-count');
            if (badgeCount) {
                badgeCount.innerText = total;
                if (total > 0) badgeCount.classList.remove('hidden');
                else badgeCount.classList.add('hidden');
            }

            const kpiTotal = document.getElementById('os-kpi-total');
            if (kpiTotal) kpiTotal.innerText = total;

            const kpiSec = document.getElementById('os-kpi-security');
            if (kpiSec) kpiSec.innerText = sec;

            const kernelCount = cachedOsPackages.filter(p => p.category === 'Kernel' || p.category === 'Core System').length;
            const kpiKernel = document.getElementById('os-kpi-kernel');
            if (kpiKernel) kpiKernel.innerText = kernelCount;

            const kpiChecked = document.getElementById('os-kpi-checked');
            if (kpiChecked) {
                if (data.last_checked && data.last_checked > 0) {
                    kpiChecked.innerText = new Date(data.last_checked * 1000).toLocaleString();
                } else {
                    kpiChecked.innerText = 'Never';
                }
            }

            const btnTop = document.getElementById('btn-upgrade-all-os');
            const btnTable = document.getElementById('btn-upgrade-os-table');
            const canUpgrade = total > 0 && !data.is_running;

            if (btnTop) {
                btnTop.disabled = !canUpgrade;
                if (data.is_running) {
                    btnTop.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Upgrading System...`;
                } else if (total === 0) {
                    btnTop.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> Up to Date`;
                } else {
                    btnTop.innerHTML = `<i class="fa-solid fa-download"></i> Upgrade All System Packages`;
                }
            }
            if (btnTable) {
                btnTable.disabled = !canUpgrade;
                if (data.is_running) {
                    btnTable.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Upgrading System...`;
                } else if (total === 0) {
                    btnTable.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> Up to Date`;
                } else {
                    btnTable.innerHTML = `<i class="fa-solid fa-download"></i> Upgrade All System Packages`;
                }
            }

            const rebootBanner = document.getElementById('os-reboot-banner');
            const rebootList = document.getElementById('os-reboot-pkgs-list');
            if (rebootBanner) {
                if (data.reboot_required) {
                    rebootBanner.classList.remove('hidden');
                    if (rebootList && data.reboot_packages && data.reboot_packages.length > 0) {
                        rebootList.innerText = `Required by: ${data.reboot_packages.join(', ')}`;
                    }
                } else {
                    rebootBanner.classList.add('hidden');
                }
            }

            renderOsPackagesTable(cachedOsPackages);

            if (data.is_running) {
                startOsUpgradeWatchdog();
            }
        }

        async function checkOsPackages() {
            const btnTop = document.getElementById('btn-check-os-packages');
            const btnTable = document.getElementById('btn-scan-apt-table');
            const tbody = document.getElementById('os-packages-tbody');

            if (btnTop) btnTop.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning...`;
            if (btnTable) btnTable.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Scanning...`;
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="py-8 text-center text-slate-400 font-sans">
                            <i class="fa-solid fa-circle-notch fa-spin text-xl text-violet-400 mb-2 block"></i>
                            Querying Debian / Ubuntu APT repositories for upgradable packages...
                        </td>
                    </tr>
                `;
            }

            try {
                const res = await fetch(`${API_BASE}/system/os-updates/check`, { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    renderOsUpdateState(data);
                } else {
                    alert(`Package check failed: ${data.detail || 'Unknown error'}`);
                    loadOsUpdateInfo();
                }
            } catch (err) {
                alert(`Error querying packages: ${err}`);
                loadOsUpdateInfo();
            } finally {
                if (btnTop) btnTop.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Scan APT Packages`;
                if (btnTable) btnTable.innerHTML = `<i class="fa-solid fa-arrows-rotate"></i> Scan Repositories`;
            }
        }

        function renderOsPackagesTable(packages) {
            const tbody = document.getElementById('os-packages-tbody');
            if (!tbody) return;

            if (!packages || packages.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="6" class="py-10 text-center text-slate-400 font-sans">
                            <div class="h-12 w-12 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 flex items-center justify-center text-xl mx-auto mb-3">
                                <i class="fa-solid fa-circle-check"></i>
                            </div>
                            <div class="text-sm font-bold text-white">All System Packages are Up to Date</div>
                            <div class="text-xs text-slate-500 mt-1">This appliance has all latest Debian / Ubuntu security patches and system updates installed.</div>
                        </td>
                    </tr>
                `;
                return;
            }

            let html = '';
            packages.forEach(pkg => {
                let catBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-300">${pkg.category || 'General'}</span>`;
                if (pkg.category === 'Kernel') {
                    catBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">Kernel</span>`;
                } else if (pkg.category === 'Security / Crypto') {
                    catBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">Security / Crypto</span>`;
                } else if (pkg.category === 'Core System') {
                    catBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-sky-500/20 text-sky-300 border border-sky-500/30">Core System</span>`;
                } else if (pkg.category === 'Directory / DNS') {
                    catBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Identity & DNS</span>`;
                }

                let secBadge = pkg.is_security
                    ? `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-600 text-white flex items-center gap-1 w-max"><i class="fa-solid fa-shield-virus text-[9px]"></i> SECURITY</span>`
                    : `<span class="px-2 py-0.5 rounded text-[10px] font-mono text-slate-400 bg-slate-800/80">${pkg.suite || 'updates'}</span>`;

                html += `
                    <tr class="hover:bg-slate-800/30 transition">
                        <td class="py-2.5 px-4 font-bold text-white flex items-center gap-2">
                            <i class="fa-solid fa-cube text-slate-500 text-xs"></i>
                            <span>${pkg.name}</span>
                        </td>
                        <td class="py-2.5 px-4">${catBadge}</td>
                        <td class="py-2.5 px-4 text-slate-400">${pkg.current_version}</td>
                        <td class="py-2.5 px-4 text-emerald-400 font-bold">${pkg.candidate_version}</td>
                        <td class="py-2.5 px-4 text-slate-500 text-[11px]">${pkg.arch}</td>
                        <td class="py-2.5 px-4">${secBadge}</td>
                    </tr>
                `;
            });
            tbody.innerHTML = html;
        }

        function filterOsPackagesTable() {
            const query = (document.getElementById('os-search-input')?.value || '').toLowerCase().trim();
            const cat = document.getElementById('os-category-select')?.value || 'ALL';

            const filtered = cachedOsPackages.filter(pkg => {
                const matchesQuery = !query || pkg.name.toLowerCase().includes(query) || (pkg.category || '').toLowerCase().includes(query);
                let matchesCat = true;
                if (cat === 'SECURITY') matchesCat = pkg.is_security;
                else if (cat !== 'ALL') matchesCat = (pkg.category === cat);
                return matchesQuery && matchesCat;
            });
            renderOsPackagesTable(filtered);
        }

        async function confirmAndRunOsUpgrade() {
            const total = cachedOsPackages.length;
            const confirmed = confirm(`Are you sure you want to upgrade ${total} Debian/Ubuntu system packages?\n\n- Packages will be installed non-interactively via APT.\n- Live upgrade progress will stream in the terminal console below.\n- Directory replication and core AD services remain uninterrupted.`);
            if (!confirmed) return;

            const btnTop = document.getElementById('btn-upgrade-all-os');
            const btnTable = document.getElementById('btn-upgrade-os-table');
            if (btnTop) { btnTop.disabled = true; btnTop.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Initializing...`; }
            if (btnTable) { btnTable.disabled = true; btnTable.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Initializing...`; }

            switchUpdateLogType('os');
            setUpdateTerminalStatus('UPGRADING OS');

            try {
                const res = await fetch(`${API_BASE}/system/os-updates/upgrade`, { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    appendTerminalLog(`[ZclockID Console] OS package upgrade task started: ${data.message}`);
                    startOsUpgradeWatchdog();
                } else {
                    alert(`Failed to start OS upgrade: ${data.detail || 'Unknown error'}`);
                    loadOsUpdateInfo();
                }
            } catch (err) {
                alert(`Error starting upgrade: ${err}`);
                loadOsUpdateInfo();
            }
        }

        function startOsUpgradeWatchdog() {
            if (osUpgradePollInterval) clearInterval(osUpgradePollInterval);
            setUpdateTerminalStatus('UPGRADING OS');

            osUpgradePollInterval = setInterval(async () => {
                fetchOsUpdateLog();

                try {
                    const res = await fetch(`${API_BASE}/system/os-updates/info`);
                    if (res.ok) {
                        const data = await res.json();
                        if (!data.is_running) {
                            clearInterval(osUpgradePollInterval);
                            osUpgradePollInterval = null;
                            setUpdateTerminalStatus('COMPLETE');
                            appendTerminalLog(`\n🎉 Debian/Ubuntu package upgrade completed! Final status: ${data.last_status}`);
                            await checkOsPackages();
                        }
                    }
                } catch (e) {
                    console.warn("Watchdog check:", e);
                }
            }, 3000);
        }

        async function confirmAndRebootAppliance() {
            const confirmed = confirm("Are you sure you want to reboot this ZclockID appliance?\n\nAll services will restart and the system will be momentarily offline for 30-60 seconds.");
            if (!confirmed) return;

            try {
                const res = await fetch(`${API_BASE}/system/reboot`, { method: 'POST' });
                const data = await res.json();
                if (res.ok) {
                    alert("Reboot command sent successfully! The appliance will restart momentarily.");
                    location.reload();
                } else {
                    alert(`Reboot failed: ${data.detail || 'Unknown error'}`);
                }
            } catch (err) {
                alert(`Error sending reboot signal: ${err}`);
            }
        }

        async function loadUpdateInfo() {
            try {
                const res = await fetch(`${API_BASE}/system/update/info`);
                if (!res.ok) return;
                const data = await res.json();

                // Current system version & arch
                const currV = data.current_version || '1.0.0';
                if (document.getElementById('header-version-badge')) document.getElementById('header-version-badge').innerText = `v${currV}`;
                document.getElementById('info-current-version').innerText = currV;
                document.getElementById('update-current-ver-badge').innerText = `v${currV}`;
                document.getElementById('dash-version-badge').innerText = `v${currV}`;
                document.getElementById('appliance-version-label').innerText = `ZclockID v${currV}`;
                document.getElementById('info-system-arch').innerText = `${data.system_arch || 'amd64'} (${data.platform_system || 'Linux'})`;
                document.getElementById('info-python-ver').innerText = `Python ${data.python_version || '3.12'}`;

                // Channel settings
                if (data.settings) {
                    const repoEl = document.getElementById('update-github-repo');
                    if (repoEl && data.settings.github_repo) {
                        repoEl.value = data.settings.github_repo;
                    }
                    const manifestEl = document.getElementById('update-custom-manifest');
                    if (manifestEl && data.settings.custom_manifest_url !== undefined) {
                        manifestEl.value = data.settings.custom_manifest_url;
                    }
                    const autoEl = document.getElementById('update-auto-check');
                    if (autoEl && data.settings.auto_check !== undefined) {
                        autoEl.checked = !!data.settings.auto_check;
                    }
                    if (data.settings.last_checked && data.settings.last_checked > 0) {
                        const d = new Date(data.settings.last_checked * 1000);
                        const lastCheckedEl = document.getElementById('info-last-checked');
                        if (lastCheckedEl) lastCheckedEl.innerText = d.toLocaleString();
                    }

                    // If cached release is newer
                    if (data.update_available && data.settings.latest_version) {
                        displayUpdateAvailable({
                            latest_version: data.settings.latest_version,
                            release_name: data.settings.latest_release_name,
                            release_notes: data.settings.latest_release_notes,
                            download_url: data.settings.latest_download_url,
                            release_type: data.settings.release_type || 'patch'
                        });
                    }
                }

                // If update is currently running, monitor it
                if (data.is_running) {
                    setUpdateTerminalStatus('UPDATING');
                    startUpdateWatchdog();
                }

                fetchCurrentUpdateLog();

                // Also refresh OS updates count badge in background
                fetch(`${API_BASE}/system/os-updates/info`).then(r => r.json()).then(osData => {
                    const total = osData.total_upgrades !== undefined ? osData.total_upgrades : (osData.packages ? osData.packages.length : 0);
                    const badgeCount = document.getElementById('badge-os-update-count');
                    if (badgeCount) {
                        badgeCount.innerText = total;
                        if (total > 0) badgeCount.classList.remove('hidden');
                        else badgeCount.classList.add('hidden');
                    }
                }).catch(() => {});
            } catch (err) {
                console.error("Error loading update info:", err);
            }
        }

        async function saveUpdateAutoCheck() {
            const autoEl = document.getElementById('update-auto-check');
            const autoCheck = autoEl ? autoEl.checked : true;
            try {
                await fetch(`${API_BASE}/system/update/settings`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ auto_check: autoCheck })
                });
            } catch (err) {
                console.error("Failed to save auto-check setting:", err);
            }
        }

        async function saveUpdateSettings() {
            const autoEl = document.getElementById('update-auto-check');
            const autoCheck = autoEl ? autoEl.checked : true;

            try {
                const res = await fetch(`${API_BASE}/system/update/settings`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        auto_check: autoCheck
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    alert('Update settings saved successfully.');
                } else {
                    alert(`Failed to save settings: ${data.detail || 'Unknown error'}`);
                }
            } catch (err) {
                alert(`Error saving update settings: ${err}`);
            }
        }

        async function checkForSystemUpdates() {
            const btn = document.getElementById('btn-check-updates-top');
            const dashBtn = document.getElementById('btn-dash-check-updates');
            const statusPill = document.getElementById('remote-check-status-pill');
            const resultCard = document.getElementById('release-result-card');

            if (btn) btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking...`;
            if (dashBtn) dashBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking...`;
            if (statusPill) {
                statusPill.innerText = 'CHECKING...';
                statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-violet-950 text-violet-300 border border-violet-800 animate-pulse';
            }

            if (resultCard) {
                resultCard.innerHTML = `
                    <div class="flex items-center gap-3 text-slate-300">
                        <i class="fa-solid fa-circle-notch fa-spin text-violet-400 text-lg"></i>
                        <div class="text-xs">
                            <div class="font-semibold text-white">Contacting Release Channel...</div>
                            <div class="text-[11px] text-slate-400">Querying upstream repository for latest tagged releases and packages.</div>
                        </div>
                    </div>
                `;
            }

            try {
                const res = await fetch(`${API_BASE}/system/update/check`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({})
                });
                const data = await res.json();

                if (data.update_available) {
                    if (statusPill) {
                        statusPill.innerText = 'UPDATE FOUND';
                        statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800 font-bold';
                    }
                    displayUpdateAvailable(data);
                } else if (data.status === 'success') {
                    if (statusPill) {
                        statusPill.innerText = 'UP TO DATE';
                        statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800';
                    }
                    displayUpToDate(data);
                } else if (data.status === 'no_releases') {
                    if (statusPill) {
                        statusPill.innerText = 'NO RELEASES';
                        statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400';
                    }
                    displayNoReleases(data);
                } else {
                    if (statusPill) {
                        statusPill.innerText = 'OFFLINE / NOTICE';
                        statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-400 border border-amber-800';
                    }
                    displayOfflineNotice(data);
                }

                const lastCheckedEl = document.getElementById('info-last-checked');
                if (lastCheckedEl) lastCheckedEl.innerText = new Date().toLocaleString();
            } catch (err) {
                if (statusPill) {
                    statusPill.innerText = 'CHECK FAILED';
                    statusPill.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800';
                }
                if (resultCard) {
                    resultCard.innerHTML = `
                        <div class="flex items-center gap-3 text-rose-300">
                            <i class="fa-solid fa-triangle-exclamation text-rose-400 text-lg"></i>
                            <div class="text-xs">
                                <div class="font-semibold text-rose-200">Update Check Error</div>
                                <div class="text-[11px] text-slate-400">${err}</div>
                            </div>
                        </div>
                    `;
                }
            } finally {
                if (btn) btn.innerHTML = `<i class="fa-solid fa-magnifying-glass"></i> Check for Updates`;
                if (dashBtn) dashBtn.innerHTML = `<i class="fa-solid fa-magnifying-glass text-slate-400"></i> Check Updates`;
            }
        }

        function displayUpdateAvailable(data) {
            cachedLatestRelease = data;
            const resultCard = document.getElementById('release-result-card');
            const notesContainer = document.getElementById('release-notes-container');
            const notesBody = document.getElementById('release-notes-body');
            const actionContainer = document.getElementById('update-action-container');
            const targetPkgName = document.getElementById('target-pkg-name');
            const targetPkgSize = document.getElementById('target-pkg-size');
            const navBadge = document.getElementById('nav-update-badge');
            const dashBadge = document.getElementById('dash-update-available-badge');
            const dashSummary = document.getElementById('dash-update-summary');

            if (navBadge) navBadge.classList.remove('hidden');
            if (dashBadge) dashBadge.classList.remove('hidden');
            if (dashSummary) dashSummary.innerText = `New version v${data.latest_version} is available for installation!`;

            const relType = (data.release_type || 'patch').toLowerCase();
            let typeBadge = `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">Patch</span>`;
            if (relType === 'major') {
                typeBadge = `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-rose-500/20 text-rose-300 border border-rose-500/30">Major Upgrade</span>`;
            } else if (relType === 'minor') {
                typeBadge = `<span class="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider bg-sky-500/20 text-sky-300 border border-sky-500/30">Feature Release</span>`;
            }

            if (resultCard) {
                resultCard.innerHTML = `
                    <div class="flex items-start justify-between gap-3">
                        <div class="flex items-start gap-3">
                            <div class="h-9 w-9 rounded-lg bg-amber-500/20 border border-amber-500/30 flex items-center justify-center text-amber-400 text-base shrink-0 mt-0.5">
                                <i class="fa-solid fa-rocket"></i>
                            </div>
                            <div>
                                <div class="flex items-center gap-2">
                                    <span class="font-bold text-white text-sm">New Release Available!</span>
                                    <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-violet-600 text-white font-bold">v${data.latest_version}</span>
                                    ${typeBadge}
                                </div>
                                <div class="text-xs text-slate-300 mt-1">${data.release_name || `ZclockID v${data.latest_version}`}</div>
                                <div class="text-[10px] text-slate-500 mt-0.5">Published: ${data.published_at ? new Date(data.published_at).toLocaleDateString() : 'Recent'}</div>
                            </div>
                        </div>
                    </div>
                `;
            }

            if (data.release_notes && notesContainer && notesBody) {
                notesContainer.classList.remove('hidden');
                notesBody.innerText = data.release_notes;
                if (data.published_at) {
                    const dt = document.getElementById('release-date-badge');
                    if (dt) dt.innerText = new Date(data.published_at).toLocaleString();
                }
            }

            if (actionContainer) actionContainer.classList.remove('hidden');
            if (targetPkgName) targetPkgName.innerText = `zclockid_${data.latest_version}_all.deb`;
            if (targetPkgSize && data.asset_size) {
                const kb = Math.round(data.asset_size / 1024);
                targetPkgSize.innerText = `${kb} KB`;
            }
        }

        function displayUpToDate(data) {
            const resultCard = document.getElementById('release-result-card');
            const notesContainer = document.getElementById('release-notes-container');
            const actionContainer = document.getElementById('update-action-container');
            const navBadge = document.getElementById('nav-update-badge');
            const dashBadge = document.getElementById('dash-update-available-badge');

            if (navBadge) navBadge.classList.add('hidden');
            if (dashBadge) dashBadge.classList.add('hidden');
            if (notesContainer) notesContainer.classList.add('hidden');
            if (actionContainer) actionContainer.classList.add('hidden');

            if (resultCard) {
                resultCard.innerHTML = `
                    <div class="flex items-center gap-3 text-emerald-400">
                        <div class="h-9 w-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center text-emerald-400 text-base shrink-0">
                            <i class="fa-solid fa-circle-check"></i>
                        </div>
                        <div class="text-xs">
                            <div class="font-bold text-white">Appliance is Up to Date</div>
                            <div class="text-[11px] text-slate-400">Current version <span class="font-mono text-emerald-400 font-semibold">v${data.current_version}</span> is the latest release published on this channel.</div>
                        </div>
                    </div>
                `;
            }
        }

        function displayNoReleases(data) {
            const resultCard = document.getElementById('release-result-card');
            const notesContainer = document.getElementById('release-notes-container');
            const actionContainer = document.getElementById('update-action-container');

            if (notesContainer) notesContainer.classList.add('hidden');
            if (actionContainer) actionContainer.classList.add('hidden');

            if (resultCard) {
                resultCard.innerHTML = `
                    <div class="flex items-center gap-3 text-slate-400">
                        <i class="fa-solid fa-box-open text-slate-500 text-xl shrink-0"></i>
                        <div class="text-xs">
                            <div class="font-semibold text-slate-200">No Releases Published Yet</div>
                            <div class="text-[11px] text-slate-400">${data.message || 'The specified GitHub repository has no release assets tagged yet.'}</div>
                            <div class="text-[10px] text-cyan-400 mt-1"><i class="fa-solid fa-arrow-down"></i> You can upload a .deb package directly using the manual upload form below.</div>
                        </div>
                    </div>
                `;
            }
        }

        function displayOfflineNotice(data) {
            const resultCard = document.getElementById('release-result-card');
            const notesContainer = document.getElementById('release-notes-container');
            const actionContainer = document.getElementById('update-action-container');

            if (notesContainer) notesContainer.classList.add('hidden');
            if (actionContainer) actionContainer.classList.add('hidden');

            if (resultCard) {
                resultCard.innerHTML = `
                    <div class="flex items-center gap-3 text-amber-400">
                        <i class="fa-solid fa-triangle-exclamation text-amber-400 text-xl shrink-0"></i>
                        <div class="text-xs">
                            <div class="font-semibold text-slate-200">Update Channel Notice</div>
                            <div class="text-[11px] text-slate-400">${data.message || 'Could not connect to release server.'}</div>
                            <div class="text-[10px] text-cyan-400 mt-1">Appliance is ready for offline updates via direct .deb file upload below.</div>
                        </div>
                    </div>
                `;
            }
        }

        async function confirmAndRunUpdate() {
            if (!cachedLatestRelease) return;
            const targetVer = cachedLatestRelease.latest_version;
            const confirmed = confirm(`Are you sure you want to upgrade ZclockID to v${targetVer}?\n\n- The API process will reload in the background.\n- Active Directory Samba services will remain uninterrupted.\n- All database records and configs will be preserved.`);
            if (!confirmed) return;

            const btn = document.getElementById('btn-run-update-now');
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Initializing Update...`;
            }

            setUpdateStep(1, 'active');
            setUpdateTerminalStatus('UPDATING');

            try {
                const res = await fetch(`${API_BASE}/system/update/install`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        download_url: cachedLatestRelease.download_url
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    appendTerminalLog(`[ZclockID Console] Background update runner initiated for v${targetVer}.`);
                    startUpdateWatchdog(targetVer);
                } else {
                    alert(`Failed to start update: ${data.detail || 'Unknown error'}`);
                    if (btn) {
                        btn.disabled = false;
                        btn.innerHTML = `<i class="fa-solid fa-bolt"></i> Install & Apply Update Now`;
                    }
                }
            } catch (err) {
                // If fetch failed due to API restart, watchdog handles it
                appendTerminalLog(`[ZclockID Console] Update command sent. Monitoring API reconnect...`);
                startUpdateWatchdog(targetVer);
            }
        }

        function handleDebFileSelected(event) {
            const file = event.target.files[0];
            if (!file) return;

            if (!file.name.endsWith('.deb')) {
                alert('Please select a valid Debian package archive (.deb)');
                event.target.value = '';
                return;
            }

            stagedDebFile = file;
            document.getElementById('staged-file-name').innerText = file.name;
            document.getElementById('staged-file-size').innerText = `${Math.round(file.size / 1024)} KB`;
            document.getElementById('staged-file-status').innerText = 'READY TO UPLOAD';
            document.getElementById('staged-file-status').className = 'text-[10px] font-mono text-emerald-400 font-bold';

            const btn = document.getElementById('btn-submit-deb');
            btn.disabled = false;
            btn.className = 'w-full py-2 bg-gradient-to-r from-violet-600 to-indigo-600 hover:from-violet-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold transition flex items-center justify-center gap-2 cursor-pointer shadow-md shadow-violet-600/20';

            document.getElementById('upload-label-main').innerText = `Selected: ${file.name}`;
            document.getElementById('upload-label-sub').innerText = `Size: ${Math.round(file.size / 1024)} KB - Click 'Upload & Install Package' to proceed`;
        }

        async function submitDebUpload() {
            if (!stagedDebFile) {
                alert('Please select a .deb file first.');
                return;
            }

            const autoInstall = document.getElementById('upload-auto-install').checked;
            const btn = document.getElementById('btn-submit-deb');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Uploading Package...`;

            setUpdateStep(1, 'active');
            setUpdateTerminalStatus('UPLOADING');
            appendTerminalLog(`[ZclockID Console] Uploading package file: ${stagedDebFile.name} (${Math.round(stagedDebFile.size / 1024)} KB)...`);

            const formData = new FormData();
            formData.append('package', stagedDebFile);
            formData.append('auto_install', autoInstall ? 'true' : 'false');

            try {
                const res = await fetch(`${API_BASE}/system/update/upload`, {
                    method: 'POST',
                    body: formData
                });
                const data = await res.json();

                if (res.ok) {
                    appendTerminalLog(`[ZclockID Console] Package uploaded and verified: ${data.package} v${data.version} (${data.arch})`);
                    setUpdateStep(2, 'success');

                    if (autoInstall) {
                        setUpdateStep(3, 'active');
                        setUpdateTerminalStatus('UPDATING');
                        appendTerminalLog(`[ZclockID Console] Background updater runner active. Installing v${data.version}...`);
                        startUpdateWatchdog(data.version);
                    } else {
                        alert(`Package v${data.version} uploaded successfully and verified!`);
                        btn.disabled = false;
                        btn.innerHTML = `<i class="fa-solid fa-check"></i> Package Staged`;
                    }
                } else {
                    alert(`Package validation failed: ${data.detail || 'Unknown error'}`);
                    setUpdateStep(2, 'error');
                    setUpdateTerminalStatus('ERROR');
                    btn.disabled = false;
                    btn.innerHTML = `<i class="fa-solid fa-upload"></i> Upload & Install Package`;
                }
            } catch (err) {
                if (autoInstall) {
                    // API might have immediately restarted
                    appendTerminalLog(`[ZclockID Console] API connection dropped for service restart. Monitoring reconnection...`);
                    startUpdateWatchdog();
                } else {
                    alert(`Upload error: ${err}`);
                    btn.disabled = false;
                    btn.innerHTML = `<i class="fa-solid fa-upload"></i> Upload & Install Package`;
                }
            }
        }

        function setUpdateStep(stepNum, status) {
            const stepIds = ['step-stage', 'step-verify', 'step-unpack', 'step-restart', 'step-healthy'];
            stepIds.forEach((id, idx) => {
                const el = document.getElementById(id);
                if (!el) return;
                const n = idx + 1;
                if (n < stepNum) {
                    el.className = 'p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-bold transition';
                } else if (n === stepNum) {
                    if (status === 'active') {
                        el.className = 'p-2.5 rounded-lg bg-violet-950/80 border border-violet-500 text-violet-300 font-bold animate-pulse transition';
                    } else if (status === 'success') {
                        el.className = 'p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-800 text-emerald-400 font-bold transition';
                    } else if (status === 'error') {
                        el.className = 'p-2.5 rounded-lg bg-rose-950/60 border border-rose-800 text-rose-400 font-bold transition';
                    }
                } else {
                    el.className = 'p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-500 transition';
                }
            });
        }

        function setUpdateTerminalStatus(statusText) {
            const badge = document.getElementById('update-terminal-status-badge');
            if (!badge) return;
            badge.innerText = statusText;
            if (statusText === 'UPDATING' || statusText === 'RESTARTING API' || statusText === 'UPLOADING') {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-violet-950 text-violet-300 border border-violet-800 font-bold animate-pulse';
            } else if (statusText === 'COMPLETE' || statusText === 'HEALTHY') {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800 font-bold';
            } else if (statusText === 'ERROR') {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-400 border border-rose-800 font-bold';
            } else {
                badge.className = 'px-2 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-400';
            }
        }

        function appendTerminalLog(msg) {
            const pre = document.getElementById('update-terminal-pre');
            if (!pre) return;
            const ts = new Date().toLocaleTimeString();
            pre.innerText += `\n[${ts}] ${msg}`;
            pre.scrollTop = pre.scrollHeight;
        }

        async function fetchUpdateLog() {
            try {
                const res = await fetch(`${API_BASE}/system/update/log`);
                if (!res.ok) return;
                const data = await res.json();
                if (data.log) {
                    const pre = document.getElementById('update-terminal-pre');
                    pre.innerText = data.log;
                    pre.scrollTop = pre.scrollHeight;
                    const lines = data.log.split('\n').filter(l => l.trim().length > 0);
                    const lineCountEl = document.getElementById('update-terminal-line-count');
                    if (lineCountEl) lineCountEl.innerText = `${lines.length} lines`;

                    // Check progress clues in log
                    if (data.log.includes('Beginning dpkg') || data.log.includes('Unpacking')) {
                        setUpdateStep(3, 'active');
                    }
                    if (data.log.includes('Restarting zclock-api')) {
                        setUpdateStep(4, 'active');
                        setUpdateTerminalStatus('RESTARTING API');
                    }
                    if (data.log.includes('completed successfully!') || data.log.includes('SUCCESS: zclock-api')) {
                        setUpdateStep(5, 'success');
                        setUpdateTerminalStatus('COMPLETE');
                    }
                }
            } catch (err) {
                console.warn("Could not fetch log (service might be restarting):", err);
            }
        }

        function startUpdateWatchdog(targetVer) {
            if (updatePollInterval) clearInterval(updatePollInterval);
            let attempts = 0;
            const maxAttempts = 30; // 60 seconds total

            setUpdateTerminalStatus('UPDATING');
            setUpdateStep(3, 'active');

            updatePollInterval = setInterval(async () => {
                attempts++;
                fetchUpdateLog();

                try {
                    const res = await fetch(`${API_BASE}/system/status`, { cache: 'no-cache' });
                    if (res.ok) {
                        const sys = await res.json();
                        setUpdateStep(4, 'success');
                        setUpdateStep(5, 'success');
                        setUpdateTerminalStatus('COMPLETE');
                        clearInterval(updatePollInterval);
                        updatePollInterval = null;

                        appendTerminalLog(`\n🎉 UPDATE COMPLETE! ZclockID is now running version ${sys.version || targetVer || ''}`);
                        appendTerminalLog(`System health: ${sys.overall_health}. All Active Directory engines online.`);

                        // Refresh all version badges on page
                        if (sys.version) {
                            if (document.getElementById('header-version-badge')) document.getElementById('header-version-badge').innerText = `v${sys.version}`;
                            const inf = document.getElementById('info-current-version');
                            const upd = document.getElementById('update-current-ver-badge');
                            const dsh = document.getElementById('dash-version-badge');
                            const app = document.getElementById('appliance-version-label');
                            if (inf) inf.innerText = sys.version;
                            if (upd) upd.innerText = `v${sys.version}`;
                            if (dsh) dsh.innerText = `v${sys.version}`;
                            if (app) app.innerText = `ZclockID v${sys.version}`;
                        }

                        // Hide update badges
                        const navBadge = document.getElementById('nav-update-badge');
                        const dashBadge = document.getElementById('dash-update-available-badge');
                        const dashSummary = document.getElementById('dash-update-summary');
                        if (navBadge) navBadge.classList.add('hidden');
                        if (dashBadge) dashBadge.classList.add('hidden');
                        if (dashSummary) dashSummary.innerText = `System updated successfully to v${sys.version || targetVer}!`;

                        displayUpToDate({ current_version: sys.version || targetVer });
                    }
                } catch (e) {
                    // Service is restarting
                    setUpdateTerminalStatus('RESTARTING API');
                    setUpdateStep(4, 'active');
                    appendTerminalLog(`Reconnecting to ZclockID management API... (attempt ${attempts}/${maxAttempts})`);
                }

                if (attempts >= maxAttempts) {
                    clearInterval(updatePollInterval);
                    updatePollInterval = null;
                    setUpdateTerminalStatus('TIMEOUT');
                    appendTerminalLog(`Watchdog reached maximum wait time. Please refresh the page manually.`);
                }
            }, 2000);
        }

        function copyUpdateLog() {
            const pre = document.getElementById('update-terminal-pre');
            if (!pre) return;
            navigator.clipboard.writeText(pre.innerText).then(() => {
                alert('Update log copied to clipboard.');
            }).catch(() => {
                alert('Could not copy log automatically.');
            });
        }

