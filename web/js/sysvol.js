        // 6. Sysvol Guardian & Integrated Replication
        let sysvolPendingAddPartner = null;
        let currentRepinPartnerIp = null;

        async function fetchSysvolStatus() {
            try {
                const res = await fetch(`${API_BASE}/sysvol/status`);
                const data = await res.json();
                const d = new Date(data.last_reset * 1000);
                const lastResetEl = document.getElementById('sysvol-last-reset');
                if (lastResetEl) lastResetEl.innerText = d.toLocaleTimeString();
                const countEl = document.getElementById('sysvol-partners-count');
                if (countEl) countEl.innerText = `${data.partners_count || 0} Registered Peers`;
                const fpEl = document.getElementById('sysvol-local-fingerprint');
                if (fpEl) fpEl.innerText = data.local_cert_fingerprint || 'Not Available';

                const bannerEl = document.getElementById('sysvol-mass-delete-banner');
                if (bannerEl) {
                    if (data.mass_delete_tripped) {
                        bannerEl.classList.remove('hidden');
                    } else {
                        bannerEl.classList.add('hidden');
                    }
                }
            } catch (err) {
                console.error('Error fetching sysvol status:', err);
            }
        }

        async function fetchSysvolPartners() {
            const tbody = document.getElementById('sysvol-partners-table-body');
            try {
                const res = await fetch(`${API_BASE}/sysvol/partners`);
                const data = await res.json();
                if (data.partners && data.partners.length > 0) {
                    tbody.innerHTML = data.partners.map(p => {
                        const d = p.last_sync ? new Date(p.last_sync * 1000).toLocaleTimeString() : 'Never';
                        const safeName = escapeHtml(p.name);
                        const safeIp = escapeHtml(p.ip_address);
                        const safeStatus = escapeHtml(p.status);
                        const safeD = escapeHtml(d);
                        const safeFilesCount = escapeHtml(p.files_count);
                        const isError = p.status === 'ERROR';
                        const statusBadgeClass = p.status === 'IN_SYNC' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : (isError ? 'bg-rose-950 text-rose-400 border border-rose-800' : 'bg-amber-950 text-amber-400 border border-amber-800');
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-server text-indigo-400"></i> ${safeName}
                                </td>
                                <td class="px-4 py-2.5 text-cyan-300 font-semibold">
                                    <div>${safeIp}</div>
                                    ${p.cert_fingerprint ? `<div class="text-[9px] text-slate-400 font-mono tracking-tight mt-0.5" title="${escapeHtml(p.cert_fingerprint)}"><i class="fa-solid fa-lock text-emerald-400 text-[8px] mr-1"></i>${escapeHtml(p.cert_fingerprint.substring(0, 23))}...</div>` : '<div class="text-[9px] text-rose-400 font-mono"><i class="fa-solid fa-triangle-exclamation mr-1"></i>Unpinned</div>'}
                                </td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-[10px] ${statusBadgeClass}">${safeStatus}</span>
                                    ${p.error ? `<div class="text-[9px] text-rose-400 mt-1 max-w-xs truncate" title="${escapeHtml(p.error)}">${escapeHtml(p.error)}</div>` : ''}
                                </td>
                                <td class="px-4 py-2.5 text-slate-400">${safeD}</td>
                                <td class="px-4 py-2.5 text-slate-300 font-bold">${safeFilesCount} items</td>
                                <td class="px-4 py-2.5 text-right space-x-1.5 whitespace-nowrap">
                                    <button data-action="triggerSysvolSyncNow" class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition" title="Sync Peer">
                                        <i class="fa-solid fa-rotate mr-1"></i> Sync
                                    </button>
                                    <button data-action="repin-sysvol-partner" data-ip="${safeIp}" class="px-2 py-1 bg-amber-950/80 hover:bg-amber-900 border border-amber-800/80 text-amber-300 rounded text-[11px] transition" title="Re-pin TLS Certificate">
                                        <i class="fa-solid fa-shield-halved mr-1"></i> Re-pin
                                    </button>
                                    <button data-action="delete-sysvol-partner" data-ip="${safeIp}" class="text-slate-500 hover:text-rose-400 transition px-1" title="Remove Peer">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </td>
                            </tr>
                        `;
                    }).join('');
                } else {
                    tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center font-sans text-slate-500">No partner DCs configured. Standalone primary DC.</td></tr>`;
                }
            } catch (err) {
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center text-rose-400">Failed to load partners: ${escapeHtml(String(err))}</td></tr>`;
            }
        }

        function openSysvolPartnerModal() {
            sysvolPendingAddPartner = null;
            const confirmBox = document.getElementById('sysvol-p-confirm-box');
            if (confirmBox) confirmBox.classList.add('hidden');
            const submitBtn = document.getElementById('sysvol-p-submit-btn');
            if (submitBtn) submitBtn.innerText = 'Pair & Start Replication';
            document.getElementById('sysvol-partner-modal').classList.remove('hidden');
            generatePartnerSecret();
        }
        function closeSysvolPartnerModal() {
            sysvolPendingAddPartner = null;
            document.getElementById('sysvol-partner-modal').classList.add('hidden');
        }

        async function generatePartnerSecret() {
            try {
                const res = await fetch(`${API_BASE}/radius/secret/generate`, { method: 'POST' });
                const data = await res.json();
                document.getElementById('sysvol-p-secret-input').value = data.secret;
            } catch (err) {}
        }

        async function showMySysvolSecret() {
            try {
                const res = await fetch(`${API_BASE}/sysvol/local-secret`);
                const data = await res.json();
                document.getElementById('sysvol-p-secret-input').value = data.secret;
                alert(`Appliance Local Pairing Key loaded:\n${data.secret}\n\nUse this secret on your secondary Domain Controller to pair.`);
            } catch (err) {
                alert(`Error loading secret: ${err}`);
            }
        }

        async function probeSysvolTls() {
            const ip = document.getElementById('sysvol-p-ip-input').value.trim();
            if (!ip) return alert('Please enter Partner DC IP Address first.');
            try {
                const res = await fetch(`${API_BASE}/sysvol/probe-tls?ip=${encodeURIComponent(ip)}`);
                const data = await res.json();
                if (res.ok) {
                    document.getElementById('sysvol-p-fingerprint-input').value = data.fingerprint;
                    const cnSpan = document.getElementById('sysvol-cert-cn');
                    if (cnSpan) cnSpan.innerText = `CN: ${data.subject_cn || 'Verified'}`;
                } else {
                    alert(`TLS Probe failed: ${data.detail || 'Could not verify peer TLS'}`);
                }
            } catch (err) {
                alert(`Error probing TLS: ${err}`);
            }
        }

        async function submitAddSysvolPartner() {
            const name = document.getElementById('sysvol-p-name-input').value.trim();
            const ip = document.getElementById('sysvol-p-ip-input').value.trim();
            const secret = document.getElementById('sysvol-p-secret-input').value.trim();
            let fingerprint = document.getElementById('sysvol-p-fingerprint-input').value.trim();

            if (!name || !ip || !secret) return alert('Name, IP, and Secret are required.');

            const confirmFlag = Boolean(sysvolPendingAddPartner && sysvolPendingAddPartner.ip_address === ip);
            if (confirmFlag && !fingerprint && sysvolPendingAddPartner && sysvolPendingAddPartner.cert_fingerprint) {
                fingerprint = sysvolPendingAddPartner.cert_fingerprint;
            }

            const payload = {
                name: name,
                ip_address: ip,
                shared_secret: secret,
                cert_fingerprint: fingerprint || null,
                confirm: confirmFlag
            };

            try {
                const res = await fetch(`${API_BASE}/sysvol/partners`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (res.ok) {
                    if (data.status === 'confirm_required') {
                        sysvolPendingAddPartner = data.partner;
                        const confirmBox = document.getElementById('sysvol-p-confirm-box');
                        const probedFpEl = document.getElementById('sysvol-p-probed-fp');
                        const localFpEl = document.getElementById('sysvol-p-local-fp');
                        const submitBtn = document.getElementById('sysvol-p-submit-btn');
                        if (probedFpEl) probedFpEl.innerText = data.peer_fingerprint || 'None';
                        if (localFpEl) localFpEl.innerText = data.local_fingerprint || 'None';
                        if (data.peer_fingerprint) {
                            document.getElementById('sysvol-p-fingerprint-input').value = data.peer_fingerprint;
                        }
                        if (confirmBox) confirmBox.classList.remove('hidden');
                        if (submitBtn) submitBtn.innerText = 'Confirm & Pair Partner';
                        return;
                    }

                    closeSysvolPartnerModal();
                    alert(data.message || 'Partner DC paired successfully');
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    alert(`Failed to add partner DC (${res.status}): ${data.detail || 'Request failed'}`);
                }
            } catch (err) {
                alert(`Error pairing partner: ${err}`);
            }
        }

        async function deleteSysvolPartner(ip) {
            if (!confirm(`Remove partner Domain Controller ${ip} from Sysvol replication?`)) return;
            try {
                const res = await fetch(`${API_BASE}/sysvol/partners/${ip}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    const data = await res.json();
                    alert(`Failed to delete: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error removing partner: ${err}`);
            }
        }

        async function triggerSysvolSyncNow() {
            try {
                const res = await fetch(`${API_BASE}/sysvol/sync-now`, { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                fetchSysvolPartners();
            } catch (err) {
                alert(`Sync error: ${err}`);
            }
        }

        async function resetSysvolNtacl() {
            if (!confirm('Force samba-tool ntacl sysvolreset across all GPO directories?')) return;
            try {
                const res = await fetch(`${API_BASE}/sysvol/reset-ntacl`, { method: 'POST' });
                const data = await res.json();
                alert(data.message);
                fetchSysvolStatus();
            } catch (err) {
                alert(`Error resetting sysvol: ${err}`);
            }
        }

        let currentPendingDetectedAt = null;

        function closeMassDeleteReviewModal() {
            const modal = document.getElementById('sysvol-mass-delete-modal');
            if (modal) modal.classList.add('hidden');
        }

        async function openMassDeleteReviewModal() {
            try {
                const res = await fetch(`${API_BASE}/sysvol/mass-delete/pending`);
                const data = await res.json();
                if (!res.ok || !data.has_pending) {
                    alert('No pending mass deletions found to review.');
                    fetchSysvolStatus();
                    return;
                }
                const p = data.pending;
                currentPendingDetectedAt = p.detected_at;

                const partnerEl = document.getElementById('mass-del-partner-ip');
                const timeEl = document.getElementById('mass-del-detected-at');
                const countEl = document.getElementById('mass-del-count');
                const listEl = document.getElementById('mass-del-paths-list');

                if (partnerEl) partnerEl.innerText = p.partner_ip || 'All Peers';
                if (timeEl) timeEl.innerText = new Date(p.detected_at * 1000).toLocaleString();
                if (countEl) countEl.innerText = p.count || p.paths.length;
                if (listEl) {
                    listEl.innerHTML = p.paths.map(path => `
                        <div class="flex items-center gap-2 py-0.5 border-b border-slate-900/60 last:border-0">
                            <i class="fa-solid fa-file-excel text-rose-400 text-[10px]"></i>
                            <span class="text-slate-200 select-all">${path}</span>
                        </div>
                    `).join('');
                }

                const modal = document.getElementById('sysvol-mass-delete-modal');
                if (modal) modal.classList.remove('hidden');
            } catch (err) {
                alert(`Error loading pending deletions: ${err}`);
            }
        }

        async function approveMassDelete() {
            if (currentPendingDetectedAt === null) {
                alert('No pending mass delete selection active.');
                return;
            }
            if (!confirm('WARNING: Are you sure you want to approve deletion of the listed files across Sysvol? This requires fulladmin privileges.')) return;
            try {
                const res = await fetch(`${API_BASE}/sysvol/mass-delete/confirm`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ detected_at: currentPendingDetectedAt })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Mass deletion approved. Files will be deleted on next sync cycle.');
                    closeMassDeleteReviewModal();
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    alert(`Approval failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error approving mass deletions: ${err}`);
            }
        }

        async function rejectMassDelete() {
            if (!confirm('Reject pending mass deletions? Local files will be restored, tombstones cleared, and safety brake released.')) return;
            try {
                const res = await fetch(`${API_BASE}/sysvol/mass-delete/reject`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'}
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Mass deletion rejected. Local files preserved.');
                    closeMassDeleteReviewModal();
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    alert(`Rejection failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error rejecting mass deletions: ${err}`);
            }
        }

        async function confirmMassDelete() {
            await openMassDeleteReviewModal();
        }

        function closeSysvolRepinModal() {
            currentRepinPartnerIp = null;
            const modal = document.getElementById('sysvol-repin-modal');
            if (modal) modal.classList.add('hidden');
        }

        async function startRepinSysvolPartner(ip) {
            currentRepinPartnerIp = ip;
            const modal = document.getElementById('sysvol-repin-modal');
            const ipDisplay = document.getElementById('repin-partner-ip-display');
            const currentFpEl = document.getElementById('repin-current-fp');
            const newFpEl = document.getElementById('repin-new-fp');

            if (ipDisplay) ipDisplay.innerText = ip;
            if (currentFpEl) currentFpEl.innerText = 'Loading...';
            if (newFpEl) newFpEl.innerText = 'Probing peer certificate...';
            if (modal) modal.classList.remove('hidden');

            try {
                const res = await fetch(`${API_BASE}/sysvol/partners/${ip}/repin`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ confirm: false })
                });
                const data = await res.json();
                if (res.ok) {
                    if (currentFpEl) currentFpEl.innerText = data.current_fingerprint || 'None';
                    if (newFpEl) newFpEl.innerText = data.new_fingerprint || 'None';
                } else {
                    alert(`Failed to probe certificate: ${data.detail}`);
                    closeSysvolRepinModal();
                }
            } catch (err) {
                alert(`Error preparing re-pin: ${err}`);
                closeSysvolRepinModal();
            }
        }

        async function confirmRepinSysvolPartner() {
            if (!currentRepinPartnerIp) return;
            try {
                const res = await fetch(`${API_BASE}/sysvol/partners/${currentRepinPartnerIp}/repin`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ confirm: true })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(data.message || 'Partner TLS certificate re-pinned successfully.');
                    closeSysvolRepinModal();
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    alert(`Re-pin failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error completing re-pin: ${err}`);
            }
        }

        window.startRepinSysvolPartner = startRepinSysvolPartner;
        window.confirmRepinSysvolPartner = confirmRepinSysvolPartner;
        window.closeSysvolRepinModal = closeSysvolRepinModal;
        window.confirmMassDelete = confirmMassDelete;
        window.openMassDeleteReviewModal = openMassDeleteReviewModal;
        window.closeMassDeleteReviewModal = closeMassDeleteReviewModal;
        window.approveMassDelete = approveMassDelete;
        window.rejectMassDelete = rejectMassDelete;

