        // 6. Sysvol Guardian & Integrated Replication
        async function fetchSysvolStatus() {
            try {
                const res = await fetch(`${API_BASE}/sysvol/status`);
                const data = await res.json();
                const d = new Date(data.last_reset * 1000);
                document.getElementById('sysvol-last-reset').innerText = d.toLocaleTimeString();
                document.getElementById('sysvol-partners-count').innerText = `${data.partners_count || 0} Registered Peers`;
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
                        return `
                            <tr class="hover:bg-slate-800/30">
                                <td class="px-4 py-2.5 font-bold text-white flex items-center gap-2">
                                    <i class="fa-solid fa-server text-indigo-400"></i> ${p.name}
                                </td>
                                <td class="px-4 py-2.5 text-cyan-300 font-semibold">${p.ip_address}</td>
                                <td class="px-4 py-2.5">
                                    <span class="px-2 py-0.5 rounded text-[10px] ${p.status === 'IN_SYNC' ? 'bg-emerald-950 text-emerald-400 border border-emerald-800' : 'bg-amber-950 text-amber-400 border border-amber-800'}">${p.status}</span>
                                </td>
                                <td class="px-4 py-2.5 text-slate-400">${d}</td>
                                <td class="px-4 py-2.5 text-slate-300 font-bold">${p.files_count} items</td>
                                <td class="px-4 py-2.5 text-right space-x-2">
                                    <button onclick="triggerSysvolSyncNow()" class="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] transition" title="Sync Peer">
                                        <i class="fa-solid fa-rotate mr-1"></i> Sync
                                    </button>
                                    <button onclick="deleteSysvolPartner('${p.ip_address}')" class="text-slate-500 hover:text-rose-400 transition" title="Remove Peer">
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
                tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-4 text-center text-rose-400">Failed to load partners: ${err}</td></tr>`;
            }
        }

        function openSysvolPartnerModal() {
            document.getElementById('sysvol-partner-modal').classList.remove('hidden');
            generatePartnerSecret();
        }
        function closeSysvolPartnerModal() {
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

        async function submitAddSysvolPartner() {
            const name = document.getElementById('sysvol-p-name-input').value.trim();
            const ip = document.getElementById('sysvol-p-ip-input').value.trim();
            const secret = document.getElementById('sysvol-p-secret-input').value.trim();

            if (!name || !ip || !secret) return alert('Name, IP, and Secret are required.');

            try {
                const res = await fetch(`${API_BASE}/sysvol/partners`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ name: name, ip_address: ip, shared_secret: secret })
                });
                const data = await res.json();
                if (res.ok) {
                    closeSysvolPartnerModal();
                    alert(data.message);
                    fetchSysvolStatus();
                    fetchSysvolPartners();
                } else {
                    alert(`Failed to add partner DC: ${data.detail}`);
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

