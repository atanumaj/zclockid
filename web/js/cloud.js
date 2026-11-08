        // ==================== AZURE CLOUD SYNC JS ====================
        let currentAzureConfig = {};

        async function fetchAzureStatus() {
            try {
                const res = await fetch(`${API_BASE}/azure/status`);
                const data = await res.json();
                
                const statusText = document.getElementById('azure-status-text');
                const statusDot = document.getElementById('azure-status-dot');
                const lastSyncEl = document.getElementById('azure-last-sync-time');
                const localCountEl = document.getElementById('azure-local-count');
                const syncedCountEl = document.getElementById('azure-synced-count');
                const banner = document.getElementById('azure-status-banner');
                const bannerMsg = document.getElementById('azure-status-banner-msg');
                const bannerIcon = document.getElementById('azure-status-banner-icon');

                const status = (data.status || 'NOT CONFIGURED').toUpperCase();
                statusText.innerText = status;

                // Color code status dot and text
                if (status === 'HEALTHY' || status === 'SYNCED') {
                    statusText.className = 'text-emerald-400 font-bold text-xs';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-emerald-400';
                } else if (status === 'DISABLED') {
                    statusText.className = 'text-slate-400 font-bold text-xs';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-slate-500';
                } else if (status === 'AUTH_ERROR' || status === 'ERROR') {
                    statusText.className = 'text-rose-400 font-bold text-xs';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse';
                } else {
                    statusText.className = 'text-amber-400 font-bold text-xs';
                    statusDot.className = 'w-2.5 h-2.5 rounded-full bg-amber-400 animate-pulse';
                }

                if (data.last_sync) {
                    const d = new Date(data.last_sync * 1000);
                    lastSyncEl.innerText = d.toLocaleString();
                } else {
                    lastSyncEl.innerText = 'Never';
                }

                localCountEl.innerText = `${data.local_users_count || 0} Accounts`;
                syncedCountEl.innerText = `${data.synced_users_count || 0} Accounts`;

                if (data.message) {
                    banner.classList.remove('hidden');
                    bannerMsg.innerText = data.message;
                    if (status === 'HEALTHY') {
                        banner.className = 'p-3 rounded-lg border border-emerald-800/60 bg-emerald-950/30 text-emerald-300 text-xs flex items-start gap-2.5';
                        bannerIcon.className = 'fa-solid fa-circle-check text-emerald-400 mt-0.5';
                    } else if (status === 'AUTH_ERROR' || status === 'ERROR') {
                        banner.className = 'p-3 rounded-lg border border-rose-800/60 bg-rose-950/30 text-rose-300 text-xs flex items-start gap-2.5';
                        bannerIcon.className = 'fa-solid fa-circle-xmark text-rose-400 mt-0.5';
                    } else {
                        banner.className = 'p-3 rounded-lg border border-slate-800 bg-slate-950/60 text-slate-300 text-xs flex items-start gap-2.5';
                        bannerIcon.className = 'fa-solid fa-circle-info text-sky-400 mt-0.5';
                    }
                } else {
                    banner.classList.add('hidden');
                }
            } catch (err) {
                console.error('Error fetching azure status:', err);
            }
        }

        async function fetchAzureConfig() {
            try {
                const res = await fetch(`${API_BASE}/azure/config`);
                if (!res.ok) throw new Error('Failed to load azure config');
                const cfg = await res.json();
                currentAzureConfig = cfg;

                document.getElementById('azure-cfg-enabled').checked = Boolean(cfg.enabled);
                document.getElementById('azure-cfg-tenant-id').value = (cfg.tenant_id && cfg.tenant_id !== 'YOUR_AZURE_TENANT_ID_GUID') ? cfg.tenant_id : '';
                document.getElementById('azure-cfg-client-id').value = (cfg.client_id && cfg.client_id !== 'YOUR_AZURE_APP_CLIENT_ID_GUID') ? cfg.client_id : '';
                
                const secretInput = document.getElementById('azure-cfg-client-secret');
                const secretHint = document.getElementById('azure-cfg-secret-hint');
                secretInput.value = '';
                if (cfg.has_secret || (cfg.client_secret && cfg.client_secret.includes('*'))) {
                    secretInput.placeholder = '•••••••••••••••• (Saved. Leave blank to keep current secret)';
                    secretHint.innerText = 'Existing secret is saved securely. Enter new value only to update.';
                } else {
                    secretInput.placeholder = 'Paste client secret value from Azure portal';
                    secretHint.innerText = 'Client secret generated under Certificates & secrets in Azure Portal';
                }

                document.getElementById('azure-cfg-domain').value = cfg.default_domain || (currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : '');
                document.getElementById('azure-cfg-ou').value = cfg.source_ou || '';
                if (cfg.sync_interval_seconds) {
                    document.getElementById('azure-cfg-interval').value = String(cfg.sync_interval_seconds);
                }
                document.getElementById('azure-cfg-exclude-disabled').checked = cfg.exclude_disabled !== false;
                document.getElementById('azure-cfg-auto-create').checked = cfg.auto_create_users !== false;
                document.getElementById('azure-cfg-password-hash').checked = Boolean(cfg.password_hash_sync);
            } catch (err) {
                console.error('Error fetching azure config:', err);
            }
        }

        function toggleAzureSecretVisibility() {
            const input = document.getElementById('azure-cfg-client-secret');
            const icon = document.getElementById('azure-secret-eye-icon');
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fa-regular fa-eye-slash text-xs';
            } else {
                input.type = 'password';
                icon.className = 'fa-regular fa-eye text-xs';
            }
        }

        async function saveAzureConfig(e) {
            if (e) e.preventDefault();
            const btn = document.getElementById('btn-save-azure-cfg');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Saving...';

            const payload = {
                enabled: document.getElementById('azure-cfg-enabled').checked,
                tenant_id: document.getElementById('azure-cfg-tenant-id').value.trim(),
                client_id: document.getElementById('azure-cfg-client-id').value.trim(),
                client_secret: document.getElementById('azure-cfg-client-secret').value.trim() || '********',
                default_domain: document.getElementById('azure-cfg-domain').value.trim() || (currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : ''),
                source_ou: document.getElementById('azure-cfg-ou').value.trim(),
                sync_interval_seconds: parseInt(document.getElementById('azure-cfg-interval').value, 10) || 900,
                exclude_disabled: document.getElementById('azure-cfg-exclude-disabled').checked,
                auto_create_users: document.getElementById('azure-cfg-auto-create').checked,
                password_hash_sync: document.getElementById('azure-cfg-password-hash').checked
            };

            try {
                const res = await fetch(`${API_BASE}/azure/config`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to update configuration');

                alert('Microsoft Entra ID synchronization settings saved successfully.');
                await fetchAzureConfig();
                await fetchAzureStatus();
            } catch (err) {
                alert(`Error saving Azure configuration: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

        async function testAzureConnection() {
            const btn = document.getElementById('btn-azure-test');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Testing...';

            const payload = {
                tenant_id: document.getElementById('azure-cfg-tenant-id').value.trim(),
                client_id: document.getElementById('azure-cfg-client-id').value.trim(),
                client_secret: document.getElementById('azure-cfg-client-secret').value.trim() || undefined
            };

            try {
                const res = await fetch(`${API_BASE}/azure/test-connection`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.success) {
                    alert(`Connection Successful!\n\n${data.message}\nToken Type: ${data.token_type}\nExpires In: ${data.expires_in}s`);
                } else {
                    alert(`Connection Failed:\n\n${data.error || data.detail || 'Could not verify credentials'}`);
                }
            } catch (err) {
                alert(`Error testing Azure connection: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

        async function triggerAzureSync() {
            const btn = document.getElementById('btn-azure-sync');
            const origText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Syncing...';

            try {
                const res = await fetch(`${API_BASE}/azure/sync`, { method: 'POST' });
                const data = await res.json();
                if (data.status === 'success') {
                    alert(`Azure Synchronization Triggered!\n\n${data.output || 'Sync completed successfully.'}`);
                } else {
                    alert(`Azure Synchronization Failed (Exit ${data.exit_code}):\n\n${data.error || data.output}`);
                }
                await fetchAzureStatus();
            } catch (err) {
                alert(`Error triggering Azure sync: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = origText;
            }
        }

