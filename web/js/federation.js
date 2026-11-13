        // ==================== IDENTITY FEDERATION & KEYCLOAK SSO ====================
        let currentFedSubTab = 'ldap';
        let cachedKeycloakConfig = null;
        let cachedKeycloakBlueprint = null;

        function switchFedSubTab(subtab) {
            currentFedSubTab = subtab;
            const subtabs = ['ldap', 'kerberos', 'blueprint', 'guide'];
            subtabs.forEach(s => {
                const view = document.getElementById(`fed-view-${s}`);
                const btn = document.getElementById(`fed-subtab-btn-${s}`);
                if (view) view.classList.add('hidden');
                if (btn) {
                    btn.classList.remove('bg-purple-600', 'text-white', 'shadow-sm');
                    btn.classList.add('bg-slate-800', 'text-slate-300');
                }
            });

            const activeView = document.getElementById(`fed-view-${subtab}`);
            const activeBtn = document.getElementById(`fed-subtab-btn-${subtab}`);
            if (activeView) activeView.classList.remove('hidden');
            if (activeBtn) {
                activeBtn.classList.remove('bg-slate-800', 'text-slate-300');
                activeBtn.classList.add('bg-purple-600', 'text-white', 'shadow-sm');
            }

            if (subtab === 'blueprint' && !cachedKeycloakBlueprint) {
                fetchKeycloakBlueprint();
            }
        }

        async function fetchKeycloakSettings() {
            try {
                const res = await fetch(`${API_BASE}/federation/keycloak/settings`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to load federation settings');
                const data = await res.json();
                cachedKeycloakConfig = data;

                // Populate badges & fields
                const badgeRealm = document.getElementById('fed-badge-realm');
                if (badgeRealm) badgeRealm.innerText = data.realm;
                const badgeIp = document.getElementById('fed-badge-ip');
                if (badgeIp) badgeIp.innerText = data.dc_ip;

                const ldapUrl = document.getElementById('fed-param-ldap-url');
                if (ldapUrl) ldapUrl.innerText = data.ldap_url;
                const ldapsUrl = document.getElementById('fed-param-ldaps-url');
                if (ldapsUrl) ldapsUrl.innerText = data.ldaps_url;

                const usersDn = document.getElementById('fed-param-users-dn');
                if (usersDn) usersDn.innerText = data.users_dn;
                const bindDn = document.getElementById('fed-param-bind-dn');
                if (bindDn) bindDn.innerText = `CN=Administrator,${data.users_dn}`;

                const filterEl = document.getElementById('fed-param-filter');
                if (filterEl) filterEl.innerText = data.search_filter;

                // Kerberos tab fields
                const krbRealm = document.getElementById('fed-krb-realm-disp');
                if (krbRealm) krbRealm.innerText = data.kerberos_realm;
                const krbSpn = document.getElementById('fed-krb-spn-disp');
                if (krbSpn) krbSpn.innerText = data.server_principal;

                const spnInput = document.getElementById('fed-keytab-spn');
                if (spnInput && !spnInput.value) {
                    spnInput.value = data.server_principal.split('@')[0];
                }

                // Keytab status badge & download button
                const statusBadge = document.getElementById('fed-keytab-status-badge');
                const dlBtn = document.getElementById('btn-download-keytab');
                if (data.keytab_exists) {
                    if (statusBadge) {
                        statusBadge.className = 'px-2.5 py-1 text-[10px] font-bold rounded font-mono bg-emerald-950/80 text-emerald-400 border border-emerald-800/60';
                        statusBadge.innerText = `ACTIVE (${data.keytab_size_bytes} B)`;
                    }
                    if (dlBtn) dlBtn.disabled = false;
                } else {
                    if (statusBadge) {
                        statusBadge.className = 'px-2.5 py-1 text-[10px] font-bold rounded font-mono bg-amber-950/80 text-amber-400 border border-amber-800/60';
                        statusBadge.innerText = 'NOT GENERATED YET';
                    }
                    if (dlBtn) dlBtn.disabled = true;
                }
            } catch (err) {
                console.error('Error fetching Keycloak settings:', err);
            }
        }

        async function runLdapProbeTest() {
            const btn = document.getElementById('btn-ldap-probe');
            const resultDiv = document.getElementById('fed-probe-result');
            if (btn) btn.disabled = true;

            try {
                const res = await fetch(`${API_BASE}/federation/keycloak/test-ldap`, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({ port: 389, use_ssl: false })
                });
                const data = await res.json();
                if (resultDiv) {
                    resultDiv.classList.remove('hidden', 'bg-rose-950/40', 'border-rose-800/40', 'text-rose-300', 'bg-emerald-950/40', 'border-emerald-800/40', 'text-emerald-300');
                    if (res.ok) {
                        resultDiv.classList.add('bg-emerald-950/40', 'border-emerald-800/40', 'text-emerald-300');
                        resultDiv.innerHTML = `<i class="fa-solid fa-check-circle mr-1"></i> ${escapeHtml(data.message)}`;
                    } else {
                        resultDiv.classList.add('bg-rose-950/40', 'border-rose-800/40', 'text-rose-300');
                        resultDiv.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1"></i> Error: ${escapeHtml(data.detail || 'Probe failed')}`;
                    }
                }
            } catch (err) {
                if (resultDiv) {
                    resultDiv.classList.remove('hidden');
                    resultDiv.className = 'p-3 rounded-lg border text-xs font-mono bg-rose-950/40 border-rose-800/40 text-rose-300';
                    resultDiv.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1"></i> Probe Error: ${escapeHtml(err.message)}`;
                }
            } finally {
                if (btn) btn.disabled = false;
            }
        }

        async function handleGenerateKeytab(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-generate-keytab');
            const account = document.getElementById('fed-keytab-account').value.trim();
            const spn = document.getElementById('fed-keytab-spn').value.trim();

            if (!spn) {
                alert('Please enter a valid Service Principal Name (e.g. HTTP/sso.yourdomain.com)');
                return;
            }

            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-1"></i> Generating...';
            }

            try {
                const res = await fetch(`${API_BASE}/federation/keycloak/generate-keytab`, {
                    method: 'POST',
                    headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
                    body: JSON.stringify({ service_account: account, spn: spn })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Failed to generate keytab');
                alert(data.message || 'Keytab generated successfully!');
                fetchKeycloakSettings();
            } catch (err) {
                alert(`Keytab Generation Error: ${err.message}`);
            } finally {
                if (btn) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Generate Keytab';
                }
            }
        }

        function downloadKeytabFile() {
            window.location.href = `${API_BASE}/federation/keycloak/export-keytab`;
        }

        async function fetchKeycloakBlueprint() {
            try {
                const res = await fetch(`${API_BASE}/federation/keycloak/blueprint`, { headers: getAuthHeaders() });
                if (!res.ok) throw new Error('Failed to load blueprint');
                const data = await res.json();
                cachedKeycloakBlueprint = data;

                const composeEl = document.getElementById('blueprint-compose-code');
                if (composeEl) composeEl.innerText = data.compose_yaml;
                const envEl = document.getElementById('blueprint-env-code');
                if (envEl) envEl.innerText = data.env_file;
            } catch (err) {
                console.error('Error loading Keycloak blueprint:', err);
            }
        }

        function copyBlueprintFile(type) {
            if (!cachedKeycloakBlueprint) return;
            const text = type === 'compose' ? cachedKeycloakBlueprint.compose_yaml : cachedKeycloakBlueprint.env_file;
            navigator.clipboard.writeText(text).then(() => {
                alert(`${type === 'compose' ? 'docker-compose.yml' : '.env'} copied to clipboard!`);
            });
        }

        function copyFedParam(elementId) {
            const el = document.getElementById(elementId);
            if (!el) return;
            navigator.clipboard.writeText(el.innerText).then(() => {
                alert(`Copied "${el.innerText}" to clipboard!`);
            });
        }

