        // ==================== THEME CONTROLLER (DARK / SOFT LIGHT) ====================
        function setAppTheme(theme) {
            const isLight = theme === 'light';
            if (isLight) {
                document.documentElement.classList.add('light-theme');
                if (document.body) document.body.classList.add('light-theme');
                localStorage.setItem('zclock_theme', 'light');
            } else {
                document.documentElement.classList.remove('light-theme');
                if (document.body) document.body.classList.remove('light-theme');
                localStorage.setItem('zclock_theme', 'dark');
            }
            updateThemeButtons(theme);
        }

        function updateThemeButtons(theme) {
            const darkBtn = document.getElementById('theme-btn-dark');
            const lightBtn = document.getElementById('theme-btn-light');
            if (!darkBtn || !lightBtn) return;

            if (theme === 'light') {
                lightBtn.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold transition text-amber-300 bg-amber-500/20 border border-amber-500/40 shadow-sm';
                darkBtn.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition text-slate-400 hover:text-slate-200';
            } else {
                darkBtn.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-semibold transition text-indigo-400 bg-slate-800 border border-indigo-500/30 shadow-sm';
                lightBtn.className = 'flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition text-slate-400 hover:text-slate-200';
            }
        }

        // Initialize theme buttons immediately
        (function initTheme() {
            const currentTheme = localStorage.getItem('zclock_theme') || 'dark';
            setAppTheme(currentTheme);
        })();

        // ==================== AUTHENTICATION GUARD & CLIENT SECURITY ====================
        const initialAuthToken = localStorage.getItem('zclockid_token');
        if (!initialAuthToken) {
            fetch('/api/v1/setup/status')
                .then(r => r.json())
                .then(d => {
                    if (!d.is_configured || !d.has_admin) {
                        window.location.replace('/setup.html');
                    } else {
                        window.location.replace('/login.html');
                    }
                })
                .catch(() => {
                    window.location.replace('/login.html');
                });
        }

        // Global fetch interceptor to automatically catch 401 Unauthorized / expired sessions
        const originalFetch = window.fetch;
        window.fetch = async function(...args) {
            const response = await originalFetch.apply(this, args);
            if (response.status === 401) {
                const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
                if (!url.includes('/auth/login')) {
                    console.warn("Session token expired or invalid (HTTP 401). Redirecting to login.");
                    localStorage.removeItem('zclockid_token');
                    localStorage.removeItem('zclockid_user');
                    localStorage.removeItem('zclockid_role');
                    window.location.replace('/login.html?reason=expired');
                }
            }
            return response;
        };

        // Client-side Idle Inactivity Monitor
        let lastUserActivity = Date.now();
        ['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart', 'click'].forEach(evt => {
            window.addEventListener(evt, () => {
                lastUserActivity = Date.now();
                localStorage.setItem('zclockid_last_activity', lastUserActivity.toString());
            }, { passive: true });
        });

        // Evaluate idle duration every 10 seconds
        setInterval(() => {
            const idleMin = parseInt(localStorage.getItem('zclockid_idle_timeout_min') || '15', 10);
            if (idleMin > 0) {
                const storedLast = parseInt(localStorage.getItem('zclockid_last_activity') || lastUserActivity.toString(), 10);
                const elapsedMs = Date.now() - storedLast;
                if (elapsedMs >= idleMin * 60 * 1000) {
                    console.warn(`Idle timeout reached (${idleMin} min). Terminating browser session.`);
                    localStorage.removeItem('zclockid_token');
                    localStorage.removeItem('zclockid_user');
                    localStorage.removeItem('zclockid_role');
                    window.location.replace('/login.html?reason=timeout');
                }
            }
        }, 10000);

        const API_BASE = '/api/v1';
        let currentActiveLogService = '';
        let currentDnsRecords = [];

        // Collapsible Sidebar Security Group
        function toggleSecurityNavGroup(forceOpen = null) {
            const container = document.getElementById('nav-group-security-items');
            const chevron = document.getElementById('nav-group-security-chevron');
            if (!container) return;

            const shouldOpen = (forceOpen !== null) ? forceOpen : container.classList.contains('hidden');
            if (shouldOpen) {
                container.classList.remove('hidden');
                if (chevron) {
                    chevron.classList.remove('fa-chevron-right');
                    chevron.classList.add('fa-chevron-down');
                }
                localStorage.setItem('zclockid_security_nav_collapsed', 'false');
            } else {
                container.classList.add('hidden');
                if (chevron) {
                    chevron.classList.remove('fa-chevron-down');
                    chevron.classList.add('fa-chevron-right');
                }
                localStorage.setItem('zclockid_security_nav_collapsed', 'true');
            }
        }

        function initSecurityNavGroupState() {
            const saved = localStorage.getItem('zclockid_security_nav_collapsed');
            if (saved === 'true') {
                toggleSecurityNavGroup(false);
            } else {
                toggleSecurityNavGroup(true);
            }
        }

        // Tab Navigation
        const NAV_ACTIVE_CLASSES = ['text-indigo-300', 'bg-indigo-600/20', 'border-indigo-500/40', 'font-semibold', 'shadow-sm'];
        const NAV_INACTIVE_CLASSES = ['text-slate-400', 'border-transparent', 'hover:text-slate-200', 'hover:bg-slate-800/50', 'font-medium'];
        const NAV_ALL_MUTABLE_CLASSES = [
            'text-indigo-400', 'text-indigo-300', 'bg-indigo-600/10', 'bg-indigo-600/15', 'bg-indigo-600/20',
            'border-indigo-500/20', 'border-indigo-500/30', 'border-indigo-500/40', 'border-transparent',
            'text-slate-400', 'hover:text-slate-200', 'hover:bg-slate-800/50', 'font-semibold', 'font-medium',
            'shadow-sm'
        ];

        function showTab(tabId) {
            if (tabId === 'reports') {
                showTab('syslog');
                switchLogsSubTab('compliance');
                return;
            }
            const tabs = ['dashboard', 'domain', 'ntp', 'users', 'dns', 'radius', 'sysvol', 'azure', 'registrations', 'reports', 'backup', 'snmp', 'update', 'rbac', 'apikeys', 'certs', 'syslog', 'federation', 'license'];
            tabs.forEach(t => {
                const el = document.getElementById(`tab-${t}`);
                const nav = document.getElementById(`nav-${t}`);
                if (el) el.classList.add('hidden');
                if (nav) {
                    NAV_ALL_MUTABLE_CLASSES.forEach(c => nav.classList.remove(c));
                    NAV_INACTIVE_CLASSES.forEach(c => nav.classList.add(c));
                }
            });

            const activeEl = document.getElementById(`tab-${tabId}`);
            const activeNav = document.getElementById(`nav-${tabId}`);
            if (activeEl) activeEl.classList.remove('hidden');
            if (activeNav) {
                NAV_ALL_MUTABLE_CLASSES.forEach(c => activeNav.classList.remove(c));
                NAV_ACTIVE_CLASSES.forEach(c => activeNav.classList.add(c));
            }

            if (['rbac', 'apikeys', 'certs', 'syslog', 'backup', 'snmp', 'update', 'federation', 'license'].includes(tabId)) {
                toggleSecurityNavGroup(true);
            }

            // Lazy load tab data
            if (tabId === 'domain') { fetchDomainInfo(); fetchUpnSuffixes(); fetchFunctionalLevels(); fetchDrsStatus(); }
            else if (tabId === 'ntp') { fetchNtpStatus(); fetchNtpConfig(); }
            else if (tabId === 'users') { fetchRadiusBandwidth(); fetchUsers(); fetchGroups(); fetchComputers(); }
            else if (tabId === 'dns') { fetchDnsZones(); fetchDnsForwarders(); fetchDnsRecords(); runDnsDiagnostics(); }
            else if (tabId === 'radius') {
                switchRadiusMainTab(currentRadiusMainTab || 'general');
                fetchRadiusClients();
                fetchRadiusBandwidth();
                fetchRadiusEap();
                fetchRadiusSessions();
                fetchRadiusMab();
                fetchRadiusCustom();
                fetchRadiusSettings();
            }
            else if (tabId === 'sysvol') { fetchSysvolStatus(); fetchSysvolPartners(); }
            else if (tabId === 'azure') { fetchAzureStatus(); fetchAzureConfig(); }
            else if (tabId === 'registrations') { fetchRegistrations(); fetchRegistrationSettings(); }
            else if (tabId === 'reports') { fetchAuditEvents(); }
            else if (tabId === 'backup') { fetchBackups(); }
            else if (tabId === 'snmp') { fetchSnmpStatus(); fetchSnmpConfig(); }
            else if (tabId === 'update') { loadUpdateInfo(); }
            else if (tabId === 'rbac') { fetchRbacMappings(); fetchSecuritySettings(); fetchActiveSessions(); }
            else if (tabId === 'apikeys') { fetchApiKeys(); }
            else if (tabId === 'certs') { fetchActiveCert(); }
            else if (tabId === 'syslog') { switchLogsSubTab(currentLogsSubTab || 'live'); }
            else if (tabId === 'federation') { switchFedSubTab(currentFedSubTab || 'ldap'); fetchKeycloakSettings(); }
            else if (tabId === 'license') { fetchLicenseStatus(); }
        }

        function toggleSecretDisplay(idx, secret) {
            const el = document.getElementById(`secret-disp-${idx}`);
            if (el.innerText.includes('•')) {
                el.innerText = secret;
                el.className = 'text-amber-300 font-bold';
            } else {
                el.innerText = '••••••••••••••••';
                el.className = 'text-slate-400';
            }
        }

        function copyToClipboard(val, msg) {
            navigator.clipboard.writeText(val);
            alert(msg || 'Copied to clipboard!');
        }

        // ==================== ADMINISTRATOR PROFILE & PASSWORD ====================
        async function openProfileModal() {
            try {
                const res = await fetch(`${API_BASE}/auth/profile`, { headers: getAuthHeaders() });
                if (res.ok) {
                    const data = await res.json();
                    document.getElementById('profile-modal-subtitle').innerText = `Session: ${data.username} (${data.role})`;
                    document.getElementById('profile-identity-name').innerText = data.username;
                    const typeBadge = document.getElementById('profile-type-badge');
                    if (data.is_ad_user) {
                        typeBadge.className = 'px-2 py-0.5 text-[10px] font-mono rounded bg-sky-950 text-sky-400 border border-sky-800';
                        typeBadge.innerText = 'ACTIVE DIRECTORY';
                    } else {
                        typeBadge.className = 'px-2 py-0.5 text-[10px] font-mono rounded bg-emerald-950 text-emerald-400 border border-emerald-800';
                        typeBadge.innerText = 'LOCAL ADMIN';
                    }
                    const roleBadge = document.getElementById('profile-role-badge');
                    roleBadge.innerText = data.role;
                }
            } catch (e) {
                console.error('Profile fetch failed:', e);
            }
            // Clear password inputs
            document.getElementById('chg-current-pass').value = '';
            document.getElementById('chg-new-pass').value = '';
            document.getElementById('chg-confirm-pass').value = '';
            document.getElementById('modal-user-profile').classList.remove('hidden');
        }

        function closeProfileModal() {
            document.getElementById('modal-user-profile').classList.add('hidden');
        }

        async function handleChangePassword(e) {
            e.preventDefault();
            const curPass = document.getElementById('chg-current-pass').value;
            const newPass = document.getElementById('chg-new-pass').value;
            const confirmPass = document.getElementById('chg-confirm-pass').value;

            if (newPass !== confirmPass) {
                alert('New password and confirmation do not match.');
                return;
            }

            const btn = document.getElementById('chg-pass-btn');
            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Updating...';

            try {
                const res = await fetch(`${API_BASE}/auth/change-password`, {
                    method: 'POST',
                    headers: getAuthHeaders(),
                    body: JSON.stringify({ current_password: curPass, new_password: newPass })
                });
                const data = await res.json();
                if (!res.ok) throw new Error(data.detail || 'Password update failed');
                alert(data.message || 'Password changed successfully!');
                closeProfileModal();
            } catch (err) {
                alert(`Error: ${err.message}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> Update Password';
            }
        }

        // ==================== MVP 3: ACCESS CONTROL & RBAC ====================
        function getAuthHeaders() {
            const token = localStorage.getItem('zclockid_token');
            const h = { 'Content-Type': 'application/json' };
            if (token) h['Authorization'] = `Bearer ${token}`;
            return h;
        }

        async function initSessionInfo() {
            const token = localStorage.getItem('zclockid_token');
            if (!token) {
                window.location.replace('/login.html');
                return;
            }

            try {
                const res = await fetch(`${API_BASE}/auth/profile`, { headers: getAuthHeaders() });
                if (!res.ok) {
                    console.warn("Session verification failed. Redirecting to login.");
                    localStorage.removeItem('zclockid_token');
                    localStorage.removeItem('zclockid_user');
                    localStorage.removeItem('zclockid_role');
                    window.location.replace('/login.html?reason=expired');
                    return;
                }
                const prof = await res.json();
                localStorage.setItem('zclockid_user', prof.username);
                localStorage.setItem('zclockid_role', prof.role);

                const uEl = document.getElementById('header-user');
                const rEl = document.getElementById('header-role-badge');
                if (uEl) uEl.innerText = prof.username;
                if (rEl) {
                    rEl.innerText = prof.role;
                    if (prof.role === 'fulladmin') {
                        rEl.className = 'px-1.5 py-0.5 text-[10px] rounded bg-emerald-950/80 border border-emerald-800/60 text-emerald-400 font-mono';
                    } else if (prof.role === 'operator') {
                        rEl.className = 'px-1.5 py-0.5 text-[10px] rounded bg-indigo-950/80 border border-indigo-800/60 text-indigo-400 font-mono';
                    } else if (prof.role === 'report') {
                        rEl.className = 'px-1.5 py-0.5 text-[10px] rounded bg-cyan-950/80 border border-cyan-800/60 text-cyan-400 font-mono';
                    } else {
                        rEl.className = 'px-1.5 py-0.5 text-[10px] rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono';
                    }
                }
                const curRoleEl = document.getElementById('rbac-current-role');
                const curRoleDescEl = document.getElementById('rbac-current-role-desc');
                if (curRoleEl) curRoleEl.innerText = prof.role;
                if (curRoleDescEl) {
                    const descMap = {
                        'fulladmin': 'Full Appliance Administrator',
                        'operator': 'User & Identity Operator',
                        'report': 'Auditor & Compliance Inspector',
                        'readonly': 'Read-Only Inspector'
                    };
                    curRoleDescEl.innerText = descMap[prof.role] || prof.role;
                }
            } catch (err) {
                console.error("Auth profile fetch error:", err);
            }
        }

        function toggleRsatGuide() {
            const content = document.getElementById('rsat-guide-content');
            const chevron = document.getElementById('rsat-guide-chevron');
            const toggleText = document.getElementById('rsat-guide-toggle-text');
            if (!content) return;

            const isCollapsed = content.classList.contains('hidden');
            if (isCollapsed) {
                content.classList.remove('hidden');
                if (chevron) {
                    chevron.classList.remove('fa-chevron-down');
                    chevron.classList.add('fa-chevron-up');
                }
                if (toggleText) toggleText.innerText = 'Collapse Guide';
                localStorage.setItem('zclockid_rsat_collapsed', 'false');
            } else {
                content.classList.add('hidden');
                if (chevron) {
                    chevron.classList.remove('fa-chevron-up');
                    chevron.classList.add('fa-chevron-down');
                }
                if (toggleText) toggleText.innerText = 'Expand Guide';
                localStorage.setItem('zclockid_rsat_collapsed', 'true');
            }
        }

        function initRsatGuideState() {
            const saved = localStorage.getItem('zclockid_rsat_collapsed');
            if (saved === 'true') {
                const content = document.getElementById('rsat-guide-content');
                const chevron = document.getElementById('rsat-guide-chevron');
                const toggleText = document.getElementById('rsat-guide-toggle-text');
                if (content) content.classList.add('hidden');
                if (chevron) {
                    chevron.classList.remove('fa-chevron-up');
                    chevron.classList.add('fa-chevron-down');
                }
                if (toggleText) toggleText.innerText = 'Expand Guide';
            }
        }

        async function logout() {
            const token = localStorage.getItem('zclockid_token');
            try {
                if (token) {
                    await fetch(`${API_BASE}/auth/logout`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${token}` }
                    });
                }
            } catch(e) {}
            localStorage.removeItem('zclockid_token');
            localStorage.removeItem('zclockid_user');
            localStorage.removeItem('zclockid_role');
            window.location.href = '/login.html';
        }

