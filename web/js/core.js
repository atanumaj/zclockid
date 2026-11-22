        // ==================== HTML ESCAPING FOR XSS DEFENSE ====================
        function escapeHtml(s) {
            if (s === null || s === undefined) return '';
            return String(s)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#39;')
                .replace(/`/g, '&#96;');
        }
        window.escapeHtml = escapeHtml;

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
        const isPublicPage = window.location.pathname.endsWith('/login.html') ||
                             window.location.pathname.endsWith('/register.html') ||
                             window.location.pathname.endsWith('/password-reset.html') ||
                             window.location.pathname.endsWith('/setup.html');

        const initialAuthToken = localStorage.getItem('zclockid_token');
        if (!isPublicPage && !initialAuthToken) {
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

        // Global fetch interceptor to automatically attach Auth Bearer & catch 401 Unauthorized
        const originalFetch = window.fetch;
        window.fetch = async function(resource, init) {
            let options = init ? { ...init } : {};
            const token = localStorage.getItem('zclockid_token');
            const urlStr = typeof resource === 'string' ? resource : (resource?.url || '');

            const isLocal = !urlStr.startsWith('http://') && !urlStr.startsWith('https://') || 
                            (typeof window !== 'undefined' && window.location && urlStr.startsWith(window.location.origin)) ||
                            urlStr.startsWith('/api/');

            if (token && isLocal) {
                if (resource instanceof Request) {
                    try {
                        if (!resource.headers.has('Authorization')) {
                            resource.headers.set('Authorization', `Bearer ${token}`);
                        }
                    } catch (e) {}
                } else if (options.headers instanceof Headers) {
                    if (!options.headers.has('Authorization')) {
                        options.headers.set('Authorization', `Bearer ${token}`);
                    }
                } else if (Array.isArray(options.headers)) {
                    const hasAuth = options.headers.some(([k]) => k.toLowerCase() === 'authorization');
                    if (!hasAuth) {
                        options.headers.push(['Authorization', `Bearer ${token}`]);
                    }
                } else {
                    options.headers = options.headers ? { ...options.headers } : {};
                    const hasAuth = Object.keys(options.headers).some(k => k.toLowerCase() === 'authorization');
                    if (!hasAuth) {
                        options.headers['Authorization'] = `Bearer ${token}`;
                    }
                }
            }

            const response = await originalFetch.call(this, resource, options);
            if (!isPublicPage && response.status === 401) {
                if (!urlStr.includes('/auth/login') && !urlStr.includes('/setup/status') && !urlStr.includes('/self-service/password/config') && !urlStr.includes('/public/register/')) {
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
            if (isPublicPage) return;
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

        // ==================== ASYNC VIEW & MODAL LOADERS ====================
        const loadedTabs = new Set();
        const loadingTabs = new Map();
        let modalsLoaded = false;
        let modalsLoading = null;

        async function ensureTabLoaded(tabId) {
            if (loadedTabs.has(tabId)) return;
            if (loadingTabs.has(tabId)) return loadingTabs.get(tabId);

            const promise = (async () => {
                const container = document.getElementById(`tab-${tabId}`);
                if (!container) return;
                try {
                    const resp = await fetch(`views/tabs/${tabId}.html`);
                    if (!resp.ok) {
                        console.error(`Failed to load view for tab "${tabId}": HTTP ${resp.status}`);
                        return;
                    }
                    const html = await resp.text();
                    container.innerHTML = html;
                    loadedTabs.add(tabId);
                } catch (err) {
                    console.error(`Network error loading tab "${tabId}":`, err);
                } finally {
                    loadingTabs.delete(tabId);
                }
            })();

            loadingTabs.set(tabId, promise);
            return promise;
        }

        async function loadModals() {
            if (modalsLoaded) return;
            if (modalsLoading) return modalsLoading;

            modalsLoading = (async () => {
                const container = document.getElementById('modals-container');
                if (!container) return;
                try {
                    const resp = await fetch('views/modals.html');
                    if (resp.ok) {
                        container.innerHTML = await resp.text();
                        modalsLoaded = true;
                    } else {
                        console.error(`Failed to load modals view: HTTP ${resp.status}`);
                    }
                } catch (err) {
                    console.error('Network error loading modals view:', err);
                } finally {
                    modalsLoading = null;
                }
            })();

            return modalsLoading;
        }

        async function preloadAllTabs() {
            const tabsToPreload = [
                'domain', 'ntp', 'users', 'dns', 'radius', 'sysvol',
                'azure', 'registrations', 'backup', 'snmp', 'update',
                'rbac', 'apikeys', 'certs', 'syslog', 'federation', 'license'
            ];
            for (const tab of tabsToPreload) {
                if (!loadedTabs.has(tab)) {
                    await ensureTabLoaded(tab);
                }
            }
        }

        async function showTab(tabId) {
            if (tabId === 'reports') {
                await showTab('syslog');
                switchLogsSubTab('compliance');
                return;
            }
            await ensureTabLoaded(tabId);
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
            else if (tabId === 'registrations') {
                if (typeof activeSelfServiceSubtab !== 'undefined' && activeSelfServiceSubtab === 'password') {
                    fetchSspprLogs();
                } else {
                    fetchRegistrations();
                    fetchRegistrationSettings();
                }
            }
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

        // ==================== UNIVERSAL PAGINATION HELPER ====================
        function renderPaginationButtons(containerId, currentPage, totalPages, goToPageFnName) {
            const container = document.getElementById(containerId);
            if (!container) return;
            if (totalPages <= 1) {
                container.innerHTML = '';
                return;
            }

            let pages = [];
            if (totalPages <= 7) {
                for (let i = 1; i <= totalPages; i++) pages.push(i);
            } else {
                pages.push(1);
                let start = Math.max(2, currentPage - 1);
                let end = Math.min(totalPages - 1, currentPage + 1);

                if (currentPage <= 3) {
                    start = 2;
                    end = 4;
                } else if (currentPage >= totalPages - 2) {
                    start = totalPages - 3;
                    end = totalPages - 1;
                }

                if (start > 2) pages.push('...');
                for (let i = start; i <= end; i++) pages.push(i);
                if (end < totalPages - 1) pages.push('...');
                pages.push(totalPages);
            }

            container.innerHTML = pages.map(p => {
                if (p === '...') {
                    return `<span class="px-2 py-1 text-slate-500 font-mono text-xs select-none">...</span>`;
                }
                const isActive = (p === currentPage);
                if (isActive) {
                    return `<button type="button" class="px-2.5 py-1 rounded-md bg-indigo-600 text-white font-bold text-xs shadow-sm shadow-indigo-600/40 select-none">${escapeHtml(p)}</button>`;
                } else {
                    return `<button type="button" data-action="go-to-page" data-page="${escapeHtml(p)}" data-page-fn="${escapeHtml(goToPageFnName)}" class="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition">${escapeHtml(p)}</button>`;
                }
            }).join('');
        }

        // ==================== GLOBAL EVENT DELEGATION SYSTEM (CSP STRICT) ====================
        window.ActionRegistry = window.ActionRegistry || {};

        function triggerAction(actionName, el, event, eventType) {
            if (!actionName) return;

            if (el && el.dataset.stopPropagation === 'true') {
                event.stopPropagation();
            }

            // 1. Check registry
            if (window.ActionRegistry[actionName]) {
                window.ActionRegistry[actionName](el, event, eventType);
                return;
            }

            // 2. Direct / camelCase on window
            const camel = actionName.replace(/-([a-z0-9])/g, (_, c) => c.toUpperCase());
            const fn = window[actionName] || window[camel];
            if (typeof fn === 'function') {
                if (eventType === 'submit') {
                    fn(event);
                } else if (el && el.dataset.tab) {
                    fn(el.dataset.tab);
                    if (el.dataset.subtab && typeof window.switchLogsSubTab === 'function') {
                        window.switchLogsSubTab(el.dataset.subtab);
                    }
                } else if (el && el.dataset.step) {
                    fn(parseInt(el.dataset.step, 10));
                } else if (el && el.dataset.theme) {
                    fn(el.dataset.theme);
                } else if (el && el.dataset.method) {
                    fn(el.dataset.method);
                } else if (el && el.dataset.subtab) {
                    fn(el.dataset.subtab);
                } else if (el && el.dataset.mainTab) {
                    fn(el.dataset.mainTab);
                } else if (el && el.dataset.logType) {
                    fn(el.dataset.logType);
                } else if (el && el.dataset.status) {
                    fn(el.dataset.status);
                } else if (el && el.dataset.col) {
                    fn(el.dataset.col);
                } else if (el && el.dataset.type && (actionName.includes('Portal') || actionName.includes('Template') || actionName.includes('Security') || actionName.includes('Sms'))) {
                    fn(el.dataset.type);
                } else if (el && el.dataset.fieldId && el.dataset.iconId) {
                    fn(el.dataset.fieldId, el.dataset.iconId);
                } else if (el && el.dataset.service && el.dataset.op) {
                    fn(el.dataset.service, el.dataset.op);
                } else if (el && el.dataset.service && el.dataset.title) {
                    fn(el.dataset.service, el.dataset.title);
                } else if (el && el.dataset.service) {
                    fn(el.dataset.service);
                } else if (el && el.dataset.actionName) {
                    fn(el.dataset.actionName);
                } else if (el && el.dataset.param) {
                    fn(el.dataset.param);
                } else if (el && el.dataset.fileType) {
                    fn(el.dataset.fileType);
                } else if (el && el.dataset.text && el.dataset.msg) {
                    fn(el.dataset.text, el.dataset.msg);
                } else if (el && el.dataset.p1 && el.dataset.p2 && el.dataset.rules) {
                    fn(el.dataset.p1, el.dataset.p2, el.dataset.rules);
                } else if (el && el.dataset.cfg) {
                    fn(el.dataset.cfg);
                } else if (el && el.dataset.cat) {
                    fn(el.dataset.cat);
                } else if (el && el.dataset.direction) {
                    const delta = el.dataset.direction === 'prev' ? -1 : 1;
                    if (actionName.includes('Reg') && typeof window.regCurrentPage === 'number') {
                        fn(window.regCurrentPage + delta);
                    } else if (typeof window.ssprCurrentPage === 'number') {
                        fn(window.ssprCurrentPage + delta);
                    } else {
                        fn(el.dataset.direction);
                    }
                } else if (eventType === 'change' && (el.type === 'checkbox' || el.type === 'radio')) {
                    fn(el.checked);
                } else {
                    fn(el, event);
                }
                return;
            }

            console.warn(`[ActionRegistry] Unhandled action: ${actionName}`);
        }

        // Built-in Action Handlers
        Object.assign(window.ActionRegistry, {
            'trigger-file-click': (el) => {
                const target = document.getElementById(el.dataset.target);
                if (target) target.click();
            },
            'sync-input-value': (el) => {
                const target = document.getElementById(el.dataset.target);
                if (target) target.value = el.value;
            },
            'stop-propagation': (el, e) => {
                e.stopPropagation();
            },
            'setQueryOid': (el) => {
                if (window.setQueryOid) window.setQueryOid(el.dataset.oid);
                if (el.dataset.runTest === 'true') {
                    const btn = document.getElementById('btn-run-snmp-test');
                    if (btn) btn.click();
                }
            },
            'refreshSnmp': () => {
                if (window.fetchSnmpStatus) window.fetchSnmpStatus();
                if (window.fetchSnmpConfig) window.fetchSnmpConfig();
            },
            'refreshHardening': () => {
                if (window.fetchSecuritySettings) window.fetchSecuritySettings();
                if (window.fetchFirewallStatus) window.fetchFirewallStatus();
            },
            'go-to-page': (el) => {
                const fnName = el.dataset.pageFn;
                const page = parseInt(el.dataset.page, 10);
                if (typeof window[fnName] === 'function') window[fnName](page);
            },
            'download-backup': (el) => typeof window.downloadBackup === 'function' && window.downloadBackup(el.dataset.filename),
            'inspect-backup': (el) => typeof window.inspectBackup === 'function' && window.inspectBackup(el.dataset.filename),
            'confirm-restore-backup': (el) => typeof window.confirmRestoreBackup === 'function' && window.confirmRestoreBackup(el.dataset.filename),
            'delete-backup': (el) => typeof window.deleteBackup === 'function' && window.deleteBackup(el.dataset.filename),
            'remove-reg-dept': (el) => typeof window.removeRegistrationDepartment === 'function' && window.removeRegistrationDepartment(el.dataset.dept),
            'approve-registration': (el) => typeof window.approveRegistration === 'function' && window.approveRegistration(parseInt(el.dataset.id, 10), el.dataset.username),
            'reject-registration': (el) => typeof window.rejectRegistration === 'function' && window.rejectRegistration(parseInt(el.dataset.id, 10), el.dataset.username),
            'change-reg-upn': (el) => typeof window.openChangeUpnModal === 'function' && window.openChangeUpnModal(el.dataset.username),
            'delete-registration': (el) => typeof window.deleteRegistration === 'function' && window.deleteRegistration(parseInt(el.dataset.id, 10), el.dataset.username),
            'toggle-radius-secret': (el) => typeof window.toggleSecretDisplay === 'function' && window.toggleSecretDisplay(parseInt(el.dataset.idx, 10), el.dataset.secret),
            'copy-radius-secret': (el) => typeof window.copyToClipboard === 'function' && window.copyToClipboard(el.dataset.secret),
            'delete-radius-client': (el) => typeof window.deleteRadiusClient === 'function' && window.deleteRadiusClient(el.dataset.name),
            'disconnect-radius-session': (el) => typeof window.disconnectSession === 'function' && window.disconnectSession(el.dataset.sessionId),
            'edit-bandwidth-profile': (el) => typeof window.openEditBandwidthModal === 'function' && window.openEditBandwidthModal(parseInt(el.dataset.id, 10)),
            'delete-bandwidth-profile': (el) => typeof window.deleteBandwidthProfile === 'function' && window.deleteBandwidthProfile(parseInt(el.dataset.id, 10), el.dataset.name),
            'delete-mab-device': (el) => typeof window.deleteMabDevice === 'function' && window.deleteMabDevice(parseInt(el.dataset.id, 10)),
            'delete-custom-attr': (el) => typeof window.deleteCustomAttr === 'function' && window.deleteCustomAttr(parseInt(el.dataset.id, 10)),
            'delete-rbac-mapping': (el) => typeof window.deleteRbacMapping === 'function' && window.deleteRbacMapping(parseInt(el.dataset.id, 10), el.dataset.principal),
            'terminate-session': (el) => typeof window.terminateSession === 'function' && window.terminateSession(el.dataset.token),
            'toggle-fw-rule': (el) => typeof window.toggleFwRuleState === 'function' && window.toggleFwRuleState(parseInt(el.dataset.id, 10), el.dataset.enable === 'true'),
            'edit-fw-rule': (el) => typeof window.editFirewallRule === 'function' && window.editFirewallRule(parseInt(el.dataset.id, 10)),
            'delete-fw-rule': (el) => typeof window.deleteFirewallRule === 'function' && window.deleteFirewallRule(parseInt(el.dataset.id, 10)),
            'revoke-api-key': (el) => typeof window.revokeApiKey === 'function' && window.revokeApiKey(parseInt(el.dataset.id, 10), el.dataset.name),
            'copy-portal-asset': (el) => typeof window.copyPortalAssetUrl === 'function' && window.copyPortalAssetUrl(el.dataset.url),
            'delete-portal-asset': (el) => typeof window.deletePortalAsset === 'function' && window.deletePortalAsset(el.dataset.name, el.dataset.type),
            'delete-sysvol-partner': (el) => typeof window.deleteSysvolPartner === 'function' && window.deleteSysvolPartner(el.dataset.ip),
            'repin-sysvol-partner': (el) => typeof window.startRepinSysvolPartner === 'function' && window.startRepinSysvolPartner(el.dataset.ip),
            'edit-user': (el) => typeof window.openEditUserModal === 'function' && window.openEditUserModal(el.dataset.username),
            'delete-user': (el) => typeof window.deleteUser === 'function' && window.deleteUser(el.dataset.username),
            'edit-group': (el) => typeof window.openEditGroupModal === 'function' && window.openEditGroupModal(el.dataset.group),
            'delete-group': (el) => typeof window.deleteGroup === 'function' && window.deleteGroup(el.dataset.group),
            'delete-computer': (el) => typeof window.deleteComputer === 'function' && window.deleteComputer(el.dataset.computer),
            'delete-forwarder': (el) => typeof window.deleteDomainForwarder === 'function' && window.deleteDomainForwarder(el.dataset.domain),
            'delete-override': (el) => typeof window.deleteHostOverride === 'function' && window.deleteHostOverride(el.dataset.fqdn, el.dataset.type),
            'edit-dns-record': (el) => typeof window.openEditDnsModal === 'function' && window.openEditDnsModal(el.dataset.zone, el.dataset.name, el.dataset.type, el.dataset.data, parseInt(el.dataset.ttl, 10)),
            'delete-dns-record': (el) => typeof window.deleteDnsRecord === 'function' && window.deleteDnsRecord(el.dataset.zone, el.dataset.name, el.dataset.type, el.dataset.data),
            'delete-upn-suffix': (el) => typeof window.deleteUpnSuffix === 'function' && window.deleteUpnSuffix(el.dataset.suffix),
            'copy-doh-ip': () => {
                const url = `https://${window.location.hostname}/dns-query`;
                if (typeof window.copyToClipboard === 'function') window.copyToClipboard(url, 'IP DoH URL copied!');
            },
            'copy-doh-fqdn': () => {
                const el = document.getElementById('doh-display-fqdn') || document.getElementById('doh-guide-fqdn-url');
                const url = el?.textContent?.trim() || `https://${window.location.hostname}/dns-query`;
                if (typeof window.copyToClipboard === 'function') window.copyToClipboard(url, 'FQDN DoH URL copied!');
            },
            'copy-doh-curl': () => {
                const el = document.getElementById('doh-guide-curl-cmd');
                const cmd = el?.textContent?.trim() || '';
                if (typeof window.copyToClipboard === 'function') window.copyToClipboard(cmd, 'cURL command copied!');
            }
        });

        // 1. Click Listener (Delegated)
        document.addEventListener('click', function(e) {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            if (btn.tagName === 'A' && (btn.getAttribute('href') === '#' || !btn.getAttribute('href'))) {
                e.preventDefault();
            }
            const action = btn.dataset.action;
            if (action === 'control-service') {
                if (typeof window.controlService === 'function') {
                    window.controlService(btn.dataset.service, btn.dataset.op);
                }
            } else if (action === 'copy-doh-curl') {
                const el = document.getElementById('doh-guide-curl-cmd');
                const cmd = el?.textContent?.trim() || '';
                if (typeof window.copyToClipboard === 'function') {
                    window.copyToClipboard(cmd, 'cURL command copied!');
                }
            } else {
                triggerAction(action, btn, e, 'click');
            }
        });

        // 2. Change Listener (Delegated)
        document.addEventListener('change', function(e) {
            const target = e.target.closest('[data-on-change]');
            if (target) {
                triggerAction(target.dataset.onChange, target, e, 'change');
            }
        });

        // 3. Input Listener (Delegated)
        document.addEventListener('input', function(e) {
            const target = e.target.closest('[data-on-input]');
            if (target) {
                triggerAction(target.dataset.onInput, target, e, 'input');
            }
        });

        // 4. Submit Listener (Delegated)
        document.addEventListener('submit', function(e) {
            const target = e.target.closest('form[data-on-submit]') || e.target.closest('[data-on-submit]');
            if (target) {
                e.preventDefault();
                triggerAction(target.dataset.onSubmit, target, e, 'submit');
            }
        });

        // 5. Keydown Listener (Delegated)
        document.addEventListener('keydown', function(e) {
            const target = e.target.closest('[data-on-keydown]');
            if (target) {
                const requiredKey = target.dataset.key || 'Enter';
                if (e.key === requiredKey) {
                    e.preventDefault();
                    triggerAction(target.dataset.onKeydown, target, e, 'keydown');
                }
            }
        });

