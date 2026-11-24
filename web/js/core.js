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

        // ==================== IN-GUI TOAST NOTIFICATIONS & DIALOGS ====================
        function getOrCreateToastContainer() {
            let container = document.getElementById('zclock-toast-container');
            if (!container) {
                container = document.createElement('div');
                container.id = 'zclock-toast-container';
                container.className = 'fixed bottom-5 right-5 z-[9999] flex flex-col gap-2.5 pointer-events-none max-w-sm w-full px-4';
                document.body.appendChild(container);
            }
            return container;
        }

        function showToast(message, type = 'info', duration = 4000) {
            const container = getOrCreateToastContainer();
            const toast = document.createElement('div');
            
            const typeStyles = {
                success: 'bg-slate-900/95 text-emerald-300 border-emerald-500/40 shadow-emerald-950/40',
                error: 'bg-slate-900/95 text-rose-300 border-rose-500/40 shadow-rose-950/40',
                warning: 'bg-slate-900/95 text-amber-300 border-amber-500/40 shadow-amber-950/40',
                info: 'bg-slate-900/95 text-cyan-300 border-cyan-500/40 shadow-cyan-950/40'
            };
            const iconStyles = {
                success: 'fa-solid fa-circle-check text-emerald-400',
                error: 'fa-solid fa-circle-exclamation text-rose-400',
                warning: 'fa-solid fa-triangle-exclamation text-amber-400',
                info: 'fa-solid fa-circle-info text-cyan-400'
            };
            
            const borderCls = typeStyles[type] || typeStyles.info;
            const iconCls = iconStyles[type] || iconStyles.info;

            toast.className = `pointer-events-auto transform transition-all duration-300 ease-out translate-y-2 opacity-0 flex items-start gap-3 p-3.5 rounded-xl border shadow-2xl backdrop-blur-md text-xs font-mono ${borderCls}`;
            toast.innerHTML = `
                <i class="${iconCls} text-sm mt-0.5 flex-shrink-0"></i>
                <div class="flex-1 text-slate-200 font-sans leading-snug break-words">${escapeHtml(message)}</div>
                <button class="toast-close-btn text-slate-400 hover:text-white transition flex-shrink-0 ml-1">
                    <i class="fa-solid fa-xmark text-xs"></i>
                </button>
            `;

            const closeBtn = toast.querySelector('.toast-close-btn');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => toast.remove());
            }

            container.appendChild(toast);
            requestAnimationFrame(() => {
                toast.classList.remove('translate-y-2', 'opacity-0');
            });

            if (duration > 0) {
                setTimeout(() => {
                    toast.classList.add('opacity-0', 'translate-y-2');
                    setTimeout(() => toast.remove(), 300);
                }, duration);
            }
        }
        window.showToast = showToast;

        function showConfirmDialog({ title = 'Confirm Action', message, confirmText = 'Confirm', confirmStyle = 'danger', confirmCb, cancelCb }) {
            let modal = document.getElementById('zclock-confirm-modal');
            if (!modal) {
                modal = document.createElement('div');
                modal.id = 'zclock-confirm-modal';
                document.body.appendChild(modal);
            }
            const isDanger = confirmStyle === 'danger';
            const confirmBtnClass = isDanger 
                ? 'bg-rose-600 hover:bg-rose-500 text-white border-rose-500/40' 
                : 'bg-indigo-600 hover:bg-indigo-500 text-white border-indigo-500/40';

            modal.className = 'fixed inset-0 bg-black/80 flex items-center justify-center p-4 z-[9998] backdrop-blur-sm';
            modal.innerHTML = `
                <div class="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
                    <div class="p-4 border-b border-slate-800 flex justify-between items-center bg-slate-950/60">
                        <div class="flex items-center gap-2.5">
                            <div class="h-8 w-8 rounded-lg ${isDanger ? 'bg-rose-600/20 border border-rose-500/30 text-rose-400' : 'bg-indigo-600/20 border border-indigo-500/30 text-indigo-400'} flex items-center justify-center text-sm">
                                <i class="fa-solid ${isDanger ? 'fa-triangle-exclamation' : 'fa-circle-question'}"></i>
                            </div>
                            <h3 class="text-sm font-bold text-white">${escapeHtml(title)}</h3>
                        </div>
                        <button id="zclock-confirm-close" class="text-slate-400 hover:text-white text-sm"><i class="fa-solid fa-xmark"></i></button>
                    </div>
                    <div class="p-5 text-xs text-slate-300 leading-relaxed space-y-3 font-sans">
                        <p class="whitespace-pre-wrap">${escapeHtml(message)}</p>
                    </div>
                    <div class="p-3.5 bg-slate-950 border-t border-slate-800 flex justify-end gap-2">
                        <button id="zclock-confirm-cancel" class="px-3.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-semibold transition">Cancel</button>
                        <button id="zclock-confirm-ok" class="px-4 py-1.5 ${confirmBtnClass} rounded-lg text-xs font-bold transition flex items-center gap-1.5 shadow-md border">
                            ${escapeHtml(confirmText)}
                        </button>
                    </div>
                </div>
            `;

            return new Promise((resolve) => {
                const cleanup = (result) => {
                    modal.classList.add('hidden');
                    resolve(result);
                    if (result && typeof confirmCb === 'function') confirmCb();
                    if (!result && typeof cancelCb === 'function') cancelCb();
                };
                const closeBtn = document.getElementById('zclock-confirm-close');
                const cancelBtn = document.getElementById('zclock-confirm-cancel');
                const okBtn = document.getElementById('zclock-confirm-ok');
                if (closeBtn) closeBtn.addEventListener('click', () => cleanup(false));
                if (cancelBtn) cancelBtn.addEventListener('click', () => cleanup(false));
                if (okBtn) okBtn.addEventListener('click', () => cleanup(true));
            });
        }
        window.showConfirmDialog = showConfirmDialog;

        // Non-intrusive in-GUI redirect for browser native window.alert
        window.alert = function(msg) {
            if (typeof msg === 'string') {
                const isError = /fail|error|invalid|unauthorized|denied/i.test(msg);
                const isSuccess = /success|successful|copied|saved|updated|created/i.test(msg);
                showToast(msg, isError ? 'error' : (isSuccess ? 'success' : 'info'));
            } else {
                showToast(String(msg), 'info');
            }
        };

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
                    if (!d.is_configured) {
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
            showToast(msg || 'Copied to clipboard!', 'info');
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

        function invokeAllowlistedAction(actionName, el, event, eventType) {
            const fn = window[actionName];
            if (typeof fn !== 'function') return;

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
        }

        function triggerAction(actionName, el, event, eventType) {
            if (!actionName) return;

            if (el && el.dataset.stopPropagation === 'true') {
                event.stopPropagation();
            }

            const handler = window.ActionRegistry[actionName];
            if (typeof handler === 'function') {
                handler(el, event, eventType);
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
                const pageHandlers = {
                    'goToUsersPage': (p) => typeof window.goToUsersPage === 'function' && window.goToUsersPage(p),
                    'goToGroupsPage': (p) => typeof window.goToGroupsPage === 'function' && window.goToGroupsPage(p),
                    'goToComputersPage': (p) => typeof window.goToComputersPage === 'function' && window.goToComputersPage(p),
                    'goToRegPage': (p) => typeof window.goToRegPage === 'function' && window.goToRegPage(p),
                    'goToSspprPage': (p) => typeof window.goToSspprPage === 'function' && window.goToSspprPage(p),
                };
                if (pageHandlers[fnName]) {
                    pageHandlers[fnName](page);
                } else {
                    console.warn(`[ActionRegistry] Unhandled page function: ${fnName}`);
                }
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
            },
            'control-service': (el) => typeof window.controlService === 'function' && window.controlService(el.dataset.service, el.dataset.op, el),
            'controlService': (el) => typeof window.controlService === 'function' && window.controlService(el.dataset.service, el.dataset.op, el),
            'open-service-modal': (el) => typeof window.openServiceControlModal === 'function' && window.openServiceControlModal(el.dataset.service),
            'openServiceControlModal': (el) => typeof window.openServiceControlModal === 'function' && window.openServiceControlModal(el.dataset.service),
            'open-log-viewer': (el) => typeof window.openLogViewer === 'function' && window.openLogViewer(el.dataset.service, el.dataset.title),
            'openLogViewer': (el) => typeof window.openLogViewer === 'function' && window.openLogViewer(el.dataset.service, el.dataset.title),
            'closeServiceControlModal': () => typeof window.closeServiceControlModal === 'function' && window.closeServiceControlModal(),
            'closeLogModal': () => typeof window.closeLogModal === 'function' && window.closeLogModal(),
            'openLogFromModal': () => typeof window.openLogFromModal === 'function' && window.openLogFromModal(),
            'refreshActiveLogs': () => typeof window.refreshActiveLogs === 'function' && window.refreshActiveLogs(),
            'executeModalServiceAction': (el) => typeof window.executeModalServiceAction === 'function' && window.executeModalServiceAction(el.dataset.actionName || el.dataset.op, el)
        });

        // Allowlisted web actions (strict allowlist registration, no arbitrary window function dispatch)
        const ALLOWLISTED_ACTIONS = [
            "acceptAndCloseLicenseModal",
            "addRegistrationDepartment",
            "applyFirewallChanges",
            "approveMassDelete",
            "backToDetailsStep",
            "checkComplexity",
            "checkForSystemUpdates",
            "checkOsPackages",
            "checkPasswordComplexity",
            "clearComputersSearch",
            "clearGroupsSearch",
            "clearSelectedLicenseFile",
            "clearUsersSearch",
            "closeAddDomainForwarderModal",
            "closeAddHostOverrideModal",
            "closeApiKeyCreateModal",
            "closeApiKeyTokenRevealModal",
            "closeBandwidthModal",
            "closeChangeUpnModal",
            "closeCreateBackupModal",
            "closeCsrModal",
            "closeCustomAttrModal",
            "closeDnsModal",
            "closeDohClientGuideModal",
            "closeEditDnsModal",
            "closeEditGroupModal",
            "closeEditUserModal",
            "closeExpiryPolicyModal",
            "closeFirewallRuleModal",
            "closeForwardersModal",
            "closeFunctionalLevelModal",
            "closeGroupModal",
            "closeIdentityModal",
            "closeInspectBackupModal",
            "closeLicenseModal",
            "closeLogModal",
            "closeMabModal",
            "closeMassDeleteReviewModal",
            "closeNewZoneModal",
            "closeProfileModal",
            "closeRadiusModal",
            "closeRbacMappingModal",
            "closeRegistrationSettingsModal",
            "closeRestoreModal",
            "closeServiceControlModal",
            "closeSspprSettingsModal",
            "closeSysvolPartnerModal",
            "closeSysvolRepinModal",
            "closeUploadBackupModal",
            "closeUpnModal",
            "closeUserModal",
            "confirmAndRebootAppliance",
            "confirmAndRemoveLicense",
            "confirmAndRunOsUpgrade",
            "confirmAndRunUpdate",
            "confirmRepinSysvolPartner",
            "copyBlueprintFile",
            "copyCsrText",
            "copyFedParam",
            "copyLiveLogs",
            "copyModalSecret",
            "copyPasswordResetLink",
            "copyRawConfigToClipboard",
            "copyRegistrationLink",
            "copyRevealedToken",
            "copyToClipboard",
            "copyUpdateLog",
            "debounceFilterLogs",
            "downloadActiveLicense",
            "downloadExamplePortalTemplate",
            "downloadKeytabFile",
            "executeDohTestQuery",
            "executeModalServiceAction",
            "executeRestore",
            "executeSnmpTestQuery",
            "exportAuditCsv",
            "exportRegistrationLogs",
            "exportSspprLogs",
            "fetchActiveCert",
            "fetchActiveSessions",
            "fetchApiKeys",
            "fetchAuditEvents",
            "fetchAuthStats24h",
            "fetchAzureConfig",
            "fetchBackups",
            "fetchComputers",
            "fetchCurrentUpdateLog",
            "fetchDnsRecords",
            "fetchDrsStatus",
            "fetchKeycloakSettings",
            "fetchLicenseStatus",
            "fetchLiveSyslog",
            "fetchNtpConfig",
            "fetchNtpStatus",
            "fetchRadiusSessions",
            "fetchRbacMappings",
            "fetchRegistrations",
            "fetchSecuritySettings",
            "fetchSspprLogs",
            "fetchSystemStatus",
            "fetchUsers",
            "filterAuditEvents",
            "filterDnsRecordsSearch",
            "filterFirewallRules",
            "filterOsPackagesTable",
            "flushDnsCache",
            "forceDrsSync",
            "generatePartnerSecret",
            "generateSecretForModal",
            "goToRegPage",
            "goToSspprPage",
            "goToStep",
            "handleChangePassword",
            "handleCreateApiKey",
            "handleDebFileSelected",
            "handleFirewallRuleSubmit",
            "handleGenerateCsr",
            "handleGenerateKeytab",
            "handleGenerateSelfSignedCert",
            "handleInitialSubmit",
            "handleLicenseFileSelect",
            "handleLogin",
            "handleOldPasswordSubmit",
            "handleOtpVerify",
            "handleRequestOtp",
            "handleResendOtp",
            "handleSaveLogRetention",
            "handleSaveRbacMapping",
            "handleSaveSyslogConfig",
            "handleSigFileSelected",
            "handleUploadCustomCert",
            "handleVerifyOtpSubmit",
            "insertCurrentClientIpIntoFirewall",
            "loadRawRadiusConfig",
            "logout",
            "nextComputersPage",
            "nextGroupsPage",
            "nextUsersPage",
            "onComputersPageSizeChange",
            "onComputersSearchInput",
            "onDnsTypeChange",
            "onGroupsPageSizeChange",
            "onGroupsSearchInput",
            "onIdentDcTypeRadioChange",
            "onOverrideTypeChange",
            "onRbacPrincipalSelectChange",
            "onRbacPrincipalTypeChange",
            "onRegMonthChange",
            "onRegPageSizeChange",
            "onRegSearchInput",
            "onSspprMonthChange",
            "onSspprPageSizeChange",
            "onSspprSearchInput",
            "onSspprStatusChange",
            "onUsersPageSizeChange",
            "onUsersSearchInput",
            "open-log-viewer",
            "open-service-modal",
            "openAddBandwidthModal",
            "openAddDomainForwarderModal",
            "openAddHostOverrideModal",
            "openApiKeyCreateModal",
            "openCreateBackupModal",
            "openCustomAttrModal",
            "openDnsModal",
            "openDohClientGuideModal",
            "openExpiryPolicyModal",
            "openFirewallRuleModal",
            "openForwardersModal",
            "openFunctionalLevelModal",
            "openGroupModal",
            "openIdentityModal",
            "openLicenseModal",
            "openLogFromModal",
            "openLogViewer",
            "openMabModal",
            "openMassDeleteReviewModal",
            "openNewZoneModal",
            "openProfileModal",
            "openRadiusModal",
            "openRbacMappingModal",
            "openRegistrationSettingsModal",
            "openServiceControlModal",
            "openSspprSettingsModal",
            "openSysvolPartnerModal",
            "openUploadBackupModal",
            "openUpnModal",
            "openUserModal",
            "prevComputersPage",
            "prevGroupsPage",
            "prevUsersPage",
            "probeSysvolTls",
            "refreshActiveLogs",
            "refreshActiveLogsView",
            "rejectMassDelete",
            "renderGroupsTable",
            "renderUsersTable",
            "renewRadiusCert",
            "resetCustomPortalHtml",
            "resetDefaultRegistrationDepartments",
            "resetFirewallTemplate",
            "resetOtpFlow",
            "resetSysvolNtacl",
            "runDnsDiagnostics",
            "runLdapProbeTest",
            "runLogRetentionPruneNow",
            "saveAzureConfig",
            "saveForwarders",
            "saveNtpConfig",
            "saveRadiusSettings",
            "saveRegistrationSettings",
            "saveSecuritySettings",
            "saveSnmpConfig",
            "saveSspprSettings",
            "saveSystemIdentity",
            "saveUpdateAutoCheck",
            "sendSyslogTestProbe",
            "sendTestSms",
            "setAppTheme",
            "setLogCategory",
            "setRegStatusFilter",
            "setSspprMethodFilter",
            "showMySysvolSecret",
            "showTab",
            "sortComputersBy",
            "sortGroupsBy",
            "sortUsersBy",
            "startProvisioning",
            "submitAddDnsRecord",
            "submitAddDomainForwarder",
            "submitAddHostOverride",
            "submitAddRadiusClient",
            "submitAddSysvolPartner",
            "submitAddUpn",
            "submitApplyExpiryPolicy",
            "submitChangeUpn",
            "submitCreateBackup",
            "submitCreateGroup",
            "submitCreateUser",
            "submitCreateZone",
            "submitDebUpload",
            "submitEditGroup",
            "submitEditUser",
            "submitLicenseUpload",
            "submitRaiseFunctionalLevels",
            "submitSaveBandwidthProfile",
            "submitSaveCustomAttr",
            "submitSaveMabDevice",
            "submitUpdateDnsRecord",
            "submitUploadBackup",
            "switchDirectorySubtab",
            "switchFedSubTab",
            "switchLogsSubTab",
            "switchMethodTab",
            "switchRadiusMainTab",
            "switchRadiusSubTab",
            "switchRbacSubTab",
            "switchSelfServiceSubtab",
            "switchUpdateLogType",
            "switchUpdateSubTab",
            "terminateAllOtherSessions",
            "testAzureConnection",
            "toggleAzureSecretVisibility",
            "toggleBackupPassphraseWarning",
            "toggleCustomPortal",
            "toggleCustomPrincipalInput",
            "toggleDohTester",
            "toggleFirewallMaster",
            "toggleLicenseAcceptance",
            "togglePasswordVisibility",
            "toggleRsatGuide",
            "toggleSecurityNavGroup",
            "toggleSmsProviderFields",
            "toggleSmtpFields",
            "toggleSspprSmsFields",
            "toggleSspprSmtpFields",
            "triggerAzureSync",
            "triggerNtpSyncNow",
            "triggerSysvolSyncNow",
            "uploadCustomPortalHtml",
            "uploadPortalAsset"
];
        for (const act of ALLOWLISTED_ACTIONS) {
            if (!window.ActionRegistry[act]) {
                window.ActionRegistry[act] = (el, ev, et) => invokeAllowlistedAction(act, el, ev, et);
            }
        }

        // 1. Click Listener (Delegated)
        document.addEventListener('click', function(e) {
            const btn = e.target.closest('[data-action]');
            if (!btn) return;
            if (btn.tagName === 'A' && (btn.getAttribute('href') === '#' || !btn.getAttribute('href'))) {
                e.preventDefault();
            }
            const action = btn.dataset.action;
            if (action === 'copy-doh-curl') {
                const el = document.getElementById('doh-guide-curl-cmd');
                const cmd = el?.textContent?.trim() || '';
                if (typeof window.copyToClipboard === 'function') {
                    window.copyToClipboard(cmd, 'cURL command copied!');
                }
            } else if (action === 'control-service') {
                if (typeof window.controlService === 'function') {
                    window.controlService(btn.dataset.service, btn.dataset.op, btn);
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

