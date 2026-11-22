// Auto-redirect to setup wizard on first run when unconfigured / no admin exists
        fetch('/api/v1/setup/status')
            .then(r => r.json())
            .then(data => {
                if (!data.is_configured || !data.has_admin) {
                    window.location.replace('/setup.html');
                }
            })
            .catch(() => {});

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

        // Check if redirected from initial setup or session timeout
        if (window.location.search.includes('provisioned=1')) {
            document.getElementById('setup-success-alert').classList.remove('hidden');
        } else if (window.location.search.includes('reason=timeout')) {
            const al = document.getElementById('session-alert');
            const txt = document.getElementById('session-alert-text');
            if (al && txt) {
                txt.innerText = 'Session expired due to inactivity. Please sign in to resume.';
                al.classList.remove('hidden');
            }
        } else if (window.location.search.includes('reason=expired')) {
            const al = document.getElementById('session-alert');
            const txt = document.getElementById('session-alert-text');
            if (al && txt) {
                txt.innerText = 'Session expired or invalid. Please authenticate.';
                al.classList.remove('hidden');
            }
        }

        async function handleLogin(e) {
            e.preventDefault();
            const errBox = document.getElementById('error-box');
            const btn = document.getElementById('login-btn');
            errBox.classList.add('hidden');

            const payload = {
                username: document.getElementById('username').value.trim(),
                password: document.getElementById('password').value
            };

            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Authenticating...';

            try {
                const res = await fetch('/api/v1/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    localStorage.setItem('zclockid_token', data.access_token || data.token);
                    localStorage.setItem('zclockid_user', data.username);
                    localStorage.setItem('zclockid_role', data.role || 'fulladmin');
                    if (data.idle_timeout_min) {
                        localStorage.setItem('zclockid_idle_timeout_min', data.idle_timeout_min);
                    }
                    localStorage.setItem('zclockid_last_activity', Date.now().toString());
                    window.location.href = '/index.html';
                } else {
                    if (data.code === 'PASSWORD_EXPIRED') {
                        const safeUser = encodeURIComponent(payload.username);
                        errBox.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1"></i> Your password has expired. <a href="/password-reset.html#change?username=${escapeHtml(safeUser)}" class="underline font-bold text-amber-300 hover:text-amber-200 ml-1">Change password &rarr;</a>`;
                    } else if (data.code === 'ACCOUNT_EXPIRED') {
                        errBox.innerHTML = `<i class="fa-solid fa-clock mr-1"></i> ${escapeHtml(data.detail || 'Your account has expired. Please contact an administrator.')}`;
                    } else if (data.code === 'ACCOUNT_DISABLED') {
                        errBox.innerHTML = `<i class="fa-solid fa-user-slash mr-1"></i> ${escapeHtml(data.detail || 'Your account is disabled. Please contact an administrator.')}`;
                    } else if (data.code === 'ACCOUNT_LOCKED_OUT') {
                        errBox.innerHTML = `<i class="fa-solid fa-lock mr-1"></i> ${escapeHtml(data.detail || 'Your account is locked out. Please contact an administrator.')}`;
                    } else {
                        errBox.innerText = data.detail || 'Authentication failed. Please verify credentials.';
                    }
                    errBox.classList.remove('hidden');
                }
            } catch (err) {
                errBox.innerText = 'Network error: could not connect to appliance.';
                errBox.classList.remove('hidden');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-right-to-bracket"></i> Sign In to Appliance';
            }
        }

window.handleLogin = handleLogin;
