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

        let currentRegId = null;
        let resendTimer = null;
        let resendSeconds = 60;
        let publicConfig = {};

        // Load registration configuration on page load
        document.addEventListener('DOMContentLoaded', async () => {
            try {
                const res = await fetch('/api/v1/public/register/config');
                const data = await res.json();
                if (res.ok) {
                    publicConfig = data;
                    const domainVal = data.default_domain || data.primary_realm || window.location.hostname;
                    document.getElementById('reg-primary-domain').textContent = domainVal;
                    
                    // Dynamically populate department dropdown configured by administrator
                    const deptSelect = document.getElementById('department');
                    if (deptSelect && data.departments && Array.isArray(data.departments) && data.departments.length > 0) {
                        deptSelect.innerHTML = data.departments.map(d => `<option value="${escapeHtml(d)}">${escapeHtml(d)}</option>`).join('');
                    }

                    if (!data.enabled) {
                        showStatus('error', 'User self-registration is currently disabled by administrator policy.');
                        document.getElementById('submit-btn').disabled = true;
                    }
                }
            } catch (err) {
                document.getElementById('reg-primary-domain').textContent = window.location.hostname;
            }
        });

        function togglePasswordVisibility(fieldId, iconId) {
            const input = document.getElementById(fieldId);
            const icon = document.getElementById(iconId);
            if (!input || !icon) return;
            if (input.type === 'password') {
                input.type = 'text';
                icon.className = 'fa-solid fa-eye-slash text-indigo-400';
            } else {
                input.type = 'password';
                icon.className = 'fa-solid fa-eye text-slate-400';
            }
        }

        function checkPasswordComplexity() {
            const p1 = document.getElementById('password').value;
            const p2 = document.getElementById('confirm_password').value;
            const u = (document.getElementById('username').value || '').trim().toLowerCase();
            const fn = (document.getElementById('given_name').value || '').trim().toLowerCase();
            const ln = (document.getElementById('surname').value || '').trim().toLowerCase();

            const hasLen = p1.length >= 8;
            const hasUpper = /[A-Z]/.test(p1);
            const hasLower = /[a-z]/.test(p1);
            const hasDigitOrSpecial = /[0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]/.test(p1);
            
            let noUser = true;
            if (u && u.length >= 3 && p1.toLowerCase().includes(u)) noUser = false;
            if (fn && fn.length >= 3 && p1.toLowerCase().includes(fn)) noUser = false;
            if (ln && ln.length >= 3 && p1.toLowerCase().includes(ln)) noUser = false;

            const matches = p1.length > 0 && p1 === p2;

            const updateRule = (id, valid) => {
                const el = document.getElementById(id);
                if (!el) return;
                const label = el.getAttribute('data-label');
                if (valid) {
                    el.className = 'text-emerald-400 flex items-center gap-1 font-medium';
                    el.innerHTML = `<i class="fa-solid fa-circle-check text-[10px]"></i> ${escapeHtml(label)}`;
                } else {
                    el.className = 'text-slate-500 flex items-center gap-1';
                    el.innerHTML = `<i class="fa-regular fa-circle text-[10px]"></i> ${escapeHtml(label)}`;
                }
            };

            updateRule('rule-len', hasLen);
            updateRule('rule-upper', hasUpper);
            updateRule('rule-lower', hasLower);
            updateRule('rule-num', hasDigitOrSpecial);
            updateRule('rule-user', noUser);
            updateRule('rule-match', matches);

            const categoriesMet = [hasUpper, hasLower, /[0-9]/.test(p1), /[^a-zA-Z0-9]/.test(p1)].filter(Boolean).length;
            return hasLen && categoriesMet >= 3 && noUser && matches;
        }

        function showStatus(type, msg) {
            const box = document.getElementById('status-box');
            box.classList.remove('hidden', 'bg-rose-950/40', 'border-rose-800', 'text-rose-300', 'bg-emerald-950/40', 'border-emerald-800', 'text-emerald-300', 'bg-amber-950/40', 'border-amber-800', 'text-amber-300');
            if (type === 'error') {
                box.classList.add('bg-rose-950/40', 'border-rose-800', 'text-rose-300');
            } else if (type === 'success') {
                box.classList.add('bg-emerald-950/40', 'border-emerald-800', 'text-emerald-300');
            } else if (type === 'warning') {
                box.classList.add('bg-amber-950/40', 'border-amber-800', 'text-amber-300');
            }
            box.textContent = msg;
        }

        function hideStatus() {
            document.getElementById('status-box').classList.add('hidden');
        }

        async function handleInitialSubmit(e) {
            e.preventDefault();
            hideStatus();
            const submitBtn = document.getElementById('submit-btn');

            const p1 = document.getElementById('password').value;
            const p2 = document.getElementById('confirm_password').value;

            if (p1 !== p2) {
                showStatus('error', '<i class="fa-solid fa-triangle-exclamation mr-1.5"></i> Passwords do not match. Please verify and try again.');
                return;
            }

            if (!checkPasswordComplexity()) {
                showStatus('error', '<i class="fa-solid fa-shield-halved mr-1.5"></i> Password does not meet Active Directory complexity requirements. Please satisfy all requirements indicated below.');
                return;
            }

            const payload = {
                given_name: document.getElementById('given_name').value.trim(),
                surname: document.getElementById('surname').value.trim(),
                email: document.getElementById('email').value.trim(),
                mobile: document.getElementById('mobile').value.trim(),
                username: document.getElementById('username').value.trim(),
                password: p1,
                department: document.getElementById('department').value,
                justification: document.getElementById('justification').value.trim()
            };

            submitBtn.disabled = true;
            submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Processing Registration...';

            try {
                const res = await fetch('/api/v1/public/register/initiate', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                let data = null;
                try {
                    data = await res.json();
                } catch (e) {
                    console.error('Failed to parse JSON response:', e);
                }

                if (res.ok && data) {
                    if (data.status === 'otp_required') {
                        // Transition to Step 2: OTP Verification
                        currentRegId = data.registration_id;
                        document.getElementById('otp-mobile-display').textContent = data.mobile_masked || payload.mobile;

                        document.getElementById('step-details').classList.add('hidden');
                        document.getElementById('step-otp').classList.remove('hidden');
                        startResendCountdown();
                        showStatus('success', `<i class="fa-solid fa-check mr-1.5"></i> ${escapeHtml(data.message)}`);
                    } else if (data.status === 'pending_approval') {
                        // OTP verification was disabled by admin; user is pending admin approval
                        document.getElementById('step-details').classList.add('hidden');
                        showStatus('warning', `
                            <div class="space-y-1">
                                <div class="font-bold text-amber-200"><i class="fa-solid fa-clock mr-1.5"></i> Registration Received - Pending Administrator Approval</div>
                                <p class="text-slate-300">${escapeHtml(data.message)}</p>
                                <p class="text-[11px] text-slate-400">Reference ID: <strong>#${escapeHtml(data.registration_id)}</strong> | An SMS and Email notification will be sent upon activation.</p>
                            </div>
                        `);
                    }
                } else {
                    const errorDetail = (data && data.detail) ? data.detail : `Registration failed with status ${res.status}.`;
                    showStatus('error', `<i class="fa-solid fa-circle-xmark mr-1.5"></i> ${escapeHtml(errorDetail)}`);
                }
            } catch (err) {
                showStatus('error', '<i class="fa-solid fa-circle-xmark mr-1.5"></i> Network error: could not connect to ZclockID API.');
            } finally {
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane"></i> Submit Registration';
            }
        }

        async function handleOtpVerify(e) {
            e.preventDefault();
            hideStatus();
            const btn = document.getElementById('btn-verify-otp');
            const otpCode = document.getElementById('otp_input').value.trim();

            if (!currentRegId) {
                showStatus('error', 'Session error. Please restart registration.');
                return;
            }

            btn.disabled = true;
            btn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Verifying & Provisioning...';

            try {
                const res = await fetch('/api/v1/public/register/verify-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ registration_id: currentRegId, otp_code: otpCode })
                });
                const data = await res.json();

                if (res.ok && data.status === 'success') {
                    // Step 3: Success Screen
                    document.getElementById('step-otp').classList.add('hidden');
                    document.getElementById('step-success').classList.remove('hidden');
                    document.getElementById('succ-username').textContent = data.username;
                    document.getElementById('succ-upn').textContent = data.domain ? `${data.username}@${data.domain}` : data.username;
                    showStatus('success', `<i class="fa-solid fa-circle-check mr-1.5"></i> ${escapeHtml(data.message)}`);
                } else {
                    showStatus('error', `<i class="fa-solid fa-circle-xmark mr-1.5"></i> ${escapeHtml(data.detail || 'Verification failed. Please check OTP code.')}`);
                }
            } catch (err) {
                showStatus('error', '<i class="fa-solid fa-circle-xmark mr-1.5"></i> Network error during verification.');
            } finally {
                btn.disabled = false;
                btn.innerHTML = '<i class="fa-solid fa-circle-check"></i> Verify Mobile & Activate Account';
            }
        }

        function startResendCountdown() {
            resendSeconds = 60;
            const resendBtn = document.getElementById('btn-resend-otp');
            const countdownEl = document.getElementById('resend-countdown');
            resendBtn.disabled = true;
            resendBtn.classList.add('opacity-50', 'cursor-not-allowed');

            if (resendTimer) clearInterval(resendTimer);
            resendTimer = setInterval(() => {
                resendSeconds--;
                countdownEl.textContent = resendSeconds;
                if (resendSeconds <= 0) {
                    clearInterval(resendTimer);
                    resendBtn.disabled = false;
                    resendBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                    resendBtn.innerHTML = '<i class="fa-solid fa-rotate"></i> Resend Code';
                }
            }, 1000);
        }

        async function handleResendOtp() {
            if (!currentRegId) return;
            const resendBtn = document.getElementById('btn-resend-otp');
            resendBtn.disabled = true;
            resendBtn.innerHTML = '<i class="fa-solid fa-circle-notch animate-spin"></i> Sending...';

            try {
                const res = await fetch('/api/v1/public/register/resend-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ registration_id: currentRegId })
                });
                const data = await res.json();
                if (res.ok) {
                    showStatus('success', `<i class="fa-solid fa-check mr-1.5"></i> ${escapeHtml(data.message)}`);
                    startResendCountdown();
                } else {
                    showStatus('error', `<i class="fa-solid fa-circle-xmark mr-1.5"></i> ${escapeHtml(data.detail || 'Failed to resend code')}`);
                }
            } catch (err) {
                showStatus('error', 'Failed to resend OTP.');
            }
        }

        function backToDetailsStep() {
            document.getElementById('step-otp').classList.add('hidden');
            document.getElementById('step-details').classList.remove('hidden');
            hideStatus();
        }

window.togglePasswordVisibility = togglePasswordVisibility;
window.checkPasswordComplexity = checkPasswordComplexity;
window.handleInitialSubmit = handleInitialSubmit;
window.handleOtpVerify = handleOtpVerify;
window.handleResendOtp = handleResendOtp;
window.backToDetailsStep = backToDetailsStep;
