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

        let currentMethod = 'old';
        let activeResetId = null;
        let activeUsername = null;
        let portalConfig = null;

        // Fetch portal settings and primary realm
        async function loadPortalConfig() {
            try {
                const res = await fetch('/api/v1/self-service/password/config');
                const data = await res.json();
                if (data.status === 'success') {
                    portalConfig = data;
                    document.getElementById('sspr-primary-domain').textContent = data.primary_domain || 'Active Directory';
                    
                    if (!data.enabled) {
                        showStatus('Self-Service Password Reset is currently disabled by administrator.', 'error');
                        document.getElementById('form-old-password').classList.add('hidden');
                        document.getElementById('otp-container').classList.add('hidden');
                        document.querySelector('.flex.p-1.bg-slate-950').classList.add('hidden');
                        return;
                    }

                    // Toggle visibility of method buttons according to admin settings
                    if (!data.allow_old_password_reset) {
                        document.getElementById('tab-btn-old').classList.add('hidden');
                    }
                    if (!data.allow_email_reset) {
                        document.getElementById('tab-btn-email').classList.add('hidden');
                    }
                    if (!data.allow_otp_reset) {
                        document.getElementById('tab-btn-sms').classList.add('hidden');
                    }

                    // Default to first enabled method
                    if (!data.allow_old_password_reset) {
                        if (data.allow_email_reset) switchMethodTab('email');
                        else if (data.allow_otp_reset) switchMethodTab('sms');
                    }
                }
            } catch (e) {
                document.getElementById('sspr-primary-domain').innerText = 'Unavailable';
            }
        }

        function switchMethodTab(method) {
            currentMethod = method;
            hideStatus();
            document.getElementById('admin-fallback-card').classList.add('hidden');

            const tabOld = document.getElementById('tab-btn-old');
            const tabEmail = document.getElementById('tab-btn-email');
            const tabSms = document.getElementById('tab-btn-sms');
            const formOld = document.getElementById('form-old-password');
            const otpBox = document.getElementById('otp-container');

            // Reset tab styling
            [tabOld, tabEmail, tabSms].forEach(btn => {
                btn.className = 'flex-1 py-2 px-3 rounded-lg transition flex items-center justify-center gap-2 text-slate-400 hover:text-slate-200';
            });

            const activeBtn = method === 'old' ? tabOld : (method === 'email' ? tabEmail : tabSms);
            activeBtn.className = 'flex-1 py-2 px-3 rounded-lg transition flex items-center justify-center gap-2 bg-indigo-600 text-white shadow-sm';

            if (method === 'old') {
                formOld.classList.remove('hidden');
                otpBox.classList.add('hidden');
            } else {
                formOld.classList.add('hidden');
                otpBox.classList.remove('hidden');
                resetOtpFlow();

                const icon = document.getElementById('otp-icon-type');
                const desc = document.getElementById('otp-channel-desc');
                if (method === 'email') {
                    icon.className = 'fa-solid fa-envelope absolute right-3 top-2.5 text-slate-500 text-xs';
                    desc.innerText = 'A 6-digit verification code will be sent to the email address registered on your Active Directory account.';
                } else {
                    icon.className = 'fa-solid fa-mobile-screen absolute right-3 top-2.5 text-slate-500 text-xs';
                    desc.innerText = 'A 6-digit verification code will be sent via SMS to the mobile phone registered on your Active Directory account.';
                }
            }
        }

        function togglePasswordVisibility(inputId, eyeId) {
            const input = document.getElementById(inputId);
            const eye = document.getElementById(eyeId);
            if (!input || !eye) return;
            if (input.type === 'password') {
                input.type = 'text';
                eye.classList.remove('fa-eye');
                eye.classList.add('fa-eye-slash');
            } else {
                input.type = 'password';
                eye.classList.remove('fa-eye-slash');
                eye.classList.add('fa-eye');
            }
        }

        function checkComplexity(passId, confirmId, prefix) {
            const pass = document.getElementById(passId)?.value || '';
            const confirm = document.getElementById(confirmId)?.value || '';

            const minLen = (portalConfig && portalConfig.min_password_length) ? portalConfig.min_password_length : 8;
            const hasLen = pass.length >= minLen;
            const hasUpper = /[A-Z]/.test(pass);
            const hasLower = /[a-z]/.test(pass);
            const hasNum = /[0-9]/.test(pass);
            const hasSpecial = /[^A-Za-z0-9]/.test(pass);
            const hasMatch = pass.length > 0 && pass === confirm;

            updateRule(`${prefix}-len`, hasLen, `Min ${minLen} characters`);
            updateRule(`${prefix}-upper`, hasUpper, 'Uppercase letter (A-Z)');
            updateRule(`${prefix}-lower`, hasLower, 'Lowercase letter (a-z)');
            updateRule(`${prefix}-num`, hasNum, 'Numeric digit (0-9)');
            updateRule(`${prefix}-special`, hasSpecial, 'Special symbol (!@#$)');
            updateRule(`${prefix}-match`, hasMatch, 'Passwords match');

            return hasLen && hasUpper && hasLower && hasNum && hasSpecial && hasMatch;
        }

        function updateRule(elemId, isValid, text) {
            const el = document.getElementById(elemId);
            if (!el) return;
            if (isValid) {
                el.className = 'flex items-center gap-1.5 text-emerald-400 font-medium';
                el.innerHTML = `<i class="fa-solid fa-circle-check text-[10px]"></i> ${escapeHtml(text)}`;
            } else {
                el.className = 'flex items-center gap-1.5 text-slate-400';
                el.innerHTML = `<i class="fa-regular fa-circle text-[10px]"></i> ${escapeHtml(text)}`;
            }
        }

        function showStatus(message, type = 'error') {
            const box = document.getElementById('status-box');
            box.classList.remove('hidden', 'bg-red-950/50', 'border-red-800/80', 'text-red-200', 'bg-emerald-950/50', 'border-emerald-800/80', 'text-emerald-200', 'bg-amber-950/50', 'border-amber-800/80', 'text-amber-200');

            if (type === 'error') {
                box.classList.add('bg-red-950/50', 'border-red-800/80', 'text-red-200');
                box.innerHTML = `<div class="flex items-start gap-2.5"><i class="fa-solid fa-circle-exclamation mt-0.5 text-red-400"></i><span>${escapeHtml(message)}</span></div>`;
            } else if (type === 'success') {
                box.classList.add('bg-emerald-950/50', 'border-emerald-800/80', 'text-emerald-200');
                box.innerHTML = `<div class="flex items-start gap-2.5"><i class="fa-solid fa-circle-check mt-0.5 text-emerald-400"></i><span>${escapeHtml(message)}</span></div>`;
            } else {
                box.classList.add('bg-amber-950/50', 'border-amber-800/80', 'text-amber-200');
                box.innerHTML = `<div class="flex items-start gap-2.5"><i class="fa-solid fa-triangle-exclamation mt-0.5 text-amber-400"></i><span>${escapeHtml(message)}</span></div>`;
            }
            box.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        function hideStatus() {
            document.getElementById('status-box').classList.add('hidden');
        }

        // ==================== SUBMIT OLD PASSWORD ====================
        async function handleOldPasswordSubmit(e) {
            e.preventDefault();
            hideStatus();

            const username = document.getElementById('old-username').value.trim();
            const oldPassword = document.getElementById('old-password').value;
            const newPassword = document.getElementById('old-new-password').value;
            const confirmPassword = document.getElementById('old-confirm-password').value;

            if (newPassword !== confirmPassword) {
                showStatus('The new passwords do not match.', 'error');
                return;
            }

            if (!checkComplexity('old-new-password', 'old-confirm-password', 'old-rules')) {
                showStatus('Please ensure the new password satisfies all complexity requirements.', 'error');
                return;
            }

            const btn = document.getElementById('btn-submit-old');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Changing Password...`;

            try {
                const res = await fetch('/api/v1/self-service/password/change-with-old', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: username,
                        old_password: oldPassword,
                        new_password: newPassword
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || 'Password change failed.');
                }

                showStatus(data.message || 'Password changed successfully! Redirecting to login...', 'success');
                document.getElementById('form-old-password').reset();
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 3000);

            } catch (err) {
                showStatus(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-check"></i> Change Password`;
            }
        }

        // ==================== REQUEST OTP (EMAIL / SMS) ====================
        async function handleRequestOtp() {
            hideStatus();
            document.getElementById('admin-fallback-card').classList.add('hidden');

            const username = document.getElementById('otp-username').value.trim();
            if (!username) {
                showStatus('Please enter your Active Directory username.', 'error');
                return;
            }

            const btn = document.getElementById('btn-request-otp');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Checking Account & Sending Code...`;

            try {
                const res = await fetch('/api/v1/self-service/password/request-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username: username,
                        channel: currentMethod
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    // Check for contact missing error to show administrator fallback card
                    if (data.detail && (data.detail.includes('No email address') || data.detail.includes('No mobile phone') || data.detail.includes('contact your Domain Administrator'))) {
                        document.getElementById('admin-fallback-text').innerText = data.detail;
                        document.getElementById('admin-fallback-card').classList.remove('hidden');
                        throw new Error(data.detail);
                    }
                    throw new Error(data.detail || 'Failed to dispatch verification code.');
                }

                activeResetId = data.reset_id;
                activeUsername = data.username;

                document.getElementById('verify-account-name').innerText = data.username;
                document.getElementById('verify-recipient').innerText = data.recipient_masked;

                document.getElementById('otp-step-request').classList.add('hidden');
                document.getElementById('otp-step-verify').classList.remove('hidden');
                showStatus(data.message, 'success');

            } catch (err) {
                showStatus(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Send Verification Code`;
            }
        }

        // ==================== VERIFY OTP & RESET PASSWORD ====================
        async function handleVerifyOtpSubmit(e) {
            e.preventDefault();
            hideStatus();

            const otpCode = document.getElementById('otp-code-input').value.trim();
            const newPassword = document.getElementById('otp-new-password').value;
            const confirmPassword = document.getElementById('otp-confirm-password').value;

            if (!otpCode || otpCode.length !== 6) {
                showStatus('Please enter the 6-digit verification code.', 'error');
                return;
            }

            if (newPassword !== confirmPassword) {
                showStatus('The new passwords do not match.', 'error');
                return;
            }

            if (!checkComplexity('otp-new-password', 'otp-confirm-password', 'otp-rules')) {
                showStatus('Please ensure the new password satisfies all complexity requirements.', 'error');
                return;
            }

            const btn = document.getElementById('btn-submit-otp');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Resetting Password in AD...`;

            try {
                const res = await fetch('/api/v1/self-service/password/verify-and-reset', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        reset_id: activeResetId,
                        username: activeUsername,
                        otp_code: otpCode,
                        new_password: newPassword
                    })
                });

                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || 'Password reset failed.');
                }

                showStatus(data.message || 'Password reset successfully! Redirecting to login...', 'success');
                document.getElementById('otp-step-verify').reset();
                setTimeout(() => {
                    window.location.href = '/login.html';
                }, 3000);

            } catch (err) {
                showStatus(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-unlock-keyhole"></i> Reset Password`;
            }
        }

        function resetOtpFlow() {
            activeResetId = null;
            activeUsername = null;
            document.getElementById('otp-step-request').classList.remove('hidden');
            document.getElementById('otp-step-verify').classList.add('hidden');
            document.getElementById('admin-fallback-card').classList.add('hidden');
            document.getElementById('otp-code-input').value = '';
            document.getElementById('otp-new-password').value = '';
            document.getElementById('otp-confirm-password').value = '';
        }

        // Init
        loadPortalConfig();

        // Check for #change or ?username= / #change?username=
        function checkUrlParams() {
            let uParam = new URLSearchParams(window.location.search).get('username');
            const hash = window.location.hash || '';
            if (hash.includes('change')) {
                switchMethodTab('old');
                if (hash.includes('username=')) {
                    try {
                        const qIdx = hash.indexOf('?');
                        if (qIdx !== -1) {
                            const hashParams = new URLSearchParams(hash.substring(qIdx));
                            const hashUser = hashParams.get('username');
                            if (hashUser) uParam = hashUser;
                        }
                    } catch (e) {}
                }
            }
            if (uParam) {
                const oldUserInput = document.getElementById('old-username');
                if (oldUserInput) oldUserInput.value = uParam;
                const otpUserInput = document.getElementById('otp-username');
                if (otpUserInput) otpUserInput.value = uParam;
            }
        }
        window.addEventListener('DOMContentLoaded', checkUrlParams);
        checkUrlParams();

window.switchMethodTab = switchMethodTab;
window.togglePasswordVisibility = togglePasswordVisibility;
window.checkComplexity = checkComplexity;
window.handleOldPasswordSubmit = handleOldPasswordSubmit;
window.handleRequestOtp = handleRequestOtp;
window.handleVerifyOtpSubmit = handleVerifyOtpSubmit;
window.resetOtpFlow = resetOtpFlow;
