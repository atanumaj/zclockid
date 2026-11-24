// Verify appliance setup state and prevent re-initialization of configured systems
fetch('/api/v1/setup/status')
    .then(r => r.json())
    .then(data => {
        const spinner = document.getElementById('setup-loading-spinner');
        if (spinner) spinner.remove();

        if (data.is_configured || data.setup_lock) {
            // Already configured - immediately redirect to login.html
            window.location.replace('/login.html');
            // If browser prevents redirect, display locked card and destroy wizard form
            const wizardCard = document.getElementById('setup-wizard-card');
            if (wizardCard) wizardCard.remove();
            const lockedBanner = document.getElementById('setup-locked-banner');
            if (lockedBanner) lockedBanner.classList.remove('hidden');
        } else {
            // Fresh, unconfigured appliance: reveal wizard
            const wizardCard = document.getElementById('setup-wizard-card');
            if (wizardCard) wizardCard.classList.remove('hidden');
            if (data.hostname) {
                const hnInput = document.getElementById('system_hostname');
                if (hnInput && !hnInput.value) {
                    hnInput.value = data.hostname.toLowerCase();
                }
            }
        }
    })
    .catch(() => {
        // Fail closed on error: redirect to login
        window.location.replace('/login.html');
    });

        function goToStep(step) {
            // Validation
            if (step === 2) {
                const acceptBox = document.getElementById("accept_license");
                if (!acceptBox || !acceptBox.checked) {
                    alert("Please read and accept the ZclockID Software License Agreement before proceeding.");
                    return;
                }
                const p1 = document.getElementById('admin_password').value;
                const p2 = document.getElementById('admin_password_confirm').value;
                if (!p1 || p1.length < 8) {
                    alert('Please enter an admin password of at least 8 characters.');
                    return;
                }
                if (p1 !== p2) {
                    alert('Passwords do not match.');
                    return;
                }
            }

            // Step 3 UI Toggle
            if (step === 3) {
                const mode = document.querySelector('input[name="domain_mode"]:checked').value;
                const joinFields = document.getElementById('join-fields');
                if (mode === 'join_domain') {
                    joinFields.classList.remove('hidden');
                } else {
                    joinFields.classList.add('hidden');
                }
            }

            // Step 4 Review Populate & Validation
            if (step === 4) {
                const hn = document.getElementById('system_hostname').value.trim().toLowerCase();
                if (!hn || !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(hn)) {
                    alert('Please enter a valid hostname (lowercase letters, numbers, and hyphens only, up to 63 characters).');
                    return;
                }
                const pAD = document.getElementById('ad_admin_password').value;
                if (!pAD || pAD.length < 8) {
                    alert('Domain Administrator Password must be at least 8 characters.');
                    return;
                }

                const mode = document.querySelector('input[name="domain_mode"]:checked').value;
                if (mode === 'join_domain') {
                    const partnerIp = document.getElementById('partner_dc_ip').value.trim();
                    if (!partnerIp) {
                        alert('Please enter the Existing Primary DC IP Address.');
                        return;
                    }
                    document.getElementById('rev-partner-row').classList.remove('hidden');
                    document.getElementById('rev-partner-ip').innerText = partnerIp;
                } else {
                    document.getElementById('rev-partner-row').classList.add('hidden');
                }

                document.getElementById('rev-hostname').innerText = hn;
                document.getElementById('rev-admin-user').innerText = document.getElementById('admin_username').value;
                document.getElementById('rev-mode').innerText = mode === 'new_domain' ? 'New Forest (Primary DC)' : 'Join Forest (Secondary DC)';
                document.getElementById('rev-realm').innerText = document.getElementById('ad_realm').value.toUpperCase();
                document.getElementById('rev-netbios').innerText = document.getElementById('ad_domain_netbios').value.toUpperCase();
            }

            // Toggle visibility
            for (let i = 1; i <= 4; i++) {
                document.getElementById(`step-${i}`).classList.add('hidden');
                const ind = document.getElementById(`step-ind-${i}`);
                ind.className = (i === step) ? 'flex items-center gap-2 text-indigo-400 font-semibold' : 'flex items-center gap-2 text-slate-500';
            }
            document.getElementById(`step-${step}`).classList.remove('hidden');
        }

        async function startProvisioning() {
            const mode = document.querySelector('input[name="domain_mode"]:checked').value;
            const payload = {
                admin_username: document.getElementById('admin_username').value,
                admin_email: document.getElementById('admin_email').value,
                admin_password: document.getElementById('admin_password').value,
                system_hostname: document.getElementById('system_hostname').value.trim().toLowerCase(),
                mode: mode,
                realm: document.getElementById('ad_realm').value.toUpperCase(),
                domain_netbios: document.getElementById('ad_domain_netbios').value.toUpperCase(),
                ad_admin_password: document.getElementById('ad_admin_password').value,
                dns_forwarder: document.getElementById('dns_forwarder').value,
                partner_dc_ip: document.getElementById('partner_dc_ip').value,
                ad_admin_user: document.getElementById('ad_admin_user').value
            };

            document.getElementById('action-buttons').classList.add('hidden');
            document.getElementById('provision-progress').classList.remove('hidden');

            try {
                const res = await fetch('/api/v1/setup/provision', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();

                if (res.ok) {
                    document.getElementById('progress-bar').className = 'bg-emerald-500 h-2 rounded-full w-full';
                    document.getElementById('progress-status').innerHTML = '<i class="fa-solid fa-circle-check text-emerald-400"></i> Provisioning Successful!';
                    document.getElementById('provision-log').innerText = data.log || 'Samba Active Directory initialized successfully.';

                    setTimeout(() => {
                        window.location.href = '/login.html?provisioned=1';
                    }, 2500);
                } else {
                    document.getElementById('progress-bar').className = 'bg-rose-500 h-2 rounded-full w-full';
                    document.getElementById('progress-status').innerHTML = '<i class="fa-solid fa-triangle-exclamation text-rose-400"></i> Provisioning Failed';
                    document.getElementById('provision-log').innerText = data.detail || 'An error occurred during domain provisioning.';
                    document.getElementById('action-buttons').classList.remove('hidden');
                }
            } catch (err) {
                document.getElementById('progress-status').innerText = 'Network error: could not connect to ZclockID API.';
                document.getElementById('action-buttons').classList.remove('hidden');
            }
        }

        function openLicenseModal() {
            document.getElementById("license-modal").classList.remove("hidden");
        }
        function closeLicenseModal() {
            document.getElementById("license-modal").classList.add("hidden");
        }
        function acceptAndCloseLicenseModal() {
            const cb = document.getElementById("accept_license");
            if (cb) cb.checked = true;
            toggleLicenseAcceptance();
            closeLicenseModal();
        }
        function toggleLicenseAcceptance() {
            const isAccepted = document.getElementById("accept_license")?.checked || false;
            const btn = document.getElementById("btn-step-1-next");
            if (btn) {
                btn.disabled = !isAccepted;
                btn.className = isAccepted 
                    ? "px-5 py-2 bg-indigo-600 hover:bg-indigo-500 text-white rounded-lg text-xs font-semibold shadow transition flex items-center gap-1.5 cursor-pointer"
                    : "px-5 py-2 bg-slate-800 text-slate-500 rounded-lg text-xs font-semibold cursor-not-allowed transition flex items-center gap-1.5";
            }
        }

window.goToStep = goToStep;
window.startProvisioning = startProvisioning;
window.openLicenseModal = openLicenseModal;
window.closeLicenseModal = closeLicenseModal;
window.acceptAndCloseLicenseModal = acceptAndCloseLicenseModal;
window.toggleLicenseAcceptance = toggleLicenseAcceptance;
