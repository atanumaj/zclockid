// ==================== ZCLOCKID ENTERPRISE LICENSE CONTROLLER ====================
let stagedLicenseFile = null;

async function fetchLicenseStatus() {
    try {
        const res = await fetch(`${API_BASE}/license/status`, { headers: getAuthHeaders() });
        if (!res.ok) {
            console.warn("Failed to fetch license status:", res.status);
            return;
        }
        const data = await res.json();
        renderLicenseStatus(data);
    } catch (err) {
        console.error("Error fetching license status:", err);
    }
}

function renderLicenseStatus(data) {
    if (!data) return;

    // 1. Subscription Status & Badge
    const badgeEl = document.getElementById('lic-card-badge');
    const tierEl = document.getElementById('lic-card-tier');
    const statusDescEl = document.getElementById('lic-card-status-desc');

    if (badgeEl) {
        if (data.status === 'ACTIVE') {
            badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
            badgeEl.innerText = 'ENTERPRISE LICENSED';
        } else if (data.status === 'EXPIRED') {
            badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950 text-amber-400 border border-amber-800';
            badgeEl.innerText = 'EXPIRED';
        } else if (data.status === 'INVALID_SIGNATURE') {
            badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800';
            badgeEl.innerText = 'INVALID SIGNATURE';
        } else {
            badgeEl.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-400 border border-sky-800';
            badgeEl.innerText = 'FREE TIER (UP TO 200)';
        }
    }

    if (tierEl) tierEl.innerText = data.tier || 'Community Edition';
    if (statusDescEl) statusDescEl.innerText = data.status_label || (data.is_licensed ? 'Commercial Subscription' : 'Free for general use (up to 200 users)');

    // 2. Capacity & Utilization Meter
    const curUsersEl = document.getElementById('lic-card-current-users');
    const maxUsersEl = document.getElementById('lic-card-max-users');
    const utilPctEl = document.getElementById('lic-card-util-pct');
    const progressEl = document.getElementById('lic-card-progress');
    const remainingEl = document.getElementById('lic-card-remaining');

    const curCount = data.current_users || 0;
    const maxUsers = data.is_unlimited ? 'Unlimited' : (data.max_users || 200);
    const utilPct = data.is_unlimited ? 0 : (data.utilization_pct || 0);

    if (curUsersEl) curUsersEl.innerText = curCount.toLocaleString();
    if (maxUsersEl) maxUsersEl.innerText = typeof maxUsers === 'number' ? maxUsers.toLocaleString() : maxUsers;
    if (utilPctEl) utilPctEl.innerText = `${utilPct}%`;

    if (progressEl) {
        progressEl.style.width = `${Math.min(100, Math.max(2, utilPct))}%`;
        if (utilPct >= 100) {
            progressEl.className = 'bg-rose-500 h-1.5 rounded-full transition-all duration-300';
            if (utilPctEl) utilPctEl.className = 'text-xs font-mono font-bold text-rose-400';
        } else if (utilPct >= 80) {
            progressEl.className = 'bg-amber-500 h-1.5 rounded-full transition-all duration-300';
            if (utilPctEl) utilPctEl.className = 'text-xs font-mono font-bold text-amber-400';
        } else {
            progressEl.className = 'bg-emerald-500 h-1.5 rounded-full transition-all duration-300';
            if (utilPctEl) utilPctEl.className = 'text-xs font-mono font-bold text-emerald-400';
        }
    }

    if (remainingEl) {
        if (data.is_unlimited) {
            remainingEl.innerText = 'Unlimited capacity';
        } else {
            const rem = data.remaining_capacity || 0;
            remainingEl.innerText = `${rem.toLocaleString()} slots remaining`;
        }
    }

    // 3. System Validity
    const expiryEl = document.getElementById('lic-card-expiry');
    const daysEl = document.getElementById('lic-card-days-remaining');
    const validityIcon = document.getElementById('lic-card-validity-icon');

    if (expiryEl) {
        if (data.is_perpetual) {
            expiryEl.innerText = 'Perpetual';
        } else if (data.expiry_date && data.expiry_date !== 'INVALID') {
            expiryEl.innerText = `Valid until ${data.expiry_date}`;
        } else {
            expiryEl.innerText = 'Invalid / Expired';
        }
    }

    if (daysEl) {
        if (data.is_perpetual) {
            daysEl.innerText = data.is_licensed ? 'Lifetime Enterprise License (No Expiration)' : 'Community Edition (No Expiration)';
        } else if (data.days_remaining !== null && data.days_remaining !== undefined) {
            if (data.days_remaining === 0) {
                daysEl.innerText = 'Subscription has expired';
            } else {
                daysEl.innerText = `${data.days_remaining} days remaining`;
            }
        } else {
            daysEl.innerText = 'Standard validity';
        }
    }

    if (validityIcon) {
        if (data.is_perpetual) {
            validityIcon.className = 'fa-solid fa-infinity text-sky-400 text-sm';
        } else if (data.status === 'EXPIRED') {
            validityIcon.className = 'fa-solid fa-clock text-rose-400 text-sm';
        } else {
            validityIcon.className = 'fa-solid fa-calendar-check text-emerald-400 text-sm';
        }
    }

    // 4. Organization & ID
    const orgEl = document.getElementById('lic-card-org');
    const idEl = document.getElementById('lic-card-id');
    if (orgEl) {
        orgEl.innerText = data.organization || 'Community / General Use';
        orgEl.title = data.organization || 'Community / General Use';
    }
    if (idEl) idEl.innerText = data.license_id || 'COMMUNITY-TIER-200';

    // 5. Alert Banner for Warnings / Over-limit
    const alertBanner = document.getElementById('lic-alert-banner');
    const alertIcon = document.getElementById('lic-alert-icon');
    const alertTitle = document.getElementById('lic-alert-title');
    const alertMsg = document.getElementById('lic-alert-message');

    if (alertBanner) {
        if (data.over_limit) {
            alertBanner.className = 'p-4 rounded-xl border bg-rose-950/60 border-rose-800 text-rose-200 flex items-start gap-3';
            if (alertIcon) alertIcon.className = 'fa-solid fa-triangle-exclamation text-base mt-0.5 text-rose-400';
            if (alertTitle) alertTitle.innerText = 'User Capacity Limit Exceeded';
            if (alertMsg) alertMsg.innerText = `Current user count (${curCount}) exceeds subscribed capacity (${maxUsers}). Please upload a valid license certificate (zclockid.lic) under Security & Management > License to support additional users.`;
            alertBanner.classList.remove('hidden');
        } else if (data.status === 'EXPIRED') {
            alertBanner.className = 'p-4 rounded-xl border bg-amber-950/60 border-amber-800 text-amber-200 flex items-start gap-3';
            if (alertIcon) alertIcon.className = 'fa-solid fa-clock text-base mt-0.5 text-amber-400';
            if (alertTitle) alertTitle.innerText = 'Enterprise License Expired';
            if (alertMsg) alertMsg.innerText = `Your subscription expired on ${data.expiry_date}. The appliance has reverted to Free Community mode (up to 200 users). Please upload an updated zclockid.lic file.`;
            alertBanner.classList.remove('hidden');
        } else if (data.status === 'INVALID_SIGNATURE') {
            alertBanner.className = 'p-4 rounded-xl border bg-rose-950/60 border-rose-800 text-rose-200 flex items-start gap-3';
            if (alertIcon) alertIcon.className = 'fa-solid fa-shield-xmark text-base mt-0.5 text-rose-400';
            if (alertTitle) alertTitle.innerText = 'Cryptographic Signature Verification Failed';
            if (alertMsg) alertMsg.innerText = data.error_detail || 'The installed license file failed signature verification.';
            alertBanner.classList.remove('hidden');
        } else {
            alertBanner.classList.add('hidden');
        }
    }

    // 6. Detailed Table Fields
    const detOrg = document.getElementById('lic-det-org');
    const detId = document.getElementById('lic-det-id');
    const detTier = document.getElementById('lic-det-tier');
    const detCap = document.getElementById('lic-det-capacity');
    const detIssued = document.getElementById('lic-det-issued');
    const detExpiry = document.getElementById('lic-det-expiry');
    const detSig = document.getElementById('lic-det-sig');

    if (detOrg) detOrg.innerText = data.organization || 'Community / General Use';
    if (detId) detId.innerText = data.license_id || 'COMMUNITY-TIER-200';
    if (detTier) detTier.innerText = data.tier || 'Community Edition';
    if (detCap) detCap.innerText = data.is_unlimited ? 'Unlimited Users' : `${(data.max_users || 200).toLocaleString()} Users ${data.is_licensed ? '(Enterprise)' : '(Free Community)'}`;
    if (detIssued) detIssued.innerText = data.issued_date || 'N/A';
    if (detExpiry) detExpiry.innerText = data.is_perpetual ? 'Perpetual (No Expiration)' : (data.expiry_date || 'N/A');

    if (detSig) {
        if (data.is_licensed && data.is_valid) {
            detSig.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950 text-emerald-400 border border-emerald-800';
            detSig.innerText = 'ED25519 VERIFIED';
        } else if (!data.is_licensed) {
            detSig.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-sky-950 text-sky-400 border border-sky-800';
            detSig.innerText = 'COMMUNITY BASELINE';
        } else {
            detSig.className = 'px-2 py-0.5 rounded text-[10px] font-bold bg-rose-950 text-rose-400 border border-rose-800';
            detSig.innerText = 'SIGNATURE FAILED';
        }
    }

    // 7. Buttons: Download & Remove License
    const btnDownload = document.getElementById('btn-download-license');
    const removeContainer = document.getElementById('lic-remove-container');
    if (btnDownload) {
        if (data.is_licensed) btnDownload.classList.remove('hidden');
        else btnDownload.classList.add('hidden');
    }
    if (removeContainer) {
        if (data.is_licensed) removeContainer.classList.remove('hidden');
        else removeContainer.classList.add('hidden');
    }
}

// File Selection Handler
function handleLicenseFileSelect(event) {
    const file = event.target.files && event.target.files[0];
    if (!file) return;

    stagedLicenseFile = file;
    const nameEl = document.getElementById('lic-selected-file-name');
    const sizeEl = document.getElementById('lic-selected-file-size');
    const infoEl = document.getElementById('lic-selected-file-info');
    const btnUpload = document.getElementById('btn-submit-license-upload');

    if (nameEl) nameEl.innerText = file.name;
    if (sizeEl) sizeEl.innerText = `(${(file.size / 1024).toFixed(1)} KB)`;
    if (infoEl) infoEl.classList.remove('hidden');
    if (btnUpload) btnUpload.disabled = false;
}

function clearSelectedLicenseFile() {
    stagedLicenseFile = null;
    const fileInput = document.getElementById('lic-file-input');
    if (fileInput) fileInput.value = '';
    const infoEl = document.getElementById('lic-selected-file-info');
    if (infoEl) infoEl.classList.add('hidden');
    const btnUpload = document.getElementById('btn-submit-license-upload');
    if (btnUpload) btnUpload.disabled = true;
}

// Upload & Activate
async function submitLicenseUpload() {
    if (!stagedLicenseFile) {
        alert("Please select a valid zclockid.lic file first.");
        return;
    }

    const btn = document.getElementById('btn-submit-license-upload');
    const feedback = document.getElementById('lic-upload-feedback');
    const origHtml = btn.innerHTML;

    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Cryptographically Verifying...`;
    if (feedback) feedback.classList.add('hidden');

    try {
        const formData = new FormData();
        formData.append('file', stagedLicenseFile);

        const token = localStorage.getItem('zclockid_token');
        const headers = {};
        if (token) headers['Authorization'] = `Bearer ${token}`;

        const res = await fetch(`${API_BASE}/license/upload`, {
            method: 'POST',
            headers: headers,
            body: formData
        });

        const data = await res.json();
        if (res.ok) {
            if (feedback) {
                feedback.className = 'p-3 rounded-lg text-xs border bg-emerald-950/60 border-emerald-800 text-emerald-300 flex items-center gap-2';
                feedback.innerHTML = `<i class="fa-solid fa-circle-check text-emerald-400"></i> ${data.message || 'License activated successfully!'}`;
                feedback.classList.remove('hidden');
            }
            clearSelectedLicenseFile();
            fetchLicenseStatus();
        } else {
            if (feedback) {
                feedback.className = 'p-3 rounded-lg text-xs border bg-rose-950/60 border-rose-800 text-rose-300 flex items-center gap-2';
                feedback.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400"></i> ${data.detail || 'Failed to activate license.'}`;
                feedback.classList.remove('hidden');
            }
        }
    } catch (err) {
        if (feedback) {
            feedback.className = 'p-3 rounded-lg text-xs border bg-rose-950/60 border-rose-800 text-rose-300 flex items-center gap-2';
            feedback.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-rose-400"></i> Upload error: ${err.message}`;
            feedback.classList.remove('hidden');
        }
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHtml;
    }
}

// Download Active License
function downloadActiveLicense() {
    const token = localStorage.getItem('zclockid_token');
    window.location.href = `${API_BASE}/license/download?token=${encodeURIComponent(token || '')}`;
}

// Remove License
async function confirmAndRemoveLicense() {
    if (!confirm("Are you sure you want to remove this enterprise license?\n\nThe appliance will revert to the Free Community Tier (up to 200 users).")) {
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/license/remove`, {
            method: 'DELETE',
            headers: getAuthHeaders()
        });
        const data = await res.json();
        if (res.ok) {
            alert(data.message || "License removed successfully. Appliance reverted to Community Free Tier.");
            fetchLicenseStatus();
        } else {
            alert(`Failed to remove license: ${data.detail}`);
        }
    } catch (err) {
        alert(`Error removing license: ${err.message}`);
    }
}
