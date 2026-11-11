/**
 * ZclockID Self Services Controller
 * Manages Subtab Switching, Self-Registration Queue with Search/Filter/Pagination,
 * and Self-Service Password Reset (SSPR) Activity Logs, Settings, and CSV Exports.
 */

let activeSelfServiceSubtab = 'registration';

// ==================== SUBTAB NAVIGATION ====================
function switchSelfServiceSubtab(tabName) {
    activeSelfServiceSubtab = tabName;
    const btnReg = document.getElementById('btn-subtab-registration');
    const btnPass = document.getElementById('btn-subtab-password');
    const paneReg = document.getElementById('selfservice-pane-registration');
    const panePass = document.getElementById('selfservice-pane-password');

    if (!btnReg || !btnPass || !paneReg || !panePass) return;

    if (tabName === 'registration') {
        btnReg.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-2 bg-indigo-600 text-white shadow-sm shadow-indigo-600/30';
        btnPass.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60';
        paneReg.classList.remove('hidden');
        panePass.classList.add('hidden');
        fetchRegistrations(currentRegFilter);
    } else {
        btnPass.className = 'px-3.5 py-1.5 rounded-lg text-xs font-semibold transition flex items-center gap-2 bg-indigo-600 text-white shadow-sm shadow-indigo-600/30';
        btnReg.className = 'px-3.5 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800/60';
        panePass.classList.remove('hidden');
        paneReg.classList.add('hidden');
        fetchSspprLogs();
    }
}

// ==================== SELF REGISTRATION STATE & ENHANCEMENTS ====================
let cachedRegistrations = [];
let regCurrentFilter = 'all';
let regSearchQuery = '';
let regCurrentMonth = '';
let regCurrentPage = 1;
let regPageSize = 25;

function setRegStatusFilter(filter) {
    regCurrentFilter = filter;
    ['all', 'PENDING_APPROVAL', 'PENDING_OTP', 'VERIFIED_AUTO_PROVISIONED', 'APPROVED'].forEach(f => {
        const b = document.getElementById(`reg-filter-${f}`);
        if (b) {
            if (f === filter) {
                b.className = 'px-2.5 py-1 rounded-md text-[11px] font-semibold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30';
            } else {
                b.className = 'px-2.5 py-1 rounded-md text-[11px] text-slate-400 hover:text-white hover:bg-slate-800';
            }
        }
    });
    regCurrentPage = 1;
    renderRegistrationsTable();
}

function onRegSearchInput() {
    regSearchQuery = document.getElementById('reg-search-input')?.value.trim().toLowerCase() || '';
    regCurrentPage = 1;
    renderRegistrationsTable();
}

function onRegMonthChange() {
    regCurrentMonth = document.getElementById('reg-filter-month')?.value || '';
    regCurrentPage = 1;
    renderRegistrationsTable();
}

function onRegPageSizeChange() {
    const val = document.getElementById('reg-page-size')?.value || '25';
    regPageSize = val === 'all' ? 999999 : parseInt(val, 10);
    regCurrentPage = 1;
    renderRegistrationsTable();
}

function goToRegPage(p) {
    regCurrentPage = p;
    renderRegistrationsTable();
}

function populateRegMonths(records) {
    const monthSelect = document.getElementById('reg-filter-month');
    if (!monthSelect) return;
    const currentVal = monthSelect.value;
    const monthsSet = new Set();

    records.forEach(r => {
        if (r.created_at) {
            const d = new Date(r.created_at * 1000);
            const yyyy = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            monthsSet.add(`${yyyy}-${mm}`);
        }
    });

    const sortedMonths = Array.from(monthsSet).sort().reverse();
    let opts = '<option value="">All Months</option>';
    sortedMonths.forEach(m => {
        const [year, month] = m.split('-');
        const monthName = new Date(parseInt(year, 10), parseInt(month, 10) - 1, 1).toLocaleString('default', { month: 'long' });
        opts += `<option value="${m}">${monthName} ${year}</option>`;
    });
    monthSelect.innerHTML = opts;
    if (monthsSet.has(currentVal)) {
        monthSelect.value = currentVal;
    }
}

// Override / Enhance fetchRegistrations to support client-side filtering, search, and pagination
async function fetchRegistrations(filter = 'all') {
    currentRegFilter = filter;
    regCurrentFilter = filter;

    const tbody = document.getElementById('registrations-table-body');
    try {
        const res = await fetch(`${API_BASE}/registrations/requests?status_filter=all&_t=${Date.now()}`);
        const data = await res.json();

        if (res.ok && data.requests) {
            cachedRegistrations = data.requests;

            // Update stats
            let pendingCount = 0;
            let autoCount = 0;
            cachedRegistrations.forEach(r => {
                if (r.status === 'PENDING_APPROVAL') pendingCount++;
                if (r.status === 'VERIFIED_AUTO_PROVISIONED') autoCount++;
            });
            const statPending = document.getElementById('reg-stat-pending');
            const statAuto = document.getElementById('reg-stat-auto');
            if (statPending) statPending.innerText = pendingCount;
            if (statAuto) statAuto.innerText = autoCount;

            populateRegMonths(cachedRegistrations);
            renderRegistrationsTable();
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-4 text-center text-rose-400">Failed to load registration queue: ${err}</td></tr>`;
    }
}

function renderRegistrationsTable() {
    const tbody = document.getElementById('registrations-table-body');
    if (!tbody) return;

    let filtered = cachedRegistrations.filter(r => {
        // Status filter
        if (regCurrentFilter !== 'all' && r.status !== regCurrentFilter) return false;

        // Month filter
        if (regCurrentMonth && r.created_at) {
            const d = new Date(r.created_at * 1000);
            const mStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            if (mStr !== regCurrentMonth) return false;
        }

        // Live search query
        if (regSearchQuery) {
            const haystack = `${r.username || ''} ${r.given_name || ''} ${r.surname || ''} ${r.mobile || ''} ${r.email || ''} ${r.department || ''}`.toLowerCase();
            if (!haystack.includes(regSearchQuery)) return false;
        }

        return true;
    });

    const totalItems = filtered.length;
    const totalPages = Math.ceil(totalItems / regPageSize) || 1;
    if (regCurrentPage > totalPages) regCurrentPage = totalPages;
    if (regCurrentPage < 1) regCurrentPage = 1;

    const startIdx = (regCurrentPage - 1) * regPageSize;
    const pagedItems = filtered.slice(startIdx, startIdx + regPageSize);

    // Update pagination info
    const info = document.getElementById('reg-pagination-info');
    if (info) {
        const startDisp = totalItems === 0 ? 0 : startIdx + 1;
        const endDisp = Math.min(startIdx + regPageSize, totalItems);
        info.innerText = `Showing ${startDisp} to ${endDisp} of ${totalItems} entries`;
    }

    // Prev / Next button state
    const prevBtn = document.getElementById('reg-btn-prev');
    const nextBtn = document.getElementById('reg-btn-next');
    if (prevBtn) prevBtn.disabled = regCurrentPage <= 1;
    if (nextBtn) nextBtn.disabled = regCurrentPage >= totalPages;

    // Render numbered page buttons
    renderPaginationButtons('reg-page-numbers', regCurrentPage, totalPages, 'goToRegPage');

    if (totalItems === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No registration requests found matching current filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = pagedItems.map(r => {
        let statusBadge = '';
        if (r.status === 'VERIFIED_AUTO_PROVISIONED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold">OTP AUTO-PROVISIONED</span>';
        } else if (r.status === 'PENDING_APPROVAL') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800 font-semibold animate-pulse">PENDING REVIEW</span>';
        } else if (r.status === 'PENDING_OTP') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800">AWAITING OTP</span>';
        } else if (r.status === 'APPROVED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800">APPROVED BY ADMIN</span>';
        } else if (r.status === 'REJECTED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800">REJECTED</span>';
        } else {
            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">${r.status}</span>`;
        }

        const dateStr = r.created_at ? new Date(r.created_at * 1000).toLocaleString() : '-';

        let actionButtons = '';
        if (r.status === 'PENDING_APPROVAL') {
            actionButtons = `
                <button onclick="approveRegistration(${r.id}, '${r.username}')" class="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-sans font-semibold text-[11px] transition mr-1" title="Approve & Provision into AD">
                    <i class="fa-solid fa-check"></i> Approve
                </button>
                <button onclick="rejectRegistration(${r.id}, '${r.username}')" class="px-2 py-1 rounded bg-rose-600/20 hover:bg-rose-600/40 text-rose-300 border border-rose-500/30 font-sans text-[11px] transition mr-1" title="Reject Request">
                    <i class="fa-solid fa-xmark"></i> Reject
                </button>
            `;
        } else if (r.status === 'VERIFIED_AUTO_PROVISIONED' || r.status === 'APPROVED') {
            actionButtons = `
                <button onclick="openChangeUpnModal('${r.username}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 text-[10px] transition mr-1" title="Change UserPrincipalName (UPN)">
                    <i class="fa-solid fa-at"></i> UPN
                </button>
            `;
        }
        actionButtons += `
            <button onclick="deleteRegistration(${r.id}, '${r.username}')" class="text-slate-500 hover:text-rose-400 transition ml-1" title="Delete Log Entry">
                <i class="fa-solid fa-trash-can"></i>
            </button>
        `;

        return `
            <tr class="hover:bg-slate-800/30">
                <td class="px-4 py-3">
                    <div class="font-bold text-white">${r.username}</div>
                    <div class="text-[10px] text-slate-400">${r.given_name || ''} ${r.surname || ''}</div>
                </td>
                <td class="px-4 py-3 text-cyan-300 font-mono text-xs">${r.mobile || '-'}</td>
                <td class="px-4 py-3 text-slate-300 font-sans">${r.email || '-'}</td>
                <td class="px-4 py-3 text-slate-400 font-sans">${r.department || '-'}</td>
                <td class="px-4 py-3 whitespace-nowrap">${statusBadge}</td>
                <td class="px-4 py-3 text-slate-500 font-mono text-[10px]">${dateStr}</td>
                <td class="px-4 py-3 text-right whitespace-nowrap">${actionButtons}</td>
            </tr>
        `;
    }).join('');
}

function exportRegistrationLogs() {
    const params = new URLSearchParams();
    if (regCurrentFilter && regCurrentFilter !== 'all') params.append('status_filter', regCurrentFilter);
    if (regCurrentMonth) params.append('month', regCurrentMonth);
    if (regSearchQuery) params.append('search', regSearchQuery);

    const token = localStorage.getItem('zclockid_token');
    const url = `/api/v1/self-service/registrations/export?${params.toString()}`;
    
    // Download via fetch or link
    fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => res.blob())
    .then(blob => {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `zclockid_registrations_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(err => alert(`Failed to export registrations: ${err}`));
}

// ==================== SELF SERVICE PASSWORD RESET (SSPR) STATE ====================
let cachedSspprLogs = [];
let ssprCurrentMethod = 'all';
let ssprCurrentStatus = 'all';
let ssprCurrentMonth = '';
let ssprSearchQuery = '';
let ssprCurrentPage = 1;
let ssprPageSize = 25;

function setSspprMethodFilter(method) {
    ssprCurrentMethod = method;
    ['all', 'OLD_PASSWORD', 'EMAIL_OTP', 'SMS_OTP'].forEach(m => {
        const b = document.getElementById(`sspr-method-${m}`);
        if (b) {
            if (m === method) {
                b.className = 'px-2.5 py-1 rounded-md text-[11px] font-semibold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30';
            } else {
                b.className = 'px-2.5 py-1 rounded-md text-[11px] text-slate-400 hover:text-white hover:bg-slate-800';
            }
        }
    });
    ssprCurrentPage = 1;
    renderSspprTable();
}

function onSspprStatusChange() {
    ssprCurrentStatus = document.getElementById('sspr-filter-status')?.value || 'all';
    ssprCurrentPage = 1;
    renderSspprTable();
}

function onSspprMonthChange() {
    ssprCurrentMonth = document.getElementById('sspr-filter-month')?.value || '';
    ssprCurrentPage = 1;
    renderSspprTable();
}

function onSspprSearchInput() {
    ssprSearchQuery = document.getElementById('sspr-search-input')?.value.trim().toLowerCase() || '';
    ssprCurrentPage = 1;
    renderSspprTable();
}

function onSspprPageSizeChange() {
    const val = document.getElementById('sspr-page-size')?.value || '25';
    ssprPageSize = val === 'all' ? 999999 : parseInt(val, 10);
    ssprCurrentPage = 1;
    renderSspprTable();
}

function goToSspprPage(p) {
    ssprCurrentPage = p;
    renderSspprTable();
}

function populateSspprMonths(records) {
    const monthSelect = document.getElementById('sspr-filter-month');
    if (!monthSelect) return;
    const currentVal = monthSelect.value;
    const monthsSet = new Set();

    records.forEach(r => {
        if (r.created_at) {
            const d = new Date(r.created_at * 1000);
            const yyyy = d.getFullYear();
            const mm = String(d.getMonth() + 1).padStart(2, '0');
            monthsSet.add(`${yyyy}-${mm}`);
        }
    });

    const sortedMonths = Array.from(monthsSet).sort().reverse();
    let opts = '<option value="">All Months</option>';
    sortedMonths.forEach(m => {
        const [year, month] = m.split('-');
        const monthName = new Date(parseInt(year, 10), parseInt(month, 10) - 1, 1).toLocaleString('default', { month: 'long' });
        opts += `<option value="${m}">${monthName} ${year}</option>`;
    });
    monthSelect.innerHTML = opts;
    if (monthsSet.has(currentVal)) {
        monthSelect.value = currentVal;
    }
}

async function fetchSspprLogs() {
    const tbody = document.getElementById('sspr-table-body');
    const token = localStorage.getItem('zclockid_token');

    try {
        const res = await fetch(`/api/v1/self-service/password/logs?limit=500&_t=${Date.now()}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();

        if (res.ok && data.logs) {
            cachedSspprLogs = data.logs;

            // Update Metric Cards
            const total = data.count ?? cachedSspprLogs.length;
            const completed = data.total_completed ?? cachedSspprLogs.filter(l => l.status === 'COMPLETED').length;
            let countOld = 0;
            let countOtp = 0;

            cachedSspprLogs.forEach(l => {
                if (l.method === 'OLD_PASSWORD') countOld++;
                else if (l.method === 'EMAIL_OTP' || l.method === 'SMS_OTP') countOtp++;
            });

            document.getElementById('sspr-stat-total').innerText = total;
            document.getElementById('sspr-stat-completed').innerText = completed;
            document.getElementById('sspr-stat-old').innerText = countOld;
            document.getElementById('sspr-stat-otp').innerText = countOtp;

            populateSspprMonths(cachedSspprLogs);
            renderSspprTable();
        }
    } catch (err) {
        if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-4 text-center text-rose-400">Failed to load SSPR activity logs: ${err}</td></tr>`;
    }
}

function renderSspprTable() {
    const tbody = document.getElementById('sspr-table-body');
    if (!tbody) return;

    let filtered = cachedSspprLogs.filter(l => {
        // Method filter
        if (ssprCurrentMethod !== 'all' && l.method !== ssprCurrentMethod) return false;

        // Status filter
        if (ssprCurrentStatus !== 'all' && l.status !== ssprCurrentStatus) return false;

        // Month filter
        if (ssprCurrentMonth && l.created_at) {
            const d = new Date(l.created_at * 1000);
            const mStr = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
            if (mStr !== ssprCurrentMonth) return false;
        }

        // Live search query
        if (ssprSearchQuery) {
            const haystack = `${l.username || ''} ${l.recipient || ''} ${l.ip_address || ''} ${l.notes || ''} ${l.method || ''} ${l.status || ''}`.toLowerCase();
            if (!haystack.includes(ssprSearchQuery)) return false;
        }

        return true;
    });

    const totalItems = filtered.length;
    const totalPages = Math.ceil(totalItems / ssprPageSize) || 1;
    if (ssprCurrentPage > totalPages) ssprCurrentPage = totalPages;
    if (ssprCurrentPage < 1) ssprCurrentPage = 1;

    const startIdx = (ssprCurrentPage - 1) * ssprPageSize;
    const pagedItems = filtered.slice(startIdx, startIdx + ssprPageSize);

    // Update pagination info
    const info = document.getElementById('sspr-pagination-info');
    if (info) {
        const startDisp = totalItems === 0 ? 0 : startIdx + 1;
        const endDisp = Math.min(startIdx + ssprPageSize, totalItems);
        info.innerText = `Showing ${startDisp} to ${endDisp} of ${totalItems} entries`;
    }

    // Prev / Next button state
    const prevBtn = document.getElementById('sspr-btn-prev');
    const nextBtn = document.getElementById('sspr-btn-next');
    if (prevBtn) prevBtn.disabled = ssprCurrentPage <= 1;
    if (nextBtn) nextBtn.disabled = ssprCurrentPage >= totalPages;

    // Render numbered page buttons
    renderPaginationButtons('sspr-page-numbers', ssprCurrentPage, totalPages, 'goToSspprPage');

    if (totalItems === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-8 text-center text-slate-500 font-sans">No password reset activity found matching current filters.</td></tr>`;
        return;
    }

    tbody.innerHTML = pagedItems.map(l => {
        let methodBadge = '';
        if (l.method === 'OLD_PASSWORD') {
            methodBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono"><i class="fa-solid fa-lock text-[9px] mr-1"></i>Current Password</span>';
        } else if (l.method === 'EMAIL_OTP') {
            methodBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-purple-950 text-purple-300 border border-purple-800 font-mono"><i class="fa-solid fa-envelope text-[9px] mr-1"></i>Email OTP</span>';
        } else if (l.method === 'SMS_OTP') {
            methodBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono"><i class="fa-solid fa-mobile-screen text-[9px] mr-1"></i>SMS OTP</span>';
        } else {
            methodBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">${l.method}</span>`;
        }

        let statusBadge = '';
        if (l.status === 'COMPLETED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold"><i class="fa-solid fa-check text-[9px] mr-1"></i>COMPLETED</span>';
        } else if (l.status === 'PENDING_OTP') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-cyan-950 text-cyan-300 border border-cyan-800 animate-pulse"><i class="fa-solid fa-hourglass-half text-[9px] mr-1"></i>PENDING OTP</span>';
        } else if (l.status === 'FAILED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-300 border border-rose-800"><i class="fa-solid fa-xmark text-[9px] mr-1"></i>FAILED</span>';
        } else if (l.status === 'EXPIRED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-[10px] bg-amber-950 text-amber-300 border border-amber-800"><i class="fa-solid fa-clock text-[9px] mr-1"></i>EXPIRED</span>';
        } else {
            statusBadge = `<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400">${l.status}</span>`;
        }

        const dateStr = l.created_at ? new Date(l.created_at * 1000).toLocaleString() : '-';

        return `
            <tr class="hover:bg-slate-800/30">
                <td class="px-4 py-3 text-slate-400 font-mono whitespace-nowrap text-[10px]">${dateStr}</td>
                <td class="px-4 py-3 font-bold text-white font-mono">${l.username}</td>
                <td class="px-4 py-3 whitespace-nowrap">${methodBadge}</td>
                <td class="px-4 py-3 font-mono text-slate-300">${l.recipient || '-'}</td>
                <td class="px-4 py-3 whitespace-nowrap">${statusBadge}</td>
                <td class="px-4 py-3 text-cyan-300 font-mono text-xs">${l.ip_address || '-'}</td>
                <td class="px-4 py-3 text-slate-400 font-sans max-w-xs truncate" title="${l.notes || ''}">${l.notes || '-'}</td>
            </tr>
        `;
    }).join('');
}

function copyPasswordResetLink() {
    const url = `${window.location.origin}/password-reset.html`;
    navigator.clipboard.writeText(url).then(() => {
        alert(`Self-Service Password Reset portal link copied to clipboard:\n${url}`);
    }).catch(() => {
        prompt("Copy this public portal link:", url);
    });
}

function exportSspprLogs() {
    const params = new URLSearchParams();
    if (ssprCurrentMethod && ssprCurrentMethod !== 'all') params.append('method', ssprCurrentMethod);
    if (ssprCurrentStatus && ssprCurrentStatus !== 'all') params.append('status', ssprCurrentStatus);
    if (ssprCurrentMonth) params.append('month', ssprCurrentMonth);
    if (ssprSearchQuery) params.append('search', ssprSearchQuery);

    const token = localStorage.getItem('zclockid_token');
    const url = `/api/v1/self-service/password/logs/export?${params.toString()}`;

    fetch(url, {
        headers: { 'Authorization': `Bearer ${token}` }
    })
    .then(res => res.blob())
    .then(blob => {
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `zclockid_sspr_logs_${new Date().toISOString().slice(0, 10)}.csv`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    })
    .catch(err => alert(`Failed to export SSPR logs: ${err}`));
}

// ==================== SSPR SETTINGS MODAL ====================
function openSspprSettingsModal() {
    fetchSspprSettings();
    document.getElementById('modal-self-service-password-settings')?.classList.remove('hidden');
}

function closeSspprSettingsModal() {
    document.getElementById('modal-self-service-password-settings')?.classList.add('hidden');
}

function toggleSspprSmtpFields() {
    const enabled = document.getElementById('sspr-cfg-smtp-enabled')?.checked;
    const sec = document.getElementById('sec-sspr-smtp-fields');
    if (sec) {
        if (enabled) sec.classList.remove('hidden');
        else sec.classList.add('hidden');
    }
}

function toggleSspprSmsFields() {
    const type = document.getElementById('sspr-cfg-sms-type')?.value;
    const sec = document.getElementById('sec-sspr-sms-ext');
    if (sec) {
        if (type === 'simulated') sec.classList.add('hidden');
        else sec.classList.remove('hidden');
    }
}

async function fetchSspprSettings() {
    const token = localStorage.getItem('zclockid_token');
    try {
        const res = await fetch('/api/v1/self-service/password/settings', {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const data = await res.json();
        if (res.ok && data.settings) {
            const s = data.settings;
            document.getElementById('sspr-cfg-enabled').checked = Boolean(s.enabled);
            document.getElementById('sspr-cfg-allow-old').checked = Boolean(s.allow_old_password_reset);
            document.getElementById('sspr-cfg-allow-email').checked = Boolean(s.allow_email_reset);
            document.getElementById('sspr-cfg-allow-otp').checked = Boolean(s.allow_otp_reset);

            document.getElementById('sspr-cfg-min-len').value = s.min_password_length || 8;
            document.getElementById('sspr-cfg-complexity').checked = Boolean(s.require_complexity);
            document.getElementById('sspr-cfg-otp-expiry').value = s.otp_expiry_minutes || 10;
            document.getElementById('sspr-cfg-max-attempts').value = s.max_daily_attempts || 5;

            document.getElementById('sspr-cfg-smtp-enabled').checked = Boolean(s.email_smtp_enabled);
            document.getElementById('sspr-cfg-smtp-host').value = s.smtp_host || '';
            document.getElementById('sspr-cfg-smtp-port').value = s.smtp_port || 587;
            document.getElementById('sspr-cfg-smtp-user').value = s.smtp_user || '';
            document.getElementById('sspr-cfg-smtp-pass').value = s.smtp_pass || '';
            document.getElementById('sspr-cfg-smtp-from').value = s.smtp_from || '';
            toggleSspprSmtpFields();

            document.getElementById('sspr-cfg-sms-type').value = s.sms_gateway_type || 'simulated';
            document.getElementById('sspr-cfg-sender').value = s.sms_sender_id || 'ZCLOCK';
            document.getElementById('sspr-cfg-sms-url').value = s.sms_gateway_url || '';
            document.getElementById('sspr-cfg-sms-key').value = s.sms_api_key || '';
            document.getElementById('sspr-cfg-sms-template').value = s.sms_template || 'Your ZclockID password reset verification code is {otp}. Valid for 10 minutes.';
            toggleSspprSmsFields();
        }
    } catch (err) {
        console.error("Failed to load SSPR settings:", err);
    }
}

async function saveSspprSettings(e) {
    e.preventDefault();
    const btn = document.getElementById('btn-save-sspr-settings');
    btn.disabled = true;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving...`;

    const token = localStorage.getItem('zclockid_token');
    const payload = {
        enabled: document.getElementById('sspr-cfg-enabled').checked,
        allow_old_password_reset: document.getElementById('sspr-cfg-allow-old').checked,
        allow_email_reset: document.getElementById('sspr-cfg-allow-email').checked,
        allow_otp_reset: document.getElementById('sspr-cfg-allow-otp').checked,
        min_password_length: parseInt(document.getElementById('sspr-cfg-min-len').value, 10) || 8,
        require_complexity: document.getElementById('sspr-cfg-complexity').checked,
        otp_expiry_minutes: parseInt(document.getElementById('sspr-cfg-otp-expiry').value, 10) || 10,
        max_daily_attempts: parseInt(document.getElementById('sspr-cfg-max-attempts').value, 10) || 5,
        email_smtp_enabled: document.getElementById('sspr-cfg-smtp-enabled').checked,
        smtp_host: document.getElementById('sspr-cfg-smtp-host').value.trim(),
        smtp_port: parseInt(document.getElementById('sspr-cfg-smtp-port').value, 10) || 587,
        smtp_user: document.getElementById('sspr-cfg-smtp-user').value.trim(),
        smtp_pass: document.getElementById('sspr-cfg-smtp-pass').value.trim(),
        smtp_from: document.getElementById('sspr-cfg-smtp-from').value.trim(),
        sms_gateway_type: document.getElementById('sspr-cfg-sms-type').value,
        sms_gateway_url: document.getElementById('sspr-cfg-sms-url').value.trim(),
        sms_api_key: document.getElementById('sspr-cfg-sms-key').value.trim(),
        sms_sender_id: document.getElementById('sspr-cfg-sender').value.trim(),
        sms_template: document.getElementById('sspr-cfg-sms-template').value.trim()
    };

    try {
        const res = await fetch('/api/v1/self-service/password/settings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok) {
            alert('Self-Service Password Reset settings updated successfully!');
            closeSspprSettingsModal();
        } else {
            alert(`Failed to save SSPR settings: ${data.detail || 'Unknown error'}`);
        }
    } catch (err) {
        alert(`Error saving SSPR settings: ${err}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save SSPR Settings`;
    }
}

async function sendTestSms(prefix) {
    const mobileInput = document.getElementById(`${prefix}-test-sms-mobile`);
    const mobile = mobileInput ? mobileInput.value.trim() : '';
    if (!mobile) {
        alert('Please enter a destination mobile number (e.g. +919582889339) to send a test SMS.');
        return;
    }

    const btn = document.getElementById(`btn-${prefix}-test-sms`);
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Sending...`;
    }

    const token = localStorage.getItem('zclockid_token');
    const payload = {
        mobile: mobile,
        sms_gateway_type: document.getElementById(`${prefix}-cfg-sms-type`)?.value || 'simulated',
        sms_gateway_url: document.getElementById(`${prefix}-cfg-sms-url`)?.value.trim() || '',
        sms_api_key: document.getElementById(`${prefix}-cfg-sms-key`)?.value.trim() || '',
        sms_sender_id: document.getElementById(`${prefix}-cfg-sender`)?.value.trim() || 'ZCLOCK',
        sms_template: document.getElementById(`${prefix}-cfg-sms-template`)?.value.trim() || ''
    };

    try {
        const res = await fetch('/api/v1/self-service/test-sms', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (res.ok) {
            alert(data.message || 'Test SMS sent successfully!');
        } else {
            alert(`Test SMS failed: ${data.detail || 'Unknown error'}`);
        }
    } catch (err) {
        alert(`Error sending test SMS: ${err}`);
    } finally {
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-paper-plane"></i> Send Test SMS`;
        }
    }
}

