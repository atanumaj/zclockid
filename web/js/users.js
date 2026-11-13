        function switchDirectorySubtab(subtab) {
            currentDirectorySubtab = subtab;
            const subtabs = ['users', 'groups', 'computers'];
            subtabs.forEach(t => {
                const btn = document.getElementById(`btn-subtab-${t}`);
                const pane = document.getElementById(`dir-pane-${t}`);
                if (btn && pane) {
                    if (t === subtab) {
                        btn.className = 'px-4 py-2 rounded-lg text-xs font-semibold bg-indigo-600/20 text-indigo-400 border border-indigo-500/30 flex items-center gap-2 transition whitespace-nowrap shrink-0';
                        pane.classList.remove('hidden');
                    } else {
                        btn.className = 'px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-slate-200 hover:bg-slate-800/50 border border-transparent flex items-center gap-2 transition whitespace-nowrap shrink-0';
                        pane.classList.add('hidden');
                    }
                }
            });

            if (subtab === 'users') fetchUsers();
            else if (subtab === 'groups') fetchGroups();
            else if (subtab === 'computers') fetchComputers();
        }

        // ==================== Search, Sort & Pagination State ====================
        let usersSearchQuery = '';
        let usersSortCol = 'username';
        let usersSortDir = 'asc';
        let usersCurrentPage = 1;
        let usersPageSize = 25;

        let groupsSearchQuery = '';
        let groupsSortCol = 'group_name';
        let groupsSortDir = 'asc';
        let groupsCurrentPage = 1;
        let groupsPageSize = 25;

        let computersSearchQuery = '';
        let computersSortCol = 'name';
        let computersSortDir = 'asc';
        let computersCurrentPage = 1;
        let computersPageSize = 25;

        function updateTableSortIcons(prefix, activeCol, dir) {
            document.querySelectorAll(`[id^="sort-icon-${prefix}-"]`).forEach(icon => {
                icon.className = 'fa-solid fa-sort text-slate-600 group-hover:text-slate-400 text-[10px]';
            });
            const activeIcon = document.getElementById(`sort-icon-${prefix}-${activeCol}`);
            if (activeIcon) {
                activeIcon.className = `fa-solid fa-sort-${dir === 'asc' ? 'up' : 'down'} text-indigo-400 text-[10px]`;
            }
        }

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
                    return `<button class="px-2.5 py-1 rounded-md bg-indigo-600 text-white font-bold text-xs shadow-sm shadow-indigo-600/40 select-none">${escapeHtml(p)}</button>`;
                } else {
                    return `<button data-action="go-to-page" data-page-fn="${escapeHtml(goToPageFnName)}" data-page="${escapeHtml(p)}" class="px-2.5 py-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 font-medium text-xs transition">${escapeHtml(p)}</button>`;
                }
            }).join('');
        }

        function goToUsersPage(p) {
            usersCurrentPage = p;
            renderUsersTable();
        }

        function sortUsersBy(col) {
            if (usersSortCol === col) {
                usersSortDir = (usersSortDir === 'asc') ? 'desc' : 'asc';
            } else {
                usersSortCol = col;
                usersSortDir = 'asc';
            }
            usersCurrentPage = 1;
            renderUsersTable();
        }

        function onUsersSearchInput() {
            const input = document.getElementById('users-search-input');
            usersSearchQuery = input ? input.value : '';
            const clearBtn = document.getElementById('users-search-clear');
            if (clearBtn) clearBtn.classList.toggle('hidden', !usersSearchQuery);
            usersCurrentPage = 1;
            renderUsersTable();
        }

        function clearUsersSearch() {
            const input = document.getElementById('users-search-input');
            if (input) input.value = '';
            usersSearchQuery = '';
            const clearBtn = document.getElementById('users-search-clear');
            if (clearBtn) clearBtn.classList.add('hidden');
            usersCurrentPage = 1;
            renderUsersTable();
        }

        function onUsersPageSizeChange() {
            const sel = document.getElementById('users-page-size');
            usersPageSize = sel ? parseInt(sel.value, 10) : 25;
            usersCurrentPage = 1;
            renderUsersTable();
        }

        function prevUsersPage() {
            if (usersCurrentPage > 1) {
                usersCurrentPage--;
                renderUsersTable();
            }
        }

        function nextUsersPage() {
            usersCurrentPage++;
            renderUsersTable();
        }

        function renderUsersTable() {
            const chk = document.getElementById('chk-show-system-users');
            const showSystem = chk ? chk.checked : false;
            // Always keep Administrator + all normal domain users. Hide krbtgt, Guest, and dns-* unless checkbox is checked.
            const baseUsers = showSystem 
                ? (globalUsers || []) 
                : (globalUsers || []).filter(u => !u.is_system_hidden && u.username.toLowerCase() !== 'krbtgt' && u.username.toLowerCase() !== 'guest' && !u.username.toLowerCase().startsWith('dns-'));

            const badge = document.getElementById('badge-users-count');
            if (badge) {
                badge.innerText = `${baseUsers.length}`;
            }

            // Search filter
            let filtered = [...baseUsers];
            const q = (usersSearchQuery || '').toLowerCase().trim();
            if (q) {
                filtered = filtered.filter(u => {
                    const uName = (u.username || '').toLowerCase();
                    const fName = (u.name || `${u.given_name || ''} ${u.surname || ''}`).toLowerCase();
                    const upn = (u.user_principal_name || '').toLowerCase();
                    const email = (u.email || '').toLowerCase();
                    const mobile = (u.mobile || '').toLowerCase();
                    const dept = (u.department || '').toLowerCase();
                    const grps = Array.isArray(u.groups) ? u.groups.join(' ').toLowerCase() : '';
                    const ubw = (u.bandwidth_profile_name || '').toLowerCase();
                    const gbw = (u.group_bandwidth_profile_name || '').toLowerCase();
                    const stat = (u.status || '').toLowerCase();
                    return uName.includes(q) || fName.includes(q) || upn.includes(q) ||
                           email.includes(q) || mobile.includes(q) || dept.includes(q) ||
                           grps.includes(q) || ubw.includes(q) || gbw.includes(q) || stat.includes(q);
                });
            }

            // Sorting
            filtered.sort((a, b) => {
                let valA = '';
                let valB = '';
                if (usersSortCol === 'username') {
                    valA = (a.username || '').toLowerCase();
                    valB = (b.username || '').toLowerCase();
                } else if (usersSortCol === 'name') {
                    valA = (a.name || `${a.given_name || ''} ${a.surname || ''}`).toLowerCase();
                    valB = (b.name || `${b.given_name || ''} ${b.surname || ''}`).toLowerCase();
                } else if (usersSortCol === 'department') {
                    valA = (a.department || '').toLowerCase();
                    valB = (b.department || '').toLowerCase();
                } else if (usersSortCol === 'user_bw') {
                    valA = (a.bandwidth_profile_name || '').toLowerCase();
                    valB = (b.bandwidth_profile_name || '').toLowerCase();
                } else if (usersSortCol === 'group_bw') {
                    valA = (a.group_bandwidth_profile_name || '').toLowerCase();
                    valB = (b.group_bandwidth_profile_name || '').toLowerCase();
                } else if (usersSortCol === 'status') {
                    valA = (a.status || '').toLowerCase();
                    valB = (b.status || '').toLowerCase();
                }

                if (valA < valB) return usersSortDir === 'asc' ? -1 : 1;
                if (valA > valB) return usersSortDir === 'asc' ? 1 : -1;
                return 0;
            });

            updateTableSortIcons('user', usersSortCol, usersSortDir);

            // Pagination calculations
            const totalCount = filtered.length;
            let pageItems = filtered;
            let totalPages = 1;

            if (usersPageSize > 0 && totalCount > 0) {
                totalPages = Math.max(1, Math.ceil(totalCount / usersPageSize));
                if (usersCurrentPage > totalPages) usersCurrentPage = totalPages;
                if (usersCurrentPage < 1) usersCurrentPage = 1;
                const startIdx = (usersCurrentPage - 1) * usersPageSize;
                pageItems = filtered.slice(startIdx, startIdx + usersPageSize);
            } else {
                usersCurrentPage = 1;
            }

            // Stats label
            const statsEl = document.getElementById('users-filter-stats');
            if (statsEl) {
                if (q) {
                    statsEl.innerText = `Showing ${filtered.length} of ${baseUsers.length} (filtered)`;
                } else if (usersPageSize > 0 && baseUsers.length > usersPageSize) {
                    const startNum = ((usersCurrentPage - 1) * usersPageSize) + 1;
                    const endNum = Math.min(usersCurrentPage * usersPageSize, totalCount);
                    statsEl.innerText = `Showing ${startNum}-${endNum} of ${totalCount}`;
                } else {
                    statsEl.innerText = `Showing ${totalCount} of ${baseUsers.length}`;
                }
            }

            // Pagination Controls
            const paginationBar = document.getElementById('users-pagination');
            const pageInfo = document.getElementById('users-pagination-info');
            const prevBtn = document.getElementById('users-prev-btn');
            const nextBtn = document.getElementById('users-next-btn');
            if (paginationBar && pageInfo && prevBtn && nextBtn) {
                if (usersPageSize === 0 || totalCount <= usersPageSize) {
                    paginationBar.classList.add('hidden');
                } else {
                    paginationBar.classList.remove('hidden');
                    pageInfo.innerText = `Page ${usersCurrentPage} of ${totalPages} (${totalCount} users)`;
                    prevBtn.disabled = (usersCurrentPage <= 1);
                    nextBtn.disabled = (usersCurrentPage >= totalPages);
                    renderPaginationButtons('users-page-numbers', usersCurrentPage, totalPages, 'goToUsersPage');
                }
            }

            const tbody = document.getElementById('users-table-body');
            if (!tbody) return;

            if (pageItems.length > 0) {
                tbody.innerHTML = pageItems.map(u => {
                    const nameDisplay = escapeHtml(u.name || u.username);
                    const safeUsername = escapeHtml(u.username);
                    const contactDetails = [];
                    if (u.email) contactDetails.push(`<span class="font-mono text-[10px] text-slate-400"><i class="fa-solid fa-envelope text-slate-500 mr-1"></i>${escapeHtml(u.email)}</span>`);
                    if (u.mobile) contactDetails.push(`<span class="font-mono text-[10px] text-slate-400"><i class="fa-solid fa-phone text-slate-500 mr-1"></i>${escapeHtml(u.mobile)}</span>`);
                    
                    // 1. Explicit User Bandwidth Override
                    let userBwBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-sans text-slate-500 bg-slate-950 border border-slate-800 flex items-center gap-1 w-max"><i class="fa-solid fa-minus text-slate-600"></i> None</span>';
                    if (u.bandwidth_profile_name) {
                        const safeBwName = escapeHtml(u.bandwidth_profile_name);
                        const safeBwRate = escapeHtml(u.bandwidth_rate || '');
                        userBwBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-sans font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1 w-max" title="Explicit User Override (takes precedence) - WISPr/MikroTik: ${safeBwRate}"><i class="fa-solid fa-user-shield text-cyan-400"></i> ${safeBwName} (${safeBwRate})</span>`;
                    }

                    // 2. Inherited Group Bandwidth Policy
                    let groupBwBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-sans text-slate-500 bg-slate-950 border border-slate-800 flex items-center gap-1 w-max"><i class="fa-solid fa-minus text-slate-600"></i> None</span>';
                    let bestGroup = null;
                    if (u.group_bandwidth_profile_name && u.group_bandwidth_group) {
                        bestGroup = {
                            group_name: u.group_bandwidth_group,
                            bandwidth_profile_name: u.group_bandwidth_profile_name,
                            bandwidth_rate: u.group_bandwidth_rate || ''
                        };
                    } else if (u.groups && u.groups.length > 0 && Array.isArray(globalGroups)) {
                        const matchingGroupsWithBw = [];
                        u.groups.forEach(grpName => {
                            const found = globalGroups.find(g => g.group_name && g.group_name.toLowerCase() === grpName.toLowerCase() && g.bandwidth_profile_name);
                            if (found) matchingGroupsWithBw.push(found);
                        });

                        if (matchingGroupsWithBw.length > 0) {
                            bestGroup = matchingGroupsWithBw[0];
                            if (matchingGroupsWithBw.length > 1 && Array.isArray(globalBandwidthProfiles)) {
                                const getSpeed = (grp) => {
                                    const prof = globalBandwidthProfiles.find(p => p.id === grp.bandwidth_profile_id || (p.name && p.name.toLowerCase() === grp.bandwidth_profile_name.toLowerCase()));
                                    if (!prof) return 0;
                                    const d = prof.download_mbps;
                                    return (d === 0 || d === null || d === undefined) ? Infinity : d;
                                };
                                matchingGroupsWithBw.sort((a, b) => getSpeed(b) - getSpeed(a));
                                bestGroup = matchingGroupsWithBw[0];
                            }
                        }
                    }

                    if (bestGroup) {
                        const safeBestGroupName = escapeHtml(bestGroup.group_name);
                        const safeBestBwName = escapeHtml(bestGroup.bandwidth_profile_name);
                        const safeBestBwRate = escapeHtml(bestGroup.bandwidth_rate || '');
                        groupBwBadge = `
                            <div>
                                <span class="px-2 py-0.5 rounded text-[10px] font-sans font-semibold bg-indigo-950 text-indigo-300 border border-indigo-800 flex items-center gap-1 w-max" title="Inherited from group ${safeBestGroupName}${u.bandwidth_profile_name ? ' (User override active)' : ''}">
                                    <i class="fa-solid fa-users text-indigo-400"></i> ${safeBestBwName} (${safeBestBwRate})
                                </span>
                                <div class="text-[9px] text-slate-400 font-mono mt-0.5 flex items-center gap-1">
                                    <span class="text-slate-500">via</span> ${safeBestGroupName}
                                </div>
                            </div>
                        `;
                    }

                    const statusBadge = u.status === 'active'
                        ? '<span class="px-2 py-0.5 rounded text-[10px] bg-emerald-950 text-emerald-400 border border-emerald-800">ACTIVE</span>'
                        : '<span class="px-2 py-0.5 rounded text-[10px] bg-rose-950 text-rose-400 border border-rose-800">DISABLED</span>';

                    const isBuiltin = u.is_built_in;
                    const safeUpn = escapeHtml(u.user_principal_name || '');
                    const safeDept = escapeHtml(u.department || '-');

                    return `
                        <tr class="hover:bg-slate-800/30">
                            <td class="px-4 py-2.5">
                                <div class="font-bold text-white flex items-center gap-1.5 flex-wrap">
                                    <i class="fa-solid fa-user ${isBuiltin ? 'text-amber-400' : 'text-emerald-400'} text-[10px]"></i> ${safeUsername}
                                    ${u.username.toLowerCase() === 'administrator' 
                                        ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-amber-950/70 text-amber-400 border border-amber-800/80 uppercase font-mono font-bold">Domain Admin</span>' 
                                        : (isBuiltin ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 uppercase font-mono">System Account</span>' : '<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-950/70 text-indigo-300 border border-indigo-800/80 uppercase font-mono">Domain User</span>')}
                                    ${u.is_self_registered ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono font-semibold flex items-center gap-1" title="Account created via User Self-Registration Portal"><i class="fa-solid fa-id-badge text-cyan-400"></i> Self-Registered</span>' : ''}
                                </div>
                                <div class="text-[10px] text-indigo-400 font-mono">${safeUpn}</div>
                                ${(u.groups && u.groups.length > 0) ? `
                                    <div class="flex flex-wrap gap-1 mt-1">
                                        ${u.groups.map(g => `<span class="px-1.5 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-800/60 text-[9px] font-mono flex items-center gap-1"><i class="fa-solid fa-users text-[8px] opacity-70"></i>${escapeHtml(g)}</span>`).join('')}
                                    </div>
                                ` : ''}
                            </td>
                            <td class="px-4 py-2.5">
                                <div class="font-semibold text-slate-200">${nameDisplay}</div>
                                <div class="flex flex-col gap-0.5 mt-0.5">${contactDetails.join('')}</div>
                            </td>
                            <td class="px-4 py-2.5">
                                ${isBuiltin ? '<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-amber-400 border border-slate-700 font-mono font-bold flex items-center gap-1 w-max"><i class="fa-solid fa-shield text-amber-400"></i> Built-in</span>' : `<span class="text-slate-300 font-sans">${safeDept}</span>`}
                            </td>
                            <td class="px-4 py-2.5">${userBwBadge}</td>
                            <td class="px-4 py-2.5">${groupBwBadge}</td>
                            <td class="px-4 py-2.5">${statusBadge}</td>
                            <td class="px-4 py-2.5 text-right whitespace-nowrap">
                                <button data-action="edit-user" data-username="${safeUsername}" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-indigo-300 font-sans font-semibold text-[10px] transition mr-1" title="Edit User Account, Credentials & Bandwidth">
                                    <i class="fa-solid fa-user-pen"></i> Edit
                                </button>
                                ${!isBuiltin ? `
                                    <button data-action="delete-user" data-username="${safeUsername}" class="text-slate-500 hover:text-rose-400 ml-1 p-1 transition" title="Delete User">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                ` : '<span class="text-slate-600 font-sans italic text-[10px] ml-1">Built-in</span>'}
                            </td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="7" class="px-4 py-6 text-center font-sans text-slate-500">' + 
                    (q ? 'No domain users matched your search query.' : 'No domain users found. Create one using "+ New User".') + 
                    '</td></tr>';
            }
        }

        async function fetchUsers() {
            try {
                const res = await fetch(`${API_BASE}/users?_t=${Date.now()}`);
                const data = await res.json();
                globalUsers = data.users || [];
                renderUsersTable();
            } catch (err) {
                console.error('Error fetching users:', err);
            }
        }

        function populateGroupCheckboxes(containerId, selectedGroupNames = []) {
            const container = document.getElementById(containerId);
            if (!container) return;

            if (!globalGroups || globalGroups.length === 0) {
                container.innerHTML = '<div class="text-slate-500 italic text-center py-2"><i class="fa-solid fa-spinner fa-spin mr-1"></i> Loading security groups...</div>';
                fetchGroups().then(() => populateGroupCheckboxes(containerId, selectedGroupNames));
                return;
            }

            const selectedNormalized = (selectedGroupNames || []).map(g => (g || '').toLowerCase());

            const sorted = [...globalGroups].sort((a, b) => {
                if (a.is_built_in !== b.is_built_in) {
                    return a.is_built_in ? 1 : -1;
                }
                return a.group_name.localeCompare(b.group_name);
            });

            container.innerHTML = sorted.map(g => {
                const isChecked = selectedNormalized.includes(g.group_name.toLowerCase());
                const safeGroupName = escapeHtml(g.group_name);
                const safeBwName = escapeHtml(g.bandwidth_profile_name || '');
                const safeContainerId = escapeHtml(containerId);
                const bwTag = g.bandwidth_profile_name ? 
                    `<span class="text-[9px] px-1.5 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1"><i class="fa-solid fa-gauge-high text-[8px]"></i> ${safeBwName}</span>` : '';
                const builtinTag = g.is_built_in ?
                    `<span class="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400">Built-in</span>` :
                    `<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">Security</span>`;

                return `
                    <label class="flex items-center justify-between p-1.5 rounded hover:bg-slate-800/70 cursor-pointer border border-transparent hover:border-slate-700 transition">
                        <div class="flex items-center gap-2">
                            <input type="checkbox" name="${safeContainerId}-chk" value="${safeGroupName}" ${isChecked ? 'checked' : ''} class="w-3.5 h-3.5 rounded bg-slate-900 border-slate-700 text-indigo-600 focus:ring-indigo-500">
                            <span class="font-medium text-slate-200">${safeGroupName}</span>
                        </div>
                        <div class="flex items-center gap-1.5">
                            ${bwTag}
                            ${builtinTag}
                        </div>
                    </label>
                `;
            }).join('');
        }

        function openUserModal() {
            populateBandwidthSelects();
            const uInput = document.getElementById('usr-name-input');
            const pInput = document.getElementById('usr-pass-input');
            const gInput = document.getElementById('usr-given-input');
            const sInput = document.getElementById('usr-sur-input');
            const eInput = document.getElementById('usr-email-input');
            const mInput = document.getElementById('usr-mobile-input');
            const dInput = document.getElementById('usr-dept-input');
            const bInput = document.getElementById('usr-bw-profile-input');
            if (uInput) uInput.value = '';
            if (pInput) pInput.value = '';
            if (gInput) gInput.value = '';
            if (sInput) sInput.value = '';
            if (eInput) eInput.value = '';
            if (mInput) mInput.value = '';
            if (dInput) dInput.value = '';
            if (bInput) bInput.value = '0';
            populateGroupCheckboxes('usr-groups-container', []);
            document.getElementById('user-modal').classList.remove('hidden');
        }
        function closeUserModal() { document.getElementById('user-modal').classList.add('hidden'); }

        async function submitCreateUser() {
            const username = document.getElementById('usr-name-input').value.trim();
            const password = document.getElementById('usr-pass-input').value;
            const givenName = document.getElementById('usr-given-input').value.trim();
            const surname = document.getElementById('usr-sur-input').value.trim();
            const email = (document.getElementById('usr-email-input') ? document.getElementById('usr-email-input').value.trim() : '');
            const mobile = (document.getElementById('usr-mobile-input') ? document.getElementById('usr-mobile-input').value.trim() : '');
            const department = document.getElementById('usr-dept-input').value.trim();
            const bwId = parseInt(document.getElementById('usr-bw-profile-input') ? document.getElementById('usr-bw-profile-input').value : 0) || 0;
            const checkedGroups = Array.from(document.querySelectorAll("input[name='usr-groups-container-chk']:checked")).map(cb => cb.value);

            if (!username || !password) return alert('Username and password are required.');

            try {
                const res = await fetch(`${API_BASE}/users`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: username,
                        password: password,
                        given_name: givenName,
                        surname: surname,
                        email: email,
                        mobile: mobile,
                        department: department,
                        bandwidth_profile_id: bwId,
                        groups: checkedGroups
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeUserModal();
                    fetchUsers();
                } else {
                    alert(`Failed to create user: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error creating user: ${err}`);
            }
        }

        // ==================== Edit User Modal Logic ====================
        function openEditUserModal(username) {
            populateBandwidthSelects();
            const u = globalUsers.find(x => x.username.toLowerCase() === username.toLowerCase());
            if (!u) return alert(`User '${username}' not found in active list.`);

            document.getElementById('edit-usr-name').value = u.username;
            document.getElementById('edit-usr-status').value = (u.status === 'disabled' || u.is_disabled) ? 'disabled' : 'active';
            document.getElementById('edit-usr-given').value = u.given_name || '';
            document.getElementById('edit-usr-sur').value = u.surname || '';
            document.getElementById('edit-usr-email').value = u.email || '';
            document.getElementById('edit-usr-mobile').value = u.mobile || '';
            document.getElementById('edit-usr-dept').value = u.department || '';
            document.getElementById('edit-usr-upn').value = u.user_principal_name || '';
            document.getElementById('edit-usr-bandwidth-profile').value = u.bandwidth_profile_id || 0;
            document.getElementById('edit-usr-pass').value = '';

            populateGroupCheckboxes('edit-usr-groups-container', u.groups || []);

            document.getElementById('edit-user-modal').classList.remove('hidden');
        }

        function closeEditUserModal() {
            document.getElementById('edit-user-modal').classList.add('hidden');
        }

        async function submitEditUser(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-submit-edit-user');
            const username = document.getElementById('edit-usr-name').value.trim();
            const statusVal = document.getElementById('edit-usr-status').value;
            const givenName = document.getElementById('edit-usr-given').value.trim();
            const surname = document.getElementById('edit-usr-sur').value.trim();
            const email = document.getElementById('edit-usr-email').value.trim();
            const mobile = document.getElementById('edit-usr-mobile').value.trim();
            const dept = document.getElementById('edit-usr-dept').value.trim();
            const upn = document.getElementById('edit-usr-upn').value.trim();
            const bwId = parseInt(document.getElementById('edit-usr-bandwidth-profile').value) || 0;
            const passVal = document.getElementById('edit-usr-pass').value;
            const checkedGroups = Array.from(document.querySelectorAll("input[name='edit-usr-groups-container-chk']:checked")).map(cb => cb.value);

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Saving...`;

            try {
                const res = await fetch(`${API_BASE}/users/${username}`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        given_name: givenName,
                        surname: surname,
                        email: email,
                        mobile: mobile,
                        department: dept,
                        user_principal_name: upn,
                        bandwidth_profile_id: bwId,
                        is_disabled: statusVal === 'disabled',
                        new_password: passVal ? passVal : null,
                        groups: checkedGroups
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeEditUserModal();
                    fetchUsers();
                    fetchRadiusBandwidth();
                } else {
                    alert(`Failed to update user: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving user: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save User Changes`;
            }
        }

        async function deleteUser(username) {
            if (!confirm(`Delete user '${username}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/users/${username}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchUsers();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting user: ${err}`);
            }
        }

        // 5. Users, Groups & Computers
        function sortGroupsBy(col) {
            if (groupsSortCol === col) {
                groupsSortDir = (groupsSortDir === 'asc') ? 'desc' : 'asc';
            } else {
                groupsSortCol = col;
                groupsSortDir = 'asc';
            }
            groupsCurrentPage = 1;
            renderGroupsTable();
        }

        function onGroupsSearchInput() {
            const input = document.getElementById('groups-search-input');
            groupsSearchQuery = input ? input.value : '';
            const clearBtn = document.getElementById('groups-search-clear');
            if (clearBtn) clearBtn.classList.toggle('hidden', !groupsSearchQuery);
            groupsCurrentPage = 1;
            renderGroupsTable();
        }

        function clearGroupsSearch() {
            const input = document.getElementById('groups-search-input');
            if (input) input.value = '';
            groupsSearchQuery = '';
            const clearBtn = document.getElementById('groups-search-clear');
            if (clearBtn) clearBtn.classList.add('hidden');
            groupsCurrentPage = 1;
            renderGroupsTable();
        }

        function goToGroupsPage(p) {
            groupsCurrentPage = p;
            renderGroupsTable();
        }

        function onGroupsPageSizeChange() {
            const sel = document.getElementById('groups-page-size');
            groupsPageSize = sel ? parseInt(sel.value, 10) : 25;
            groupsCurrentPage = 1;
            renderGroupsTable();
        }

        function prevGroupsPage() {
            if (groupsCurrentPage > 1) {
                groupsCurrentPage--;
                renderGroupsTable();
            }
        }

        function nextGroupsPage() {
            groupsCurrentPage++;
            renderGroupsTable();
        }

        function renderGroupsTable() {
            const chk = document.getElementById('chk-show-builtin-groups');
            const showBuiltin = chk ? chk.checked : false;
            const baseGroups = showBuiltin ? (globalGroups || []) : (globalGroups || []).filter(g => !g.is_built_in);

            const badgeCount = document.getElementById('badge-groups-count');
            if (badgeCount) {
                badgeCount.innerText = `${baseGroups.length}`;
            }

            // Search filter
            let filtered = [...baseGroups];
            const q = (groupsSearchQuery || '').toLowerCase().trim();
            if (q) {
                filtered = filtered.filter(g => {
                    const gName = (g.group_name || '').toLowerCase();
                    const desc = (g.description || '').toLowerCase();
                    const bw = (g.bandwidth_profile_name || '').toLowerCase();
                    const dn = (g.dn || '').toLowerCase();
                    const type = g.is_built_in ? 'builtin built-in system' : 'custom security';
                    return gName.includes(q) || desc.includes(q) || bw.includes(q) || dn.includes(q) || type.includes(q);
                });
            }

            // Sorting
            filtered.sort((a, b) => {
                let valA = '';
                let valB = '';
                if (groupsSortCol === 'group_name') {
                    valA = (a.group_name || '').toLowerCase();
                    valB = (b.group_name || '').toLowerCase();
                } else if (groupsSortCol === 'is_built_in') {
                    valA = a.is_built_in ? 1 : 0;
                    valB = b.is_built_in ? 1 : 0;
                } else if (groupsSortCol === 'description') {
                    valA = (a.description || '').toLowerCase();
                    valB = (b.description || '').toLowerCase();
                } else if (groupsSortCol === 'members') {
                    valA = a.member_count !== undefined ? a.member_count : (a.members ? a.members.length : 0);
                    valB = b.member_count !== undefined ? b.member_count : (b.members ? b.members.length : 0);
                    return groupsSortDir === 'asc' ? valA - valB : valB - valA;
                } else if (groupsSortCol === 'bandwidth_profile_name') {
                    valA = (a.bandwidth_profile_name || '').toLowerCase();
                    valB = (b.bandwidth_profile_name || '').toLowerCase();
                }

                if (valA < valB) return groupsSortDir === 'asc' ? -1 : 1;
                if (valA > valB) return groupsSortDir === 'asc' ? 1 : -1;
                return 0;
            });

            updateTableSortIcons('group', groupsSortCol, groupsSortDir);

            // Pagination
            const totalCount = filtered.length;
            let pageItems = filtered;
            let totalPages = 1;

            if (groupsPageSize > 0 && totalCount > 0) {
                totalPages = Math.max(1, Math.ceil(totalCount / groupsPageSize));
                if (groupsCurrentPage > totalPages) groupsCurrentPage = totalPages;
                if (groupsCurrentPage < 1) groupsCurrentPage = 1;
                const startIdx = (groupsCurrentPage - 1) * groupsPageSize;
                pageItems = filtered.slice(startIdx, startIdx + groupsPageSize);
            } else {
                groupsCurrentPage = 1;
            }

            // Stats
            const statsEl = document.getElementById('groups-filter-stats');
            if (statsEl) {
                if (q) {
                    statsEl.innerText = `Showing ${filtered.length} of ${baseGroups.length} (filtered)`;
                } else if (groupsPageSize > 0 && baseGroups.length > groupsPageSize) {
                    const startNum = ((groupsCurrentPage - 1) * groupsPageSize) + 1;
                    const endNum = Math.min(groupsCurrentPage * groupsPageSize, totalCount);
                    statsEl.innerText = `Showing ${startNum}-${endNum} of ${totalCount}`;
                } else {
                    statsEl.innerText = `Showing ${totalCount} of ${baseGroups.length}`;
                }
            }

            // Pagination Bar
            const paginationBar = document.getElementById('groups-pagination');
            const pageInfo = document.getElementById('groups-pagination-info');
            const prevBtn = document.getElementById('groups-prev-btn');
            const nextBtn = document.getElementById('groups-next-btn');
            if (paginationBar && pageInfo && prevBtn && nextBtn) {
                if (groupsPageSize === 0 || totalCount <= groupsPageSize) {
                    paginationBar.classList.add('hidden');
                } else {
                    paginationBar.classList.remove('hidden');
                    pageInfo.innerText = `Page ${groupsCurrentPage} of ${totalPages} (${totalCount} groups)`;
                    prevBtn.disabled = (groupsCurrentPage <= 1);
                    nextBtn.disabled = (groupsCurrentPage >= totalPages);
                    renderPaginationButtons('groups-page-numbers', groupsCurrentPage, totalPages, 'goToGroupsPage');
                }
            }

            const tbody = document.getElementById('groups-table-body');
            if (!tbody) return;

            if (pageItems.length > 0) {
                tbody.innerHTML = pageItems.map(g => {
                    let bwBadge = '<span class="px-2 py-0.5 rounded text-[10px] font-sans text-slate-500 bg-slate-950 border border-slate-800 flex items-center gap-1 w-max"><i class="fa-solid fa-minus text-slate-600"></i> None</span>';
                    if (g.bandwidth_profile_name) {
                        const safeBwName = escapeHtml(g.bandwidth_profile_name);
                        const safeBwRate = escapeHtml(g.bandwidth_rate || '');
                        bwBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-sans font-semibold bg-cyan-950 text-cyan-300 border border-cyan-800 flex items-center gap-1 w-max" title="WISPr/MikroTik: ${safeBwRate}"><i class="fa-solid fa-gauge-high text-cyan-400"></i> ${safeBwName} (${safeBwRate})</span>`;
                    }

                    const isBuiltin = g.is_built_in;
                    const memberCount = g.member_count !== undefined ? g.member_count : (g.members ? g.members.length : 0);
                    const safeGroupName = escapeHtml(g.group_name);
                    const safeDnPart = escapeHtml(g.dn ? g.dn.split(',')[1] || '' : '');
                    const safeDesc = g.description ? escapeHtml(g.description) : '<span class="text-slate-600 italic">No description</span>';

                    return `
                        <tr class="hover:bg-slate-800/30">
                            <td class="px-4 py-2.5">
                                <div class="font-bold text-white flex items-center gap-1.5 flex-wrap">
                                    <i class="fa-solid fa-users text-indigo-400 text-[10px]"></i> ${safeGroupName}
                                    ${isBuiltin ? '<span class="text-[9px] px-1.5 py-0.5 rounded bg-amber-950/70 text-amber-400 border border-amber-800/80 uppercase font-mono font-bold">Built-in Group</span>' : '<span class="text-[9px] px-1.5 py-0.5 rounded bg-indigo-950/70 text-indigo-300 border border-indigo-800/80 uppercase font-mono">Custom Group</span>'}
                                </div>
                                <div class="text-[10px] text-slate-500 font-mono">${safeDnPart}</div>
                            </td>
                            <td class="px-4 py-2.5">
                                ${isBuiltin ? '<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-amber-400 border border-slate-700 font-mono font-bold flex items-center gap-1 w-max"><i class="fa-solid fa-shield text-amber-400"></i> Built-in</span>' : '<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono flex items-center gap-1 w-max"><i class="fa-solid fa-users text-indigo-400"></i> Custom Group</span>'}
                            </td>
                            <td class="px-4 py-2.5 text-slate-300 font-sans text-xs">
                                ${safeDesc}
                            </td>
                            <td class="px-4 py-2.5">
                                <span class="px-2 py-0.5 rounded text-[10px] font-mono bg-slate-950 border border-slate-800 text-slate-300">
                                    <i class="fa-solid fa-user-group text-slate-500 mr-1"></i>${escapeHtml(memberCount)} members
                                </span>
                            </td>
                            <td class="px-4 py-2.5">${bwBadge}</td>
                            <td class="px-4 py-2.5 text-right whitespace-nowrap">
                                <button data-action="edit-group" data-group="${safeGroupName}" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-indigo-300 font-sans font-semibold text-[10px] transition mr-1" title="Edit Group Policy & Bandwidth Tier">
                                    <i class="fa-solid fa-pen"></i> Edit Policy
                                </button>
                                ${!isBuiltin ? `
                                    <button data-action="delete-group" data-group="${safeGroupName}" class="text-slate-500 hover:text-rose-400 ml-1 p-1 transition" title="Delete Security Group">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                ` : '<span class="px-1.5 py-0.5 rounded bg-slate-950 text-slate-500 border border-slate-800 font-mono text-[9px] inline-flex items-center gap-1 ml-1" title="Protected System Group (Cannot Delete)"><i class="fa-solid fa-lock text-slate-600"></i> Locked</span>'}
                            </td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center font-sans text-slate-500">' + 
                    (q ? 'No security groups matched your search query.' : 'No custom security groups found. Create one using "+ New Security Group" or check "Show Built-in System Groups".') + 
                    '</td></tr>';
            }
        }

        async function fetchGroups() {
            try {
                const res = await fetch(`${API_BASE}/groups?_t=${Date.now()}`);
                const data = await res.json();
                globalGroups = data.groups || [];
                renderGroupsTable();
                if (typeof renderUsersTable === 'function' && typeof globalUsers !== 'undefined' && globalUsers.length > 0) {
                    renderUsersTable();
                }
            } catch (err) {
                console.error('Error fetching groups:', err);
            }
        }

        function openGroupModal() {
            populateBandwidthSelects();
            const grpInput = document.getElementById('grp-name-input');
            const descInput = document.getElementById('grp-desc-input');
            const bwInput = document.getElementById('grp-bw-profile-input');
            if (grpInput) grpInput.value = '';
            if (descInput) descInput.value = '';
            if (bwInput) bwInput.value = '0';
            document.getElementById('group-modal').classList.remove('hidden');
        }

        function closeGroupModal() {
            document.getElementById('group-modal').classList.add('hidden');
        }

        async function submitCreateGroup() {
            const name = document.getElementById('grp-name-input').value.trim();
            const desc = document.getElementById('grp-desc-input') ? document.getElementById('grp-desc-input').value.trim() : '';
            const bwSelect = document.getElementById('grp-bw-profile-input');
            const bwId = bwSelect && parseInt(bwSelect.value, 10) > 0 ? parseInt(bwSelect.value, 10) : null;
            if (!name) return alert('Group name is required.');
            try {
                const res = await fetch(`${API_BASE}/groups`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        group_name: name,
                        description: desc,
                        bandwidth_profile_id: bwId
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeGroupModal();
                    fetchGroups();
                    fetchRadiusBandwidth();
                } else {
                    alert(`Failed to create group: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error creating group: ${err}`);
            }
        }

        function openEditGroupModal(groupName) {
            populateBandwidthSelects();
            const g = globalGroups.find(x => x.group_name.toLowerCase() === groupName.toLowerCase());
            if (!g) return alert(`Group '${groupName}' not found in active list.`);

            document.getElementById('edit-grp-name').value = g.group_name;
            document.getElementById('edit-grp-desc').value = g.description || '';
            const bwSelect = document.getElementById('edit-grp-bw-profile');
            if (bwSelect) {
                bwSelect.value = (g.bandwidth_profile_id) ? String(g.bandwidth_profile_id) : '0';
            }
            document.getElementById('edit-group-modal').classList.remove('hidden');
        }

        function closeEditGroupModal() {
            document.getElementById('edit-group-modal').classList.add('hidden');
        }

        async function submitEditGroup() {
            const groupName = document.getElementById('edit-grp-name').value;
            const desc = document.getElementById('edit-grp-desc').value.trim();
            const bwVal = document.getElementById('edit-grp-bw-profile').value;
            const bwId = parseInt(bwVal, 10) || 0;

            const btn = document.getElementById('btn-save-group');
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin"></i> Saving...`;

            try {
                const res = await fetch(`${API_BASE}/groups/${encodeURIComponent(groupName)}`, {
                    method: 'PUT',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        description: desc,
                        bandwidth_profile_id: bwId
                    })
                });
                const data = await res.json();
                if (res.ok) {
                    closeEditGroupModal();
                    fetchGroups();
                    fetchRadiusBandwidth();
                } else {
                    alert(`Failed to update group: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error saving group: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-floppy-disk"></i> Save Group Policy`;
            }
        }

        async function deleteGroup(groupName) {
            if (!confirm(`Are you sure you want to delete Active Directory group '${groupName}'?`)) return;
            try {
                const res = await fetch(`${API_BASE}/groups/${encodeURIComponent(groupName)}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchGroups();
                    fetchRadiusBandwidth();
                } else {
                    const data = await res.json();
                    alert(`Delete failed: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting group: ${err}`);
            }
        }

        // ==================== Domain Computers Search, Sort & Pagination ====================
        function sortComputersBy(col) {
            if (computersSortCol === col) {
                computersSortDir = (computersSortDir === 'asc') ? 'desc' : 'asc';
            } else {
                computersSortCol = col;
                computersSortDir = 'asc';
            }
            computersCurrentPage = 1;
            renderComputersTable();
        }

        function onComputersSearchInput() {
            const input = document.getElementById('computers-search-input');
            computersSearchQuery = input ? input.value : '';
            const clearBtn = document.getElementById('computers-search-clear');
            if (clearBtn) clearBtn.classList.toggle('hidden', !computersSearchQuery);
            computersCurrentPage = 1;
            renderComputersTable();
        }

        function clearComputersSearch() {
            const input = document.getElementById('computers-search-input');
            if (input) input.value = '';
            computersSearchQuery = '';
            const clearBtn = document.getElementById('computers-search-clear');
            if (clearBtn) clearBtn.classList.add('hidden');
            computersCurrentPage = 1;
            renderComputersTable();
        }

        function goToComputersPage(p) {
            computersCurrentPage = p;
            renderComputersTable();
        }

        function onComputersPageSizeChange() {
            const sel = document.getElementById('computers-page-size');
            computersPageSize = sel ? parseInt(sel.value, 10) : 25;
            computersCurrentPage = 1;
            renderComputersTable();
        }

        function prevComputersPage() {
            if (computersCurrentPage > 1) {
                computersCurrentPage--;
                renderComputersTable();
            }
        }

        function nextComputersPage() {
            computersCurrentPage++;
            renderComputersTable();
        }

        function renderComputersTable() {
            const baseComputers = globalComputers || [];
            const badge = document.getElementById('badge-computers-count');
            if (badge) badge.innerText = `${baseComputers.length}`;

            // Search filter
            let filtered = [...baseComputers];
            const q = (computersSearchQuery || '').toLowerCase().trim();
            if (q) {
                filtered = filtered.filter(c => {
                    const cName = (c.name || '').toLowerCase();
                    const host = (c.dns_hostname || '').toLowerCase();
                    const os = (c.operating_system || '').toLowerCase();
                    const osVer = (c.os_version || '').toLowerCase();
                    const role = c.is_dc ? 'domain controller dc server' : 'workstation client server';
                    return cName.includes(q) || host.includes(q) || os.includes(q) || osVer.includes(q) || role.includes(q);
                });
            }

            // Sorting
            filtered.sort((a, b) => {
                let valA = '';
                let valB = '';
                if (computersSortCol === 'name') {
                    valA = (a.name || '').toLowerCase();
                    valB = (b.name || '').toLowerCase();
                } else if (computersSortCol === 'dns_hostname') {
                    valA = (a.dns_hostname || '').toLowerCase();
                    valB = (b.dns_hostname || '').toLowerCase();
                } else if (computersSortCol === 'operating_system') {
                    valA = (a.operating_system || '').toLowerCase();
                    valB = (b.operating_system || '').toLowerCase();
                } else if (computersSortCol === 'is_dc') {
                    valA = a.is_dc ? 1 : 0;
                    valB = b.is_dc ? 1 : 0;
                } else if (computersSortCol === 'created_at') {
                    valA = (a.created_at || '').toLowerCase();
                    valB = (b.created_at || '').toLowerCase();
                }

                if (valA < valB) return computersSortDir === 'asc' ? -1 : 1;
                if (valA > valB) return computersSortDir === 'asc' ? 1 : -1;
                return 0;
            });

            updateTableSortIcons('comp', computersSortCol, computersSortDir);

            // Pagination
            const totalCount = filtered.length;
            let pageItems = filtered;
            let totalPages = 1;

            if (computersPageSize > 0 && totalCount > 0) {
                totalPages = Math.max(1, Math.ceil(totalCount / computersPageSize));
                if (computersCurrentPage > totalPages) computersCurrentPage = totalPages;
                if (computersCurrentPage < 1) computersCurrentPage = 1;
                const startIdx = (computersCurrentPage - 1) * computersPageSize;
                pageItems = filtered.slice(startIdx, startIdx + computersPageSize);
            } else {
                computersCurrentPage = 1;
            }

            // Stats
            const statsEl = document.getElementById('computers-filter-stats');
            if (statsEl) {
                if (q) {
                    statsEl.innerText = `Showing ${filtered.length} of ${baseComputers.length} (filtered)`;
                } else if (computersPageSize > 0 && baseComputers.length > computersPageSize) {
                    const startNum = ((computersCurrentPage - 1) * computersPageSize) + 1;
                    const endNum = Math.min(computersCurrentPage * computersPageSize, totalCount);
                    statsEl.innerText = `Showing ${startNum}-${endNum} of ${totalCount}`;
                } else {
                    statsEl.innerText = `Showing ${totalCount} of ${baseComputers.length}`;
                }
            }

            // Pagination Bar
            const paginationBar = document.getElementById('computers-pagination');
            const pageInfo = document.getElementById('computers-pagination-info');
            const prevBtn = document.getElementById('computers-prev-btn');
            const nextBtn = document.getElementById('computers-next-btn');
            if (paginationBar && pageInfo && prevBtn && nextBtn) {
                if (computersPageSize === 0 || totalCount <= computersPageSize) {
                    paginationBar.classList.add('hidden');
                } else {
                    paginationBar.classList.remove('hidden');
                    pageInfo.innerText = `Page ${computersCurrentPage} of ${totalPages} (${totalCount} computers)`;
                    prevBtn.disabled = (computersCurrentPage <= 1);
                    nextBtn.disabled = (computersCurrentPage >= totalPages);
                    renderPaginationButtons('computers-page-numbers', computersCurrentPage, totalPages, 'goToComputersPage');
                }
            }

            const tbody = document.getElementById('computers-table-body');
            if (!tbody) return;

            if (pageItems.length > 0) {
                tbody.innerHTML = pageItems.map(c => {
                    const icon = c.is_dc ? 'fa-server text-indigo-400' : 'fa-desktop text-cyan-400';
                    const roleBadge = c.is_dc
                        ? '<span class="px-2 py-0.5 rounded text-[10px] bg-indigo-950 text-indigo-300 border border-indigo-800 font-mono font-bold flex items-center gap-1 w-max"><i class="fa-solid fa-shield text-indigo-400"></i> Domain Controller</span>'
                        : '<span class="px-2 py-0.5 rounded text-[10px] bg-slate-800 text-slate-300 border border-slate-700 font-mono flex items-center gap-1 w-max"><i class="fa-solid fa-desktop text-slate-400"></i> Domain Workstation</span>';

                    const safeName = escapeHtml(c.name);
                    const safeDn = escapeHtml(c.dn || '');
                    const safeDnPart = escapeHtml(c.dn ? c.dn.split(',')[1] || '' : '');
                    const safeDnsHost = escapeHtml(c.dns_hostname || '-');
                    const safeOs = escapeHtml(c.operating_system || '-');
                    const safeOsVer = escapeHtml(c.os_version || '-');
                    const safeCreatedAt = escapeHtml(c.created_at || '-');

                    return `
                        <tr class="hover:bg-slate-800/30">
                            <td class="px-4 py-2.5">
                                <div class="font-bold text-white flex items-center gap-1.5 font-mono">
                                    <i class="fa-solid ${icon} text-[11px]"></i> ${safeName}
                                </div>
                                <div class="text-[10px] text-slate-500 font-mono truncate max-w-[200px]" title="${safeDn}">${safeDnPart}</div>
                            </td>
                            <td class="px-4 py-2.5 font-mono text-cyan-300 text-xs">
                                ${safeDnsHost}
                            </td>
                            <td class="px-4 py-2.5">
                                <div class="font-semibold text-slate-200">${safeOs}</div>
                                <div class="text-[10px] text-slate-400 font-mono">Version: ${safeOsVer}</div>
                            </td>
                            <td class="px-4 py-2.5">${roleBadge}</td>
                            <td class="px-4 py-2.5 text-slate-400 font-mono text-[11px]">${safeCreatedAt}</td>
                            <td class="px-4 py-2.5 text-right whitespace-nowrap">
                                ${!c.is_dc ? `
                                    <button data-action="delete-computer" data-computer="${safeName}" class="px-2 py-1 rounded bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 text-xs transition" title="Disjoin / Remove Computer Account">
                                        <i class="fa-solid fa-trash-can mr-1"></i> Remove
                                    </button>
                                ` : '<span class="px-2 py-0.5 rounded bg-slate-950 text-slate-500 border border-slate-800 font-mono text-[10px] flex items-center gap-1 w-max ml-auto"><i class="fa-solid fa-lock text-slate-600"></i> Primary DC</span>'}
                            </td>
                        </tr>
                    `;
                }).join('');
            } else {
                tbody.innerHTML = '<tr><td colspan="6" class="px-4 py-6 text-center font-sans text-slate-500">' +
                    (q ? 'No domain computers matched your search query.' : 'No domain computers found. Workstations will appear here automatically when joined to the domain.') +
                    '</td></tr>';
            }
        }

        async function fetchComputers() {
            try {
                const res = await fetch(`${API_BASE}/computers`);
                const data = await res.json();
                globalComputers = data.computers || [];
                renderComputersTable();
            } catch (err) {
                console.error('Error fetching computers:', err);
            }
        }

        async function deleteComputer(compName) {
            if (!confirm(`Are you sure you want to delete computer account '${compName}' from Active Directory? Workstations using this trust account will lose domain connectivity.`)) return;
            try {
                const res = await fetch(`${API_BASE}/computers/${encodeURIComponent(compName)}`, { method: 'DELETE' });
                if (res.ok) {
                    fetchComputers();
                } else {
                    const data = await res.json();
                    alert(`Failed to delete computer: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error deleting computer: ${err}`);
            }
        }

        // ==================== User Principal Name (UPN) Logic ====================
        function openChangeUpnModal(username, currentUpn = '') {
            const domainFallback = currentSystemIdentity?.realm ? currentSystemIdentity.realm.toLowerCase() : '';
            const fallbackUpn = domainFallback ? `${username}@${domainFallback}` : username;
            document.getElementById('upn-modal-username').value = username;
            document.getElementById('upn-modal-current').value = currentUpn || fallbackUpn;
            document.getElementById('upn-modal-new').value = currentUpn || fallbackUpn;
            document.getElementById('modal-change-upn').classList.remove('hidden');
        }

        function closeChangeUpnModal() {
            document.getElementById('modal-change-upn').classList.add('hidden');
        }

        async function submitChangeUpn(e) {
            e.preventDefault();
            const btn = document.getElementById('btn-submit-change-upn');
            const username = document.getElementById('upn-modal-username').value.trim();
            const newUpn = document.getElementById('upn-modal-new').value.trim();

            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin"></i> Updating UPN...`;

            try {
                const res = await fetch(`${API_BASE}/users/${encodeURIComponent(username)}/upn`, {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({ user_principal_name: newUpn })
                });
                const data = await res.json();
                if (res.ok) {
                    alert(`UserPrincipalName updated successfully!\n\nUser: ${username}\nNew UPN: ${newUpn}`);
                    closeChangeUpnModal();
                    fetchUsers();
                    fetchRegistrations(currentRegFilter);
                } else {
                    alert(`Failed to update UPN: ${data.detail}`);
                }
            } catch (err) {
                alert(`Error updating UPN: ${err}`);
            } finally {
                btn.disabled = false;
                btn.innerHTML = `<i class="fa-solid fa-check"></i> Update UPN`;
            }
        }

