(function () {
    const utils = window.vmaUtils || {};
    const router = window.vmaRouter || {};
    const auth = window.vmaAuth || {};

    const {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle,
        createMessageHelper,
        normalizeApiResponse,
        selectHelpers
    } = utils;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Code initialisation skipped: utilities not available.');
        return;
    }

    /* ---- Sorting utilities ---- */

    const SORT_STORAGE_KEY_PREFIX = 'vma.code.sort';

    function loadSortState(tableKey) {
        try {
            const raw = localStorage.getItem(`${SORT_STORAGE_KEY_PREFIX}.${tableKey}`);
            if (!raw) return null;
            return JSON.parse(raw);
        } catch { return null; }
    }

    function saveSortState(tableKey, sortState) {
        try {
            localStorage.setItem(`${SORT_STORAGE_KEY_PREFIX}.${tableKey}`, JSON.stringify(sortState));
        } catch { /* ignore */ }
    }

    function getSortValue(item, key, columns) {
        if (!item) return '';

        // For dynamic columns, use the extract function
        const col = columns?.find(c => c.key === key);
        if (col && col.extract) {
            const val = col.extract(item);
            return val ?? '';
        }

        // Direct property access for simple tables
        return item[key] ?? '';
    }

    function compareValues(a, b, direction) {
        // Handle null/undefined
        if (a == null && b == null) return 0;
        if (a == null) return direction === 'asc' ? -1 : 1;
        if (b == null) return direction === 'asc' ? 1 : -1;

        // Try numeric comparison first
        const numA = parseFloat(a);
        const numB = parseFloat(b);
        if (!isNaN(numA) && !isNaN(numB)) {
            return direction === 'asc' ? numA - numB : numB - numA;
        }

        // String comparison
        const strA = String(a).toLowerCase();
        const strB = String(b).toLowerCase();
        const result = strA.localeCompare(strB, undefined, { numeric: true, sensitivity: 'base' });
        return direction === 'asc' ? result : -result;
    }

    function sortItems(items, sortKey, direction, columns) {
        if (!sortKey || !Array.isArray(items)) return items;
        return [...items].sort((a, b) => {
            const valA = getSortValue(a, sortKey, columns);
            const valB = getSortValue(b, sortKey, columns);
            return compareValues(valA, valB, direction);
        });
    }

    function createSortableHeader(text, key, currentSort, onClick) {
        const th = document.createElement('th');
        th.className = 'sortable-header';
        th.setAttribute('data-sort-key', key);
        th.setAttribute('role', 'columnheader');
        th.setAttribute('aria-sort', currentSort?.key === key
            ? (currentSort.direction === 'asc' ? 'ascending' : 'descending')
            : 'none');

        const wrapper = document.createElement('button');
        wrapper.type = 'button';
        wrapper.className = 'sort-header-btn';

        const label = document.createElement('span');
        label.textContent = text;
        wrapper.appendChild(label);

        const indicator = document.createElement('span');
        indicator.className = 'sort-indicator';
        if (currentSort?.key === key) {
            indicator.classList.add('sort-indicator--active');
            indicator.innerHTML = currentSort.direction === 'asc'
                ? '<i class="fas fa-sort-up"></i>'
                : '<i class="fas fa-sort-down"></i>';
        } else {
            indicator.innerHTML = '<i class="fas fa-sort"></i>';
        }
        wrapper.appendChild(indicator);

        wrapper.addEventListener('click', () => onClick(key));
        th.appendChild(wrapper);
        return th;
    }

    function toggleSortDirection(currentSort, key) {
        if (currentSort?.key === key) {
            return { key, direction: currentSort.direction === 'asc' ? 'desc' : 'asc' };
        }
        return { key, direction: 'asc' };
    }

    /* ---- Product List columns ---- */
    const PRODUCT_COLUMNS = [
        { key: 'name', header: 'Product', sortable: true },
        { key: 'team', header: 'Team', sortable: true }
    ];

    /* ---- Repository List columns ---- */
    const REPOSITORY_COLUMNS = [
        { key: 'name', header: 'Repository', sortable: true }
    ];

    /* ---- SAST Finding columns ---- */

    const COLUMN_STORAGE_KEY = 'vma.code.columns';

    function truncate(str, max) {
        if (!str) return '';
        return str.length > max ? str.slice(0, max) + '…' : str;
    }

    function formatCwes(item) {
        const cwes = Array.isArray(item?.cwes) ? item.cwes : [];
        if (!cwes.length) return '—';
        return cwes.map(c => c.id || c).join(', ');
    }

    function formatOwasp(item) {
        const owasp = Array.isArray(item?.owasp) ? item.owasp : [];
        if (!owasp.length) return '—';
        return owasp.map(o => typeof o === 'string' ? o.split(' - ')[0] : o).join(', ');
    }

    function formatTechnology(item) {
        const tech = Array.isArray(item?.technology) ? item.technology : [];
        if (!tech.length) return '—';
        return tech.join(', ');
    }

    function formatLocation(item) {
        if (!item) return '';
        return `${item.file_path || ''}:${item.start_line || ''}`;
    }

    const SAST_COLUMNS = [
        { key: 'rule_id_short', header: 'Rule',         visible: true,  extract: item => {
            const rid = item?.rule_id || '';
            const parts = rid.split('.');
            return parts.length > 2 ? parts.slice(-2).join('.') : rid;
        }},
        { key: 'severity',      header: 'Severity',     visible: true,  extract: item => item?.severity || '' },
        { key: 'location',      header: 'Location',     visible: true,  extract: formatLocation },
        { key: 'message',       header: 'Message',      visible: true,  extract: item => truncate(item?.message, 100) },
        { key: 'confidence',    header: 'Confidence',   visible: true,  extract: item => item?.confidence || '' },
        { key: 'impact',        header: 'Impact',       visible: false, extract: item => item?.impact || '' },
        { key: 'likelihood',    header: 'Likelihood',   visible: false, extract: item => item?.likelihood || '' },
        { key: 'cwes',          header: 'CWEs',         visible: false, extract: formatCwes },
        { key: 'owasp',         header: 'OWASP',        visible: false, extract: formatOwasp },
        { key: 'category',      header: 'Category',     visible: true,  extract: item => item?.category || '' },
        { key: 'technology',    header: 'Technology',   visible: false, extract: formatTechnology },
        { key: 'scanner',       header: 'Scanner',      visible: false, extract: item => item?.scanner || '' },
        { key: 'rule_id_full',  header: 'Full Rule ID', visible: false, extract: item => item?.rule_id || '' },
        { key: 'code_snippet',  header: 'Code',         visible: false, extract: item => truncate(item?.code_snippet, 60) },
        { key: 'suggested_fix', header: 'Fix',          visible: false, extract: item => truncate(item?.suggested_fix, 60) }
    ];

    /* ---- Column visibility persistence ---- */

    function loadColumnVisibility() {
        try {
            const raw = localStorage.getItem(COLUMN_STORAGE_KEY);
            if (!raw) return null;
            return JSON.parse(raw);
        } catch { return null; }
    }

    function saveColumnVisibility(visibility) {
        try {
            localStorage.setItem(COLUMN_STORAGE_KEY, JSON.stringify(visibility));
        } catch { /* ignore */ }
    }

    function getDefaultVisibility() {
        const vis = {};
        SAST_COLUMNS.forEach(col => { vis[col.key] = col.visible; });
        return vis;
    }

    function getVisibleColumns(state) {
        const vis = state.columnVisibility || getDefaultVisibility();
        return SAST_COLUMNS.filter(col => vis[col.key]);
    }

    /* ---- Severity helpers ---- */

    function getSeverityBadgeClass(level) {
        if (!level) return 'severity-none';
        const lower = String(level).toLowerCase();
        if (lower === 'error') return 'severity-critical';
        if (lower === 'warning') return 'severity-high';
        if (lower === 'info') return 'severity-low';
        return 'severity-none';
    }

    function getSeverityLabel(level) {
        if (!level) return '';
        const lower = String(level).toLowerCase();
        if (lower === 'error') return 'Error';
        if (lower === 'warning') return 'Warning';
        if (lower === 'info') return 'Info';
        return level;
    }

    /* ---- Data parsing ---- */

    function parseProductRecord(product) {
        if (!product) {
            return { name: '', description: '', team: '' };
        }

        if (Array.isArray(product)) {
            return {
                name: product[0] ?? '',
                description: product[1] ?? '',
                team: product[2] ?? ''
            };
        }

        if (typeof product === 'object') {
            return {
                name: product.id ?? product.name ?? '',
                description: product.description ?? '',
                team: product.team ?? product.team_id ?? ''
            };
        }

        return { name: '', description: '', team: '' };
    }

    function getUniqueTeamsFromProducts(products) {
        if (!Array.isArray(products)) return [];
        const names = products.map(p => p.team ?? p.team_id ?? p[2]).filter(Boolean);
        const unique = Array.from(new Set(names));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique;
    }

    function extractUniqueRepositories(sastData) {
        if (!Array.isArray(sastData)) return [];
        const repoNames = sastData
            .map(item => item.repository)
            .filter(Boolean);
        const unique = Array.from(new Set(repoNames));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique.map(name => ({ name }));
    }

    /* ---- Data loading ---- */

    async function loadProducts(state, helpers) {
        if (!state.productRows) return;

        state.productRows.innerHTML = '';
        const loadingRow = document.createElement('tr');
        loadingRow.appendChild(createElementWithAttrs('td', 'Loading…', { colspan: '2', class: 'empty' }));
        state.productRows.appendChild(loadingRow);

        try {
            const res = await fetchJSON(apiUrl('/products'));
            state.data.products = normalizeApiResponse(res).map(parseProductRecord);
        } catch (error) {
            state.productRows.innerHTML = '';
            const row = document.createElement('tr');
            row.appendChild(
                createElementWithAttrs('td', 'Unable to load products.', { colspan: '2', class: 'empty' })
            );
            state.productRows.appendChild(row);
            state.productCounter.textContent = '0';
            helpers.productList?.show(error.message || 'Failed to fetch products.', 'error');
            return;
        }

        state.data.products = Array.isArray(state.data.products) ? state.data.products : [];
        updateFilterOptions(state);

        const filterValue = state.filterSelect?.value || '';
        const filtered = filterValue
            ? state.data.products.filter(product => product.team === filterValue)
            : state.data.products;
        renderProductRows(state, filtered, filterValue);
    }

    async function loadRepositories(state, helpers) {
        if (!state.currentTeam || !state.currentProduct) {
            state.data.repositories = [];
            renderRepositoryRows(state, []);
            return;
        }

        state.repositoryRows.innerHTML = '';
        const loadingRow = document.createElement('tr');
        loadingRow.appendChild(createElementWithAttrs('td', 'Loading repositories…', { colspan: '1', class: 'empty' }));
        state.repositoryRows.appendChild(loadingRow);

        try {
            // Fetch all SAST data for the product to extract unique repositories
            const url = apiUrl(`/sast/${encodeURIComponent(state.currentTeam)}/${encodeURIComponent(state.currentProduct)}`);
            const res = await fetchJSON(url);
            const sastData = normalizeApiResponse(res);
            state.data.repositories = extractUniqueRepositories(sastData);
        } catch (error) {
            state.repositoryRows.innerHTML = '';
            const row = document.createElement('tr');
            row.appendChild(
                createElementWithAttrs('td', 'Unable to load repositories.', { colspan: '1', class: 'empty' })
            );
            state.repositoryRows.appendChild(row);
            helpers.repositories?.show(error.message || 'Failed to load repositories.', 'error');
            return;
        }

        renderRepositoryRows(state, state.data.repositories);
    }

    async function loadFindings(state, helpers) {
        if (!state.currentTeam || !state.currentProduct || !state.currentRepository) {
            state.data.findings = [];
            applyFindingSearch(state);
            return;
        }

        state.findingRows.innerHTML = '';
        const loadingRow = document.createElement('tr');
        const colCount = getVisibleColumns(state).length;
        loadingRow.appendChild(createElementWithAttrs('td', 'Loading findings…', { colspan: colCount.toString(), class: 'empty' }));
        state.findingRows.appendChild(loadingRow);

        try {
            const url = apiUrl(`/sast/${encodeURIComponent(state.currentTeam)}/${encodeURIComponent(state.currentProduct)}/${encodeURIComponent(state.currentRepository)}`);
            const res = await fetchJSON(url);
            state.data.findings = normalizeApiResponse(res);
        } catch (error) {
            state.findingRows.innerHTML = '';
            const row = document.createElement('tr');
            row.appendChild(
                createElementWithAttrs('td', 'Unable to load findings.', { colspan: colCount.toString(), class: 'empty' })
            );
            state.findingRows.appendChild(row);
            helpers.findings?.show(error.message || 'Failed to load findings.', 'error');
            return;
        }

        state.data.findings = Array.isArray(state.data.findings) ? state.data.findings : [];
        applyFindingSearch(state);
    }

    /* ---- Filter handling ---- */

    function updateFilterOptions(state) {
        if (!state.filterSelect) return;

        const teams = getUniqueTeamsFromProducts(state.data.products);
        const currentValue = state.filterSelect.value;

        state.filterSelect.innerHTML = '';
        const allOption = createElementWithAttrs('option', 'All teams', { value: '' });
        state.filterSelect.appendChild(allOption);

        teams.forEach(team => {
            state.filterSelect.appendChild(createElementWithAttrs('option', team, { value: team }));
        });

        if (teams.includes(currentValue)) {
            state.filterSelect.value = currentValue;
        } else {
            state.filterSelect.value = '';
        }
    }

    function handleFilter(state) {
        if (!state.filterSelect) return;

        state.filterSelect.addEventListener('change', () => {
            if (state.view !== 'productList') {
                switchToProductListView(state);
            }
            const filterValue = state.filterSelect.value || '';
            const filtered = filterValue
                ? state.data.products.filter(product => product.team === filterValue)
                : state.data.products;
            renderProductRows(state, filtered, filterValue);
        });
    }

    /* ---- Product list rendering ---- */

    function renderProductListTableHeader(state) {
        const { productThead, productListSort } = state;
        if (!productThead) return;

        const tr = productThead.querySelector('tr') || document.createElement('tr');
        tr.innerHTML = '';

        PRODUCT_COLUMNS.forEach(col => {
            if (col.sortable) {
                const th = createSortableHeader(col.header, col.key, productListSort, (key) => {
                    state.productListSort = toggleSortDirection(state.productListSort, key);
                    saveSortState('productList', state.productListSort);
                    renderProductListTableHeader(state);
                    const filterValue = state.filterSelect?.value || '';
                    const filtered = filterValue
                        ? state.data.products.filter(product => product.team === filterValue)
                        : state.data.products;
                    renderProductRows(state, filtered, filterValue);
                });
                tr.appendChild(th);
            } else {
                const th = document.createElement('th');
                th.textContent = col.header;
                tr.appendChild(th);
            }
        });

        if (!tr.parentNode) productThead.appendChild(tr);
    }

    function renderProductRows(state, filteredProducts, filterValue) {
        const { productRows, productCounter, productListSort } = state;
        if (!productRows || !productCounter) return;

        if (!Array.isArray(filteredProducts) || !filteredProducts.length) {
            const message = filterValue ? 'No products match this team.' : 'No products yet.';
            productRows.innerHTML = '';
            const row = document.createElement('tr');
            const cell = createElementWithAttrs('td', message, { colspan: '2', class: 'empty' });
            row.appendChild(cell);
            productRows.appendChild(row);
            productCounter.textContent = '0';
            return;
        }

        // Apply sorting
        const sorted = sortItems(filteredProducts, productListSort?.key, productListSort?.direction);

        productRows.innerHTML = '';
        sorted.forEach(product => {
            const name = product.name || '—';
            const team = product.team || '—';

            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.setAttribute('data-product-action', 'showRepos');
            row.setAttribute('data-product-name', name);
            row.setAttribute('data-product-team', team);
            row.appendChild(createElementWithAttrs('td', name));
            row.appendChild(createElementWithAttrs('td', team));
            productRows.appendChild(row);
        });

        productCounter.textContent = sorted.length;
    }

    function attachProductListInteractions(state, helpers) {
        if (!state.productRows) return;

        state.productRows.addEventListener('click', event => {
            const trigger = event.target.closest('[data-product-action="showRepos"]');
            if (!trigger) return;

            const name = trigger.getAttribute('data-product-name');
            const team = trigger.getAttribute('data-product-team');
            if (!name || !team) return;

            showProductRepositories(state, helpers, { name, team });
        });
    }

    /* ---- Repository list rendering ---- */

    function renderRepositoryListTableHeader(state) {
        const { repositoryThead, repositoryListSort } = state;
        if (!repositoryThead) return;

        const tr = repositoryThead.querySelector('tr') || document.createElement('tr');
        tr.innerHTML = '';

        REPOSITORY_COLUMNS.forEach(col => {
            if (col.sortable) {
                const th = createSortableHeader(col.header, col.key, repositoryListSort, (key) => {
                    state.repositoryListSort = toggleSortDirection(state.repositoryListSort, key);
                    saveSortState('repositoryList', state.repositoryListSort);
                    renderRepositoryListTableHeader(state);
                    renderRepositoryRows(state, state.data.repositories);
                });
                tr.appendChild(th);
            } else {
                const th = document.createElement('th');
                th.textContent = col.header;
                tr.appendChild(th);
            }
        });

        if (!tr.parentNode) repositoryThead.appendChild(tr);
    }

    function renderRepositoryRows(state, repositories) {
        const { repositoryRows, repositoryCounter, repositoryListSort } = state;
        if (!repositoryRows || !repositoryCounter) return;

        if (!Array.isArray(repositories) || !repositories.length) {
            const message = 'No repositories found for this product.';
            repositoryRows.innerHTML = '';
            const row = document.createElement('tr');
            const cell = createElementWithAttrs('td', message, { colspan: '1', class: 'empty' });
            row.appendChild(cell);
            repositoryRows.appendChild(row);
            repositoryCounter.textContent = '0';
            return;
        }

        // Apply sorting
        const sorted = sortItems(repositories, repositoryListSort?.key, repositoryListSort?.direction);

        repositoryRows.innerHTML = '';
        sorted.forEach(repo => {
            const name = repo.name || '—';

            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.setAttribute('data-repo-action', 'showFindings');
            row.setAttribute('data-repo-name', name);
            row.appendChild(createElementWithAttrs('td', name));
            repositoryRows.appendChild(row);
        });

        repositoryCounter.textContent = sorted.length;
    }

    function attachRepositoryListInteractions(state, helpers) {
        if (!state.repositoryRows) return;

        state.repositoryRows.addEventListener('click', event => {
            const trigger = event.target.closest('[data-repo-action="showFindings"]');
            if (!trigger) return;

            const name = trigger.getAttribute('data-repo-name');
            if (!name) return;

            showRepositoryFindings(state, helpers, name);
        });
    }

    /* ---- Findings table rendering ---- */

    function renderFindingsTableHeader(state) {
        const { findingThead, findingSort } = state;
        if (!findingThead) return;

        const tr = findingThead.querySelector('tr') || document.createElement('tr');
        tr.innerHTML = '';

        getVisibleColumns(state).forEach(col => {
            const th = createSortableHeader(col.header, col.key, findingSort, (key) => {
                state.findingSort = toggleSortDirection(state.findingSort, key);
                saveSortState('findings', state.findingSort);
                renderFindingsTableHeader(state);
                applyFindingSearch(state);
            });
            tr.appendChild(th);
        });

        if (!tr.parentNode) findingThead.appendChild(tr);
    }

    function renderFindingRows(state, items, emptyMessage = 'No SAST findings found.') {
        if (!state.findingRows) return;

        const visibleCols = getVisibleColumns(state);
        state.findingRows.innerHTML = '';

        if (!Array.isArray(items) || !items.length) {
            state.findingRows.innerHTML = `<tr><td colspan="${visibleCols.length}" class="empty">${emptyMessage}</td></tr>`;
            return;
        }

        items.forEach(finding => {
            const row = document.createElement('tr');
            row.style.cursor = 'pointer';

            visibleCols.forEach(col => {
                const val = col.extract(finding);
                const td = document.createElement('td');

                if (col.key === 'severity') {
                    const badge = createElementWithAttrs('span', getSeverityLabel(val), {
                        class: `severity-badge ${getSeverityBadgeClass(val)}`
                    });
                    td.appendChild(badge);
                } else if (col.key === 'confidence') {
                    const lower = String(val).toLowerCase();
                    const cls = lower === 'high' ? 'severity-high' :
                                lower === 'medium' ? 'severity-medium' :
                                lower === 'low' ? 'severity-low' : 'severity-none';
                    const badge = createElementWithAttrs('span', val || '—', {
                        class: `severity-badge ${cls}`
                    });
                    td.appendChild(badge);
                } else {
                    td.textContent = val || '—';
                }
                row.appendChild(td);
            });

            row.addEventListener('click', () => {
                showFindingDetail(state, finding);
            });

            state.findingRows.appendChild(row);
        });
    }

    /* ---- Column toggle ---- */

    function renderColumnToggleDropdown(state) {
        const { columnToggleDropdown, columnVisibility } = state;
        if (!columnToggleDropdown) return;
        columnToggleDropdown.innerHTML = '';

        SAST_COLUMNS.forEach(col => {
            const item = document.createElement('div');
            item.className = 'column-toggle-item';
            const cb = document.createElement('input');
            cb.type = 'checkbox';
            cb.checked = !!columnVisibility[col.key];
            cb.id = `code-col-toggle-${col.key}`;
            const lbl = document.createElement('label');
            lbl.textContent = col.header;
            lbl.setAttribute('for', cb.id);
            item.appendChild(cb);
            item.appendChild(lbl);
            cb.addEventListener('change', () => {
                state.columnVisibility[col.key] = cb.checked;
                saveColumnVisibility(state.columnVisibility);
                renderFindingsTableHeader(state);
                applyFindingSearch(state);
            });
            columnToggleDropdown.appendChild(item);
        });
    }

    function setupColumnToggle(state) {
        const { columnToggleBtn, columnToggleDropdown } = state;
        if (!columnToggleBtn || !columnToggleDropdown) return;

        columnToggleBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            columnToggleDropdown.classList.toggle('open');
        });

        document.addEventListener('click', (e) => {
            if (!columnToggleDropdown.contains(e.target) && e.target !== columnToggleBtn) {
                columnToggleDropdown.classList.remove('open');
            }
        });

        renderColumnToggleDropdown(state);
    }

    /* ---- Search ---- */

    function applyFindingSearch(state) {
        const source = Array.isArray(state.data.findings) ? state.data.findings : [];
        const term = state.findingSearchInput?.value?.trim().toLowerCase();
        const { findingSort } = state;

        let result = source;

        // Apply text search
        if (term) {
            const visCols = getVisibleColumns(state);
            result = result.filter(item => {
                return visCols.some(col => {
                    const text = col.extract(item);
                    return text && String(text).toLowerCase().includes(term);
                });
            });
        }

        // Apply sorting
        if (findingSort?.key) {
            result = sortItems(result, findingSort.key, findingSort.direction, SAST_COLUMNS);
        }

        renderFindingRows(state, result);
        updateFindingsSubtitle(state, source);
    }

    function updateFindingsSubtitle(state, items) {
        if (!state.findingMeta) return;
        if (state.currentTeam && state.currentProduct && state.currentRepository) {
            const count = Array.isArray(items) ? items.length : 0;
            state.findingMeta.textContent = `${state.currentTeam} / ${state.currentProduct} / ${state.currentRepository} · ${count} finding${count !== 1 ? 's' : ''}`;
        } else {
            state.findingMeta.textContent = 'Select a repository to view findings';
        }
    }

    /* ---- View switching ---- */

    function showProductRepositories(state, helpers, { name, team }) {
        state.view = 'repositoryList';
        state.currentProduct = name;
        state.currentTeam = team;
        state.currentRepository = '';

        if (state.productListCard) state.productListCard.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = false;
        if (state.findingsCard) state.findingsCard.hidden = true;
        if (state.detailCard) state.detailCard.hidden = true;

        if (state.repositoryTitle) {
            state.repositoryTitle.textContent = `${name} Repositories`;
        }
        if (state.repositoryMeta) {
            state.repositoryMeta.textContent = `${team} / ${name}`;
        }

        setPageTitle?.(`Code · ${name}`);
        loadRepositories(state, helpers);
    }

    function showRepositoryFindings(state, helpers, repositoryName) {
        state.view = 'findings';
        state.currentRepository = repositoryName;

        if (state.productListCard) state.productListCard.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = true;
        if (state.findingsCard) state.findingsCard.hidden = false;
        if (state.detailCard) state.detailCard.hidden = true;

        if (state.findingTitle) {
            state.findingTitle.textContent = `${repositoryName} Findings`;
        }

        setPageTitle?.(`Code · ${repositoryName}`);
        loadFindings(state, helpers);
    }

    function showFindingDetail(state, finding) {
        state.view = 'detail';
        state.currentFinding = finding;

        if (state.productListCard) state.productListCard.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = true;
        if (state.findingsCard) state.findingsCard.hidden = true;
        if (state.detailCard) state.detailCard.hidden = false;

        if (state.detailTitle) {
            state.detailTitle.textContent = finding.rule_id || 'Finding Details';
        }
        if (state.detailMeta) {
            const parts = [];
            if (finding.severity) parts.push(getSeverityLabel(finding.severity));
            if (finding.file_path) parts.push(`${finding.file_path}:${finding.start_line || ''}`);
            if (finding.category) parts.push(finding.category);
            state.detailMeta.textContent = parts.join(' · ');
        }

        setPageTitle?.(`Code · ${finding.rule_id || 'Finding'}`);
        renderDetailContent(state, finding);
    }

    function switchToFindingsView(state) {
        state.view = 'findings';
        if (state.productListCard) state.productListCard.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = true;
        if (state.findingsCard) state.findingsCard.hidden = false;
        if (state.detailCard) state.detailCard.hidden = true;
        setPageTitle?.(`Code · ${state.currentRepository}`);
    }

    function switchToRepositoryListView(state) {
        state.view = 'repositoryList';
        state.currentRepository = '';
        state.data.findings = [];

        if (state.productListCard) state.productListCard.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = false;
        if (state.findingsCard) state.findingsCard.hidden = true;
        if (state.detailCard) state.detailCard.hidden = true;

        setPageTitle?.(`Code · ${state.currentProduct}`);
    }

    function switchToProductListView(state) {
        state.view = 'productList';
        state.currentProduct = '';
        state.currentTeam = '';
        state.currentRepository = '';
        state.data.repositories = [];
        state.data.findings = [];

        if (state.productListCard) state.productListCard.hidden = false;
        if (state.repositoryListCard) state.repositoryListCard.hidden = true;
        if (state.findingsCard) state.findingsCard.hidden = true;
        if (state.detailCard) state.detailCard.hidden = true;

        setPageTitle?.('Code');
    }

    /* ---- Detail view ---- */

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function renderDetailContent(state, finding) {
        const container = state.detailContent;
        if (!container) return;
        container.innerHTML = '';

        // Severity + confidence row
        const metaRow = createElementWithAttrs('div', null, { class: 'sast-detail-meta' });
        const sevBadge = createElementWithAttrs('span', getSeverityLabel(finding.severity), {
            class: `severity-badge ${getSeverityBadgeClass(finding.severity)}`
        });
        metaRow.appendChild(sevBadge);
        if (finding.confidence) {
            const confBadge = createElementWithAttrs('span', `Confidence: ${finding.confidence}`, {
                class: 'severity-badge severity-none'
            });
            metaRow.appendChild(confBadge);
        }
        if (finding.impact) {
            metaRow.appendChild(createElementWithAttrs('span', `Impact: ${finding.impact}`, { class: 'sast-detail-tag' }));
        }
        if (finding.likelihood) {
            metaRow.appendChild(createElementWithAttrs('span', `Likelihood: ${finding.likelihood}`, { class: 'sast-detail-tag' }));
        }
        container.appendChild(metaRow);

        // Location
        const loc = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
        loc.innerHTML = `<strong>Location:</strong> ${escapeHtml(finding.file_path || '')}:${finding.start_line || ''}:${finding.start_col || ''} – ${finding.end_line || ''}:${finding.end_col || ''}`;
        container.appendChild(loc);

        // Message
        if (finding.message) {
            const msg = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            msg.innerHTML = `<strong>Message:</strong>`;
            const msgText = createElementWithAttrs('p', finding.message);
            msg.appendChild(msgText);
            container.appendChild(msg);
        }

        // Code snippet
        if (finding.code_snippet) {
            const codeSection = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            codeSection.innerHTML = `<strong>Code:</strong>`;
            const codeBlock = createElementWithAttrs('pre', null, { class: 'sast-code-block' });
            const codeEl = createElementWithAttrs('code', finding.code_snippet);
            codeBlock.appendChild(codeEl);
            codeSection.appendChild(codeBlock);
            container.appendChild(codeSection);
        }

        // Suggested fix
        if (finding.suggested_fix) {
            const fixSection = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            fixSection.innerHTML = `<strong>Suggested Fix:</strong>`;
            const fixBlock = createElementWithAttrs('pre', null, { class: 'sast-code-block' });
            const fixEl = createElementWithAttrs('code', finding.suggested_fix);
            fixBlock.appendChild(fixEl);
            fixSection.appendChild(fixBlock);
            container.appendChild(fixSection);
        }

        // CWEs
        const cwes = Array.isArray(finding.cwes) ? finding.cwes : [];
        if (cwes.length) {
            const cweSection = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            cweSection.innerHTML = `<strong>CWEs:</strong> ${escapeHtml(cwes.map(c => `${c.id || c} ${c.name ? '– ' + c.name : ''}`).join(', '))}`;
            container.appendChild(cweSection);
        }

        // OWASP
        const owasp = Array.isArray(finding.owasp) ? finding.owasp : [];
        if (owasp.length) {
            const owaspSection = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            owaspSection.innerHTML = `<strong>OWASP:</strong> ${escapeHtml(owasp.join(', '))}`;
            container.appendChild(owaspSection);
        }

        // References
        const refs = Array.isArray(finding.refs) ? finding.refs : [];
        if (refs.length) {
            const refSection = createElementWithAttrs('div', null, { class: 'sast-detail-field' });
            refSection.innerHTML = `<strong>References:</strong>`;
            const refList = createElementWithAttrs('ul', null, { class: 'sast-detail-refs' });
            refs.forEach(ref => {
                const li = createElementWithAttrs('li');
                const a = createElementWithAttrs('a', ref, { href: ref, target: '_blank', rel: 'noopener noreferrer' });
                li.appendChild(a);
                refList.appendChild(li);
            });
            refSection.appendChild(refList);
            container.appendChild(refSection);
        }

        // Extra metadata
        const extras = [];
        if (finding.category) extras.push(`Category: ${finding.category}`);
        if (Array.isArray(finding.subcategory) && finding.subcategory.length) extras.push(`Subcategory: ${finding.subcategory.join(', ')}`);
        if (Array.isArray(finding.technology) && finding.technology.length) extras.push(`Technology: ${finding.technology.join(', ')}`);
        if (Array.isArray(finding.vulnerability_class) && finding.vulnerability_class.length) extras.push(`Vulnerability Class: ${finding.vulnerability_class.join(', ')}`);
        if (finding.engine_kind) extras.push(`Engine: ${finding.engine_kind}`);
        if (finding.validation_state) extras.push(`Validation: ${finding.validation_state}`);
        if (finding.fingerprint) extras.push(`Fingerprint: ${truncate(finding.fingerprint, 40)}`);

        if (extras.length) {
            const extraSection = createElementWithAttrs('div', null, { class: 'sast-detail-field sast-detail-extras' });
            extraSection.innerHTML = `<strong>Details:</strong>`;
            const dl = createElementWithAttrs('div', null, { class: 'sast-detail-tags' });
            extras.forEach(e => {
                dl.appendChild(createElementWithAttrs('span', e, { class: 'sast-detail-tag' }));
            });
            extraSection.appendChild(dl);
            container.appendChild(extraSection);
        }
    }

    /* ---- Page renderer ---- */

    function renderCodePage() {
        const root = document.getElementById('vmaContent');
        if (!root) return null;

        setActiveRoute?.('code');
        setPageTitle?.('Code');
        clearElement(root);

        const defaultColCount = getVisibleColumns({ columnVisibility: getDefaultVisibility() }).length;

        const wrapper = createElementWithAttrs('section', '', { class: 'code-page' });

        // Product list card
        const productListCard = createElementWithAttrs('div', '', { class: 'table-card page-section' });
        productListCard.innerHTML = `
            <div class="table-header">
                <h2>Products</h2>
                <div class="inline-filter">
                    <label class="sr-only" for="code-filter">Filter by team</label>
                    <select id="code-filter" data-code-filter>
                        <option value="">All teams</option>
                    </select>
                    <span class="badge" data-code-product-count>0</span>
                </div>
            </div>
            <div class="inline-message" data-code-product-list-feedback hidden></div>
            <table class="data-table">
                <thead data-code-product-thead><tr></tr></thead>
                <tbody data-code-product-rows>
                    <tr><td colspan="2" class="empty">Loading…</td></tr>
                </tbody>
            </table>
        `;

        // Repository list card
        const repositoryListCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: true,
            'data-code-repository-card': ''
        });
        repositoryListCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2 data-code-repository-title>Repositories</h2>
                    <p class="table-subtitle" data-code-repository-meta></p>
                </div>
                <div class="table-header__actions">
                    <button type="button" class="btn link" data-code-repo-back>
                        <i class="fas fa-arrow-left"></i>
                        Go back
                    </button>
                    <span class="badge" data-code-repository-count>0</span>
                </div>
            </div>
            <div class="inline-message" data-code-repository-feedback hidden></div>
            <table class="data-table">
                <thead data-code-repository-thead><tr></tr></thead>
                <tbody data-code-repository-rows>
                    <tr><td colspan="1" class="empty">Select a product to view repositories.</td></tr>
                </tbody>
            </table>
        `;

        // Findings card
        const findingsCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: true,
            'data-code-findings-card': ''
        });
        findingsCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2 data-code-finding-title>SAST Findings</h2>
                    <p class="table-subtitle" data-code-finding-meta>Select a repository to view findings</p>
                </div>
                <div class="table-header__actions">
                    <button type="button" class="btn link" data-code-findings-back>
                        <i class="fas fa-arrow-left"></i>
                        Go back
                    </button>
                    <div class="column-toggle-wrapper">
                        <button type="button" class="btn secondary" data-code-column-toggle-btn>
                            <i class="fas fa-table-columns"></i> Columns
                        </button>
                        <div class="column-toggle-dropdown" data-code-column-toggle-dropdown></div>
                    </div>
                    <label class="sr-only" for="code-finding-search">Search findings</label>
                    <input
                        type="search"
                        id="code-finding-search"
                        class="table-search"
                        placeholder="Search findings…"
                        data-code-finding-search
                    >
                </div>
            </div>
            <div class="inline-message" data-code-findings-feedback hidden></div>
            <table class="data-table">
                <thead data-code-finding-thead><tr></tr></thead>
                <tbody data-code-finding-rows>
                    <tr><td colspan="${defaultColCount}" class="empty">Select a repository to view findings.</td></tr>
                </tbody>
            </table>
        `;

        // Detail card
        const detailCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: true,
            'data-code-detail-card': ''
        });
        detailCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2 data-code-detail-title>Finding Details</h2>
                    <p class="table-subtitle" data-code-detail-meta></p>
                </div>
                <div class="table-header__actions">
                    <button type="button" class="btn link" data-code-detail-back>
                        <i class="fas fa-arrow-left"></i>
                        Back to findings
                    </button>
                </div>
            </div>
            <div class="sast-detail-content" data-code-detail-content></div>
        `;

        wrapper.appendChild(productListCard);
        wrapper.appendChild(repositoryListCard);
        wrapper.appendChild(findingsCard);
        wrapper.appendChild(detailCard);
        root.appendChild(wrapper);

        return {
            productListCard,
            repositoryListCard,
            findingsCard,
            detailCard,
            filterSelect: productListCard.querySelector('[data-code-filter]'),
            productCounter: productListCard.querySelector('[data-code-product-count]'),
            productThead: productListCard.querySelector('[data-code-product-thead]'),
            productRows: productListCard.querySelector('[data-code-product-rows]'),
            productListFeedback: productListCard.querySelector('[data-code-product-list-feedback]'),
            repositoryTitle: repositoryListCard.querySelector('[data-code-repository-title]'),
            repositoryMeta: repositoryListCard.querySelector('[data-code-repository-meta]'),
            repositoryCounter: repositoryListCard.querySelector('[data-code-repository-count]'),
            repositoryBackButton: repositoryListCard.querySelector('[data-code-repo-back]'),
            repositoryThead: repositoryListCard.querySelector('[data-code-repository-thead]'),
            repositoryRows: repositoryListCard.querySelector('[data-code-repository-rows]'),
            repositoryFeedback: repositoryListCard.querySelector('[data-code-repository-feedback]'),
            findingTitle: findingsCard.querySelector('[data-code-finding-title]'),
            findingMeta: findingsCard.querySelector('[data-code-finding-meta]'),
            findingsBackButton: findingsCard.querySelector('[data-code-findings-back]'),
            columnToggleBtn: findingsCard.querySelector('[data-code-column-toggle-btn]'),
            columnToggleDropdown: findingsCard.querySelector('[data-code-column-toggle-dropdown]'),
            findingSearchInput: findingsCard.querySelector('[data-code-finding-search]'),
            findingThead: findingsCard.querySelector('[data-code-finding-thead]'),
            findingRows: findingsCard.querySelector('[data-code-finding-rows]'),
            findingsFeedback: findingsCard.querySelector('[data-code-findings-feedback]'),
            detailTitle: detailCard.querySelector('[data-code-detail-title]'),
            detailMeta: detailCard.querySelector('[data-code-detail-meta]'),
            detailContent: detailCard.querySelector('[data-code-detail-content]'),
            detailBackButton: detailCard.querySelector('[data-code-detail-back]'),
            columnVisibility: loadColumnVisibility() || getDefaultVisibility(),
            data: { products: [], repositories: [], findings: [] },
            currentTeam: '',
            currentProduct: '',
            currentRepository: '',
            currentFinding: null,
            view: 'productList',
            productListSort: loadSortState('productList') || { key: 'name', direction: 'asc' },
            repositoryListSort: loadSortState('repositoryList') || { key: 'name', direction: 'asc' },
            findingSort: loadSortState('findings') || { key: 'severity', direction: 'desc' }
        };
    }

    /* ---- Route registration ---- */

    registerRoute('code', async () => {
        const state = renderCodePage();
        if (!state) return;

        const helpers = {
            productList: createMessageHelper(state.productListFeedback),
            repositories: createMessageHelper(state.repositoryFeedback),
            findings: createMessageHelper(state.findingsFeedback)
        };

        // Load products and render list
        await loadProducts(state, helpers);
        renderProductListTableHeader(state);

        // Filter change handler
        handleFilter(state);

        // List interactions
        attachProductListInteractions(state, helpers);
        attachRepositoryListInteractions(state, helpers);

        // Repository list table header
        renderRepositoryListTableHeader(state);

        // Findings search handler
        if (state.findingSearchInput) {
            state.findingSearchInput.addEventListener('input', () => applyFindingSearch(state));
        }

        // Column toggle
        setupColumnToggle(state);
        renderFindingsTableHeader(state);

        // Back buttons
        if (state.repositoryBackButton) {
            state.repositoryBackButton.addEventListener('click', () => switchToProductListView(state));
        }
        if (state.findingsBackButton) {
            state.findingsBackButton.addEventListener('click', () => switchToRepositoryListView(state));
        }
        if (state.detailBackButton) {
            state.detailBackButton.addEventListener('click', () => switchToFindingsView(state));
        }
    });
})();
