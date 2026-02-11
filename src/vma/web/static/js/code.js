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
        selectHelpers,
        createFormToggle,
        components
    } = utils;

    const { createToolbar } = components || {};

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

    /* ---- Repository List columns ---- */
    const REPOSITORY_COLUMNS = [
        { key: 'name', header: 'Repository', sortable: true },
        { key: 'product', header: 'Product', sortable: true },
        { key: 'team', header: 'Team', sortable: true },
        { key: 'url', header: 'URL', sortable: true }
    ];

    const REPOSITORY_FILTER_STORAGE_KEY = 'vma.code.repository.filter';

    function loadRepositoryFilter() {
        try {
            const raw = localStorage.getItem(REPOSITORY_FILTER_STORAGE_KEY);
            return raw ? JSON.parse(raw) : { team: '', product: '' };
        } catch {
            return { team: '', product: '' };
        }
    }

    function saveRepositoryFilter(filter) {
        try {
            localStorage.setItem(REPOSITORY_FILTER_STORAGE_KEY, JSON.stringify(filter));
        } catch { /* ignore */ }
    }

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

    function extractUniqueRepositories(sastData, { team = '', product = '' } = {}) {
        if (!Array.isArray(sastData)) return [];
        const repoNames = sastData
            .map(item => item.repository)
            .filter(Boolean);
        const unique = Array.from(new Set(repoNames));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique.map(name => ({ name, team, product }));
    }

    /* ---- Data loading ---- */

    async function loadProducts(state, helpers) {
        try {
            const res = await fetchJSON(apiUrl('/products'));
            state.data.products = normalizeApiResponse(res).map(parseProductRecord);
        } catch (error) {
            state.data.products = [];
            helpers.repositories?.show(error.message || 'Failed to fetch products.', 'error');
            return;
        }

        state.data.products = Array.isArray(state.data.products) ? state.data.products : [];
        populateRepositoryTeamOptions(state);
        updateRepositoryProductOptions(state, 'create');
        updateRepositoryProductOptions(state, 'delete');
    }

    async function loadRepositories(state, helpers) {
        state.repositoryRows.innerHTML = '';
        const loadingRow = document.createElement('tr');
        loadingRow.appendChild(createElementWithAttrs('td', 'Loading repositories…', { colspan: REPOSITORY_COLUMNS.length.toString(), class: 'empty' }));
        state.repositoryRows.appendChild(loadingRow);

        try {
            if (!state.data.products.length) {
                await loadProducts(state, helpers);
            }

            const teams = getUniqueTeamsFromProducts(state.data.products);
            if (!teams.length) {
                state.data.repositories = [];
                renderRepositoryRows(state, []);
                return;
            }

            const responses = await Promise.all(teams.map(async team => {
                try {
                    const url = apiUrl(`/repo/${encodeURIComponent(team)}`);
                    const res = await fetchJSON(url);
                    return normalizeApiResponse(res);
                } catch (error) {
                    const products = state.data.products.filter(product => product.team === team);
                    const fallback = [];
                    for (const product of products) {
                        try {
                            const sastUrl = apiUrl(`/sast/${encodeURIComponent(team)}/${encodeURIComponent(product.name)}`);
                            const sastRes = await fetchJSON(sastUrl);
                            const sastData = normalizeApiResponse(sastRes);
                            fallback.push(...extractUniqueRepositories(sastData, { team, product: product.name }));
                        } catch (sastError) {
                            continue;
                        }
                    }
                    return fallback;
                }
            }));

            state.data.repositories = responses.flat().filter(Boolean);
        } catch (error) {
            state.repositoryRows.innerHTML = '';
            const row = document.createElement('tr');
            const colCount = REPOSITORY_COLUMNS.length.toString();
            row.appendChild(
                createElementWithAttrs('td', 'Unable to load repositories.', { colspan: colCount, class: 'empty' })
            );
            state.repositoryRows.appendChild(row);
            helpers.repositories?.show(error.message || 'Failed to load repositories.', 'error');
            return;
        }

        renderRepositoryRows(state, state.data.repositories);
        updateRepositoryDeleteOptions(state);
        applyRepositoryFilters(state);
        updateRepositoryMeta(state);
    }

    function updateRepositoryFilters(state) {
        const teams = getUniqueTeamsFromProducts(state.data.products).map(name => ({ name }));
        selectHelpers.populate(state.repositoryTeamFilter, teams, {
            valueKey: item => item.name,
            labelKey: item => item.name,
            placeholder: teams.length ? 'All teams' : 'No teams available',
            preserveValue: true
        });

        const teamValue = state.repositoryTeamFilter?.value || '';
        const products = teamValue
            ? state.data.products.filter(product => (product.team ?? product.team_id) === teamValue)
            : state.data.products;

        selectHelpers.populate(state.repositoryProductFilter, products, {
            valueKey: item => item.name,
            labelKey: item => item.name,
            placeholder: products.length ? 'All products' : 'No products available',
            preserveValue: true
        });
    }

    function applyRepositoryFilters(state) {
        const teamValue = state.repositoryTeamFilter?.value || '';
        const productValue = state.repositoryProductFilter?.value || '';

        const filtered = (state.data.repositories || []).filter(repo => {
            if (teamValue && repo.team !== teamValue) return false;
            if (productValue && repo.product !== productValue) return false;
            return true;
        });

        renderRepositoryRows(state, filtered);
        saveRepositoryFilter({ team: teamValue, product: productValue });
    }

    function populateRepositoryTeamOptions(state) {
        const teams = getUniqueTeamsFromProducts(state.data.products).map(name => ({ name }));
        selectHelpers.populate(state.repositoryTeamSelect, teams, {
            valueKey: item => item.name,
            labelKey: item => item.name,
            placeholder: teams.length ? 'Select a team…' : 'No teams available',
            preserveValue: true
        });
        selectHelpers.populate(state.repositoryDeleteTeamSelect, teams, {
            valueKey: item => item.name,
            labelKey: item => item.name,
            placeholder: teams.length ? 'Select a team…' : 'No teams available',
            preserveValue: true
        });
    }

    function updateRepositoryProductOptions(state, context = 'create') {
        const isDelete = context === 'delete';
        const teamSelect = isDelete ? state.repositoryDeleteTeamSelect : state.repositoryTeamSelect;
        const productSelect = isDelete ? state.repositoryDeleteProductSelect : state.repositoryProductSelect;

        if (!productSelect) {
            return;
        }

        const team = teamSelect?.value || '';
        const products = state.data.products.filter(product => (product.team ?? product.team_id) === team);
        selectHelpers.populate(productSelect, products, {
            valueKey: item => item.name,
            labelKey: item => item.name,
            placeholder: team ? 'Select a product…' : 'Select a team first…',
            preserveValue: true
        });

        productSelect.disabled = !team || !products.length;
        if (isDelete) {
            updateRepositoryDeleteOptions(state);
        }
    }

    function updateRepositoryMeta(state) {
        const label = state.currentTeam && state.currentProduct
            ? `${state.currentTeam} / ${state.currentProduct}`
            : 'All repositories';

        if (state.repositoryCreateMeta) {
            state.repositoryCreateMeta.textContent = label;
        }
        if (state.repositoryDeleteMeta) {
            state.repositoryDeleteMeta.textContent = label;
        }
        if (state.repositoryToolbar) {
            const subtitle = state.repositoryToolbar.querySelector('.toolbar-subtitle');
            if (subtitle) {
                subtitle.textContent = label;
            }
        }
    }

    function updateRepositoryDeleteOptions(state) {
        if (!state.repositoryDeleteSelect) {
            return;
        }

        const team = state.repositoryDeleteTeamSelect?.value || '';
        const product = state.repositoryDeleteProductSelect?.value || '';

        state.repositoryDeleteSelect.innerHTML = '';
        const placeholder = team && product ? 'Select a repository…' : 'Select a team and product first…';
        state.repositoryDeleteSelect.appendChild(
            createElementWithAttrs('option', placeholder, { value: '' })
        );

        if (!team || !product) {
            state.repositoryDeleteSelect.disabled = true;
            return;
        }

        const repositories = Array.isArray(state.data.repositories) ? state.data.repositories : [];
        repositories
            .filter(repo => (repo.team ?? '') === team && (repo.product ?? '') === product)
            .forEach(repo => {
                const name = repo.name || '';
                if (!name) return;
                state.repositoryDeleteSelect.appendChild(
                    createElementWithAttrs('option', name, { value: name })
                );
            });

        state.repositoryDeleteSelect.disabled = state.repositoryDeleteSelect.options.length <= 1;
    }

    function setupRepositoryFormToggles(state, helpers) {
        const createToggle = createFormToggle({
            button: state.repositoryCreateToggle,
            container: state.repositoryCreateCard,
            form: state.repositoryCreateForm,
            labels: {
                open: '<i class="fas fa-plus"></i> Add Repository',
                close: '<i class="fas fa-times"></i> Cancel'
            },
            onShow: () => helpers.repositoryCreate?.hide(),
            onHide: () => helpers.repositoryCreate?.hide()
        });

        const deleteToggle = createFormToggle({
            button: state.repositoryDeleteToggle,
            container: state.repositoryDeleteCard,
            form: state.repositoryDeleteForm,
            labels: {
                open: '<i class="fas fa-trash"></i> Delete Repository',
                close: '<i class="fas fa-times"></i> Cancel Delete'
            },
            onShow: () => helpers.repositoryDelete?.hide(),
            onHide: () => {
                helpers.repositoryDelete?.hide();
                updateRepositoryDeleteOptions(state);
            }
        });

        state.setRepositoryCreateVisible = createToggle.setVisible;
        state.setRepositoryDeleteVisible = deleteToggle.setVisible;
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
            const message = 'No repositories found.';
            repositoryRows.innerHTML = '';
            const row = document.createElement('tr');
            const cell = createElementWithAttrs('td', message, { colspan: REPOSITORY_COLUMNS.length.toString(), class: 'empty' });
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
            const url = repo.url || '—';
            const product = repo.product || '—';
            const team = repo.team || '—';

            const row = document.createElement('tr');
            row.style.cursor = 'pointer';
            row.setAttribute('data-repo-action', 'showFindings');
            row.setAttribute('data-repo-name', name);
            row.setAttribute('data-repo-product', product);
            row.setAttribute('data-repo-team', team);
            row.appendChild(createElementWithAttrs('td', name));
            row.appendChild(createElementWithAttrs('td', product));
            row.appendChild(createElementWithAttrs('td', team));
            row.appendChild(createElementWithAttrs('td', url));
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
            const product = trigger.getAttribute('data-repo-product');
            const team = trigger.getAttribute('data-repo-team');
            if (!name) return;

            showRepositoryFindings(state, helpers, { name, product, team });
        });
    }

    function handleRepositoryCreateForm(state, helpers) {
        if (!state.repositoryCreateForm) return;

        state.repositoryCreateForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.repositoryCreate?.hide();

            const name = state.repositoryCreateForm.querySelector('#code-repo-name')?.value?.trim();
            const url = state.repositoryCreateForm.querySelector('#code-repo-url')?.value?.trim();
            const team = state.repositoryTeamSelect?.value?.trim();
            const product = state.repositoryProductSelect?.value?.trim();

            if (!team || !product) {
                helpers.repositoryCreate?.show('Select a team and product before adding a repository.', 'error');
                return;
            }

            if (!name || !url) {
                helpers.repositoryCreate?.show('Repository name and URL are required.', 'error');
                return;
            }

            try {
                const payload = await fetchJSON(apiUrl('/repo'), {
                    method: 'POST',
                    body: JSON.stringify({ product, team, name, url })
                });

                if (!payload || payload.status === false) {
                    throw new Error('Failed to create repository.');
                }

                state.repositoryCreateForm.reset();
                await loadRepositories(state, helpers);
                helpers.repositoryCreate?.show('Repository created successfully.', 'success');
            } catch (error) {
                helpers.repositoryCreate?.show(error.message || 'Failed to create repository.', 'error');
            }
        });

        state.repositoryCreateForm.addEventListener('reset', () => {
            helpers.repositoryCreate?.hide();
            if (state.repositoryTeamSelect) {
                state.repositoryTeamSelect.value = '';
            }
            if (state.repositoryProductSelect) {
                selectHelpers.reset(state.repositoryProductSelect, 'Select a team first…');
                state.repositoryProductSelect.disabled = true;
            }
        });
    }

    function handleRepositoryDeleteForm(state, helpers) {
        if (!state.repositoryDeleteForm) return;

        state.repositoryDeleteForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.repositoryDelete?.hide();

            const name = state.repositoryDeleteSelect?.value?.trim();
            const team = state.repositoryDeleteTeamSelect?.value?.trim();
            const product = state.repositoryDeleteProductSelect?.value?.trim();

            if (!team || !product) {
                helpers.repositoryDelete?.show('Select a team and product before deleting a repository.', 'error');
                return;
            }

            if (!name) {
                helpers.repositoryDelete?.show('Select a repository to delete.', 'error');
                return;
            }

            try {
                const endpoint = `/repo/${encodeURIComponent(team)}/${encodeURIComponent(product)}/${encodeURIComponent(name)}`;
                const payload = await fetchJSON(apiUrl(endpoint), { method: 'DELETE' });

                if (!payload || payload.status === false) {
                    throw new Error('Failed to delete repository.');
                }

                await loadRepositories(state, helpers);
                helpers.repositoryDelete?.show('Repository deleted successfully.', 'success');
            } catch (error) {
                helpers.repositoryDelete?.show(error.message || 'Failed to delete repository.', 'error');
            }
        });

        state.repositoryDeleteForm.addEventListener('reset', () => {
            helpers.repositoryDelete?.hide();
            if (state.repositoryDeleteTeamSelect) {
                state.repositoryDeleteTeamSelect.value = '';
            }
            if (state.repositoryDeleteProductSelect) {
                selectHelpers.reset(state.repositoryDeleteProductSelect, 'Select a team first…');
                state.repositoryDeleteProductSelect.disabled = true;
            }
            updateRepositoryDeleteOptions(state);
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

    function showRepositoryFindings(state, helpers, repositoryMeta) {
        const { name, product, team } = repositoryMeta || {};
        state.view = 'findings';
        state.currentRepository = name || '';
        state.currentProduct = product || '';
        state.currentTeam = team || '';

        state.setRepositoryCreateVisible?.(false);
        state.setRepositoryDeleteVisible?.(false);

        // Hide list view, show edit view
        if (state.listView) state.listView.hidden = true;
        if (state.editView) state.editView.hidden = false;
        if (state.findingsCard) state.findingsCard.hidden = false;
        if (state.detailCard) state.detailCard.hidden = true;

        if (state.findingTitle) {
            state.findingTitle.textContent = `${name || 'Repository'} Findings`;
        }
        if (state.findingMeta) {
            state.findingMeta.textContent = `${team} / ${product}`;
        }

        setPageTitle?.(`Code · ${name || 'Repository'}`);
        loadFindings(state, helpers);
    }

    function showFindingDetail(state, finding) {
        state.view = 'detail';
        state.currentFinding = finding;

        state.setRepositoryCreateVisible?.(false);
        state.setRepositoryDeleteVisible?.(false);

        // Stay in edit view, just switch cards
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

        state.setRepositoryCreateVisible?.(false);
        state.setRepositoryDeleteVisible?.(false);

        // Stay in edit view, just switch cards
        if (state.findingsCard) state.findingsCard.hidden = false;
        if (state.detailCard) state.detailCard.hidden = true;

        setPageTitle?.(`Code · ${state.currentRepository}`);
    }

    function switchToRepositoryListView(state) {
        state.view = 'repositoryList';
        state.currentRepository = '';
        state.currentTeam = '';
        state.currentProduct = '';
        state.data.findings = [];

        state.setRepositoryCreateVisible?.(false);
        state.setRepositoryDeleteVisible?.(false);

        // Hide edit view, show list view
        if (state.editView) state.editView.hidden = true;
        if (state.listView) state.listView.hidden = false;

        setPageTitle?.('Code');
        updateRepositoryMeta(state);
        applyRepositoryFilters(state);
    }

    function switchToProductListView(state) {
        state.view = 'repositoryList';
        state.currentProduct = '';
        state.currentTeam = '';
        state.currentRepository = '';
        state.data.repositories = [];
        state.data.findings = [];

        if (state.repositoryToolbar) state.repositoryToolbar.hidden = true;
        if (state.repositoryListCard) state.repositoryListCard.hidden = true;
        if (state.repositoryCreateCard) state.repositoryCreateCard.hidden = true;
        if (state.repositoryDeleteCard) state.repositoryDeleteCard.hidden = true;
        if (state.findingsCard) state.findingsCard.hidden = true;
        if (state.detailCard) state.detailCard.hidden = true;

        state.setRepositoryCreateVisible?.(false);
        state.setRepositoryDeleteVisible?.(false);

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

        // Repository list card
        const repositoryToolbar = createToolbar ? createToolbar({
            title: 'Repositories',
            subtitle: '',
            buttons: [
                {
                    label: 'Add Repository',
                    icon: 'fas fa-plus',
                    className: 'btn primary',
                    attributes: { 'data-code-repo-create-toggle': '' }
                },
                {
                    label: 'Delete Repository',
                    icon: 'fas fa-trash',
                    className: 'btn danger',
                    attributes: { 'data-code-repo-delete-toggle': '' }
                }
            ]
        }) : null;
        if (repositoryToolbar) {
            repositoryToolbar.hidden = false;
        }

        const repositoryListCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: false,
            'data-code-repository-card': ''
        });
        repositoryListCard.innerHTML = `
            <div class="table-header">
                <h2 data-code-repository-title>Repositories</h2>
                <div class="inline-filter">
                    <label class="sr-only" for="code-repo-team-filter">Filter by team</label>
                    <select id="code-repo-team-filter" data-code-repo-team-filter>
                        <option value="">All teams</option>
                    </select>
                    <label class="sr-only" for="code-repo-product-filter">Filter by product</label>
                    <select id="code-repo-product-filter" data-code-repo-product-filter>
                        <option value="">All products</option>
                    </select>
                    <span class="badge" data-code-repository-count>0</span>
                </div>
            </div>
            <div class="inline-message" data-code-repository-feedback hidden></div>
            <table class="data-table">
                <thead data-code-repository-thead><tr></tr></thead>
                <tbody data-code-repository-rows>
                    <tr><td colspan="4" class="empty">Loading repositories…</td></tr>
                </tbody>
            </table>
        `;

        const repositoryCreateCard = createElementWithAttrs('div', '', {
            class: 'form-card page-section hidden-form',
            hidden: true,
            'data-code-repository-create-card': ''
        });
        repositoryCreateCard.innerHTML = `
            <h3>Add Repository</h3>
            <p class="table-subtitle" data-code-repository-create-meta></p>
            <form data-code-repository-create-form>
                <div class="form-group">
                    <label for="code-repo-team">Team</label>
                    <select id="code-repo-team" name="team" required>
                        <option value="">Select a team…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="code-repo-product">Product</label>
                    <select id="code-repo-product" name="product" required disabled>
                        <option value="">Select a team first…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="code-repo-name">Repository name</label>
                    <input type="text" id="code-repo-name" name="name" placeholder="backend-service" required>
                </div>
                <div class="form-group">
                    <label for="code-repo-url">Repository URL</label>
                    <input type="url" id="code-repo-url" name="url" placeholder="https://github.com/org/repo" required>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Add Repository
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-code-repository-create-feedback hidden></div>
        `;

        const repositoryDeleteCard = createElementWithAttrs('div', '', {
            class: 'form-card page-section hidden-form',
            hidden: true,
            'data-code-repository-delete-card': ''
        });
        repositoryDeleteCard.innerHTML = `
            <h3>Delete Repository</h3>
            <p class="table-subtitle" data-code-repository-delete-meta></p>
            <form class="compare-form" data-code-repository-delete-form>
                <div class="form-group">
                    <label for="code-repo-delete-team">Team</label>
                    <select id="code-repo-delete-team" name="team" required>
                        <option value="">Select a team…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="code-repo-delete-product">Product</label>
                    <select id="code-repo-delete-product" name="product" required disabled>
                        <option value="">Select a team first…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="code-repo-delete-name">Repository</label>
                    <select id="code-repo-delete-name" name="name" required disabled>
                        <option value="">Select a repository…</option>
                    </select>
                </div>
                <div class="form-actions compare-actions">
                    <button type="submit" class="btn danger">
                        <i class="fas fa-trash"></i>
                        Delete Repository
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-code-repository-delete-feedback hidden></div>
        `;

        // Findings card
        const findingsCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            'data-code-findings-card': ''
        });
        findingsCard.innerHTML = `
            <div class="table-header">
                <h3>Findings</h3>
                <div class="table-header__actions">
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
                    <button type="button" class="btn secondary" data-code-detail-back>
                        <i class="fas fa-arrow-left"></i>
                        Back to Findings
                    </button>
                </div>
            </div>
            <div class="sast-detail-content" data-code-detail-content></div>
        `;

        // List view (contains toolbar, create/delete forms, and repository list)
        const listView = createElementWithAttrs('div', '', { class: 'list-view', 'data-list-view': '' });
        if (repositoryToolbar) {
            listView.appendChild(repositoryToolbar);
        }
        listView.appendChild(repositoryCreateCard);
        listView.appendChild(repositoryDeleteCard);
        listView.appendChild(repositoryListCard);

        // Edit view header (toolbar for findings)
        const editViewHeader = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        editViewHeader.innerHTML = `
            <div>
                <h2 data-code-finding-title>SAST Findings</h2>
                <p class="toolbar-subtitle" data-code-finding-meta>Select a repository to view findings</p>
            </div>
            <div class="toolbar-actions">
                <button type="button" class="btn secondary" data-code-findings-back>
                    <i class="fas fa-arrow-left"></i> Back to Repositories
                </button>
            </div>
        `;

        // Edit view (findings and detail cards)
        const editView = createElementWithAttrs('div', '', { class: 'edit-view', 'data-edit-view': '', hidden: true });
        editView.appendChild(editViewHeader);
        editView.appendChild(findingsCard);
        editView.appendChild(detailCard);

        wrapper.appendChild(listView);
        wrapper.appendChild(editView);
        root.appendChild(wrapper);

        return {
            listView,
            editView,
            editViewHeader,
            repositoryToolbar,
            repositoryListCard,
            findingsCard,
            detailCard,
            repositoryCounter: repositoryListCard.querySelector('[data-code-repository-count]'),
            repositoryCreateToggle: repositoryToolbar?.buttons?.[0] || repositoryListCard.querySelector('[data-code-repo-create-toggle]'),
            repositoryDeleteToggle: repositoryToolbar?.buttons?.[1] || repositoryListCard.querySelector('[data-code-repo-delete-toggle]'),
            repositoryThead: repositoryListCard.querySelector('[data-code-repository-thead]'),
            repositoryRows: repositoryListCard.querySelector('[data-code-repository-rows]'),
            repositoryFeedback: repositoryListCard.querySelector('[data-code-repository-feedback]'),
            repositoryTeamFilter: repositoryListCard.querySelector('[data-code-repo-team-filter]'),
            repositoryProductFilter: repositoryListCard.querySelector('[data-code-repo-product-filter]'),
            repositoryCreateCard,
            repositoryCreateForm: repositoryCreateCard.querySelector('[data-code-repository-create-form]'),
            repositoryCreateFeedback: repositoryCreateCard.querySelector('[data-code-repository-create-feedback]'),
            repositoryCreateMeta: repositoryCreateCard.querySelector('[data-code-repository-create-meta]'),
            repositoryTeamSelect: repositoryCreateCard.querySelector('#code-repo-team'),
            repositoryProductSelect: repositoryCreateCard.querySelector('#code-repo-product'),
            repositoryDeleteCard,
            repositoryDeleteForm: repositoryDeleteCard.querySelector('[data-code-repository-delete-form]'),
            repositoryDeleteFeedback: repositoryDeleteCard.querySelector('[data-code-repository-delete-feedback]'),
            repositoryDeleteTeamSelect: repositoryDeleteCard.querySelector('#code-repo-delete-team'),
            repositoryDeleteProductSelect: repositoryDeleteCard.querySelector('#code-repo-delete-product'),
            repositoryDeleteSelect: repositoryDeleteCard.querySelector('#code-repo-delete-name'),
            repositoryDeleteMeta: repositoryDeleteCard.querySelector('[data-code-repository-delete-meta]'),
            findingTitle: editViewHeader.querySelector('[data-code-finding-title]'),
            findingMeta: editViewHeader.querySelector('[data-code-finding-meta]'),
            findingsBackButton: editViewHeader.querySelector('[data-code-findings-back]'),
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
            view: 'repositoryList',
            repositoryListSort: loadSortState('repositoryList') || { key: 'name', direction: 'asc' },
            findingSort: loadSortState('findings') || { key: 'severity', direction: 'desc' }
        };
    }

    /* ---- Route registration ---- */

    registerRoute('code', async () => {
        const state = renderCodePage();
        if (!state) return;

        const helpers = {
            repositories: createMessageHelper(state.repositoryFeedback),
            findings: createMessageHelper(state.findingsFeedback),
            repositoryCreate: createMessageHelper(state.repositoryCreateFeedback),
            repositoryDelete: createMessageHelper(state.repositoryDeleteFeedback)
        };

        // Load products and render list
        await loadProducts(state, helpers);
        updateRepositoryFilters(state);
        await loadRepositories(state, helpers);
        updateRepositoryMeta(state);

        const savedFilter = loadRepositoryFilter();
        if (state.repositoryTeamFilter) {
            state.repositoryTeamFilter.value = savedFilter.team || '';
        }
        if (state.repositoryProductFilter) {
            state.repositoryProductFilter.value = savedFilter.product || '';
        }
        updateRepositoryFilters(state);
        applyRepositoryFilters(state);
        attachRepositoryListInteractions(state, helpers);
        handleRepositoryCreateForm(state, helpers);
        handleRepositoryDeleteForm(state, helpers);
        setupRepositoryFormToggles(state, helpers);

        if (state.repositoryTeamFilter) {
            state.repositoryTeamFilter.addEventListener('change', () => {
                updateRepositoryFilters(state);
                applyRepositoryFilters(state);
            });
        }
        if (state.repositoryProductFilter) {
            state.repositoryProductFilter.addEventListener('change', () => {
                applyRepositoryFilters(state);
            });
        }

        if (state.repositoryTeamSelect) {
            state.repositoryTeamSelect.addEventListener('change', () => {
                updateRepositoryProductOptions(state, 'create');
            });
        }
        if (state.repositoryProductSelect) {
            state.repositoryProductSelect.addEventListener('change', () => {
                helpers.repositoryCreate?.hide();
            });
        }
        if (state.repositoryDeleteTeamSelect) {
            state.repositoryDeleteTeamSelect.addEventListener('change', () => {
                updateRepositoryProductOptions(state, 'delete');
            });
        }
        if (state.repositoryDeleteProductSelect) {
            state.repositoryDeleteProductSelect.addEventListener('change', () => {
                updateRepositoryDeleteOptions(state);
            });
        }

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
        if (state.findingsBackButton) {
            state.findingsBackButton.addEventListener('click', () => switchToRepositoryListView(state));
        }
        if (state.detailBackButton) {
            state.detailBackButton.addEventListener('click', () => switchToFindingsView(state));
        }
    });
})();
