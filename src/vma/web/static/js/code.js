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

    /* ---- Column definitions ---- */

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
        { key: 'product',       header: 'Product',      visible: false, extract: item => item?.product || '' },
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

    /* ---- Team/product helpers ---- */

    function getUniqueTeamsFromProducts(products) {
        if (!Array.isArray(products)) return [];
        const names = products.map(p => p.team ?? p.team_id ?? p[2]).filter(Boolean);
        const unique = Array.from(new Set(names));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique;
    }

    function getProductsForTeam(products, team) {
        if (!Array.isArray(products) || !team) return [];
        return products.filter(p => (p.team ?? p.team_id ?? p[2]) === team);
    }

    /* ---- Data loading ---- */

    async function loadProducts(state) {
        try {
            const res = await fetchJSON(apiUrl('/products'));
            const norm = normalizeApiResponse(res);
            state.data.products = Array.isArray(norm.result) ? norm.result : [];
        } catch (e) {
            console.error('Failed to load products:', e);
            state.data.products = [];
        }
    }

    async function loadFindings(state) {
        if (!state.currentTeam || !state.currentProduct) {
            state.data.findings = [];
            applySearch(state);
            return;
        }
        try {
            const url = apiUrl(`/sast/${encodeURIComponent(state.currentTeam)}/${encodeURIComponent(state.currentProduct)}`);
            const res = await fetchJSON(url);
            const norm = normalizeApiResponse(res);
            state.data.findings = Array.isArray(norm.result) ? norm.result : [];
        } catch (e) {
            console.error('Failed to load SAST findings:', e);
            state.data.findings = [];
        }
        applySearch(state);
    }

    /* ---- Populate selects ---- */

    function populateTeamOptions(state) {
        const select = state.teamSelect;
        if (!select) return;
        select.innerHTML = '';

        const teams = getUniqueTeamsFromProducts(state.data.products);

        const placeholder = createElementWithAttrs('option', 'Select a team…', { value: '' });
        placeholder.disabled = true;
        placeholder.selected = true;
        select.appendChild(placeholder);

        teams.forEach(name => {
            select.appendChild(createElementWithAttrs('option', name, { value: name }));
        });

        select.disabled = !teams.length;
        updateProductOptions(state);
    }

    function updateProductOptions(state) {
        const select = state.productSelect;
        if (!select) return;
        select.innerHTML = '';

        const team = state.currentTeam;
        const placeholderText = team ? 'Select a product…' : 'Select a team first…';
        const placeholder = createElementWithAttrs('option', placeholderText, { value: '' });
        placeholder.disabled = true;
        placeholder.selected = true;
        select.appendChild(placeholder);

        if (!team) {
            select.disabled = true;
            return;
        }

        const products = getProductsForTeam(state.data.products, team);
        products.forEach(p => {
            const name = p.id ?? p.name ?? p[0];
            select.appendChild(createElementWithAttrs('option', name, { value: name }));
        });

        select.disabled = !products.length;
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
                renderTableHeader(state);
                applySearch(state);
            });
            columnToggleDropdown.appendChild(item);
        });
    }

    function renderTableHeader(state) {
        const { tableHead } = state;
        if (!tableHead) return;
        const tr = tableHead.querySelector('tr') || document.createElement('tr');
        tr.innerHTML = '';
        getVisibleColumns(state).forEach(col => {
            const th = document.createElement('th');
            th.textContent = col.header;
            tr.appendChild(th);
        });
        if (!tr.parentNode) tableHead.appendChild(tr);
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

    function applySearch(state) {
        const source = Array.isArray(state.data.findings) ? state.data.findings : [];
        const term = state.searchInput?.value?.trim().toLowerCase();

        if (!term) {
            renderFindingRows(state, source);
            return;
        }

        const visCols = getVisibleColumns(state);
        const filtered = source.filter(item => {
            return visCols.some(col => {
                const text = col.extract(item);
                return text && String(text).toLowerCase().includes(term);
            });
        });

        renderFindingRows(state, filtered);
    }

    /* ---- Table rendering ---- */

    function updateSubtitle(state, items) {
        if (!state.subtitle) return;
        if (state.currentTeam && state.currentProduct) {
            const count = Array.isArray(items) ? items.length : 0;
            state.subtitle.textContent = `${state.currentTeam} / ${state.currentProduct} · ${count} finding${count !== 1 ? 's' : ''}`;
        } else {
            state.subtitle.textContent = 'Select a team and product to view findings';
        }
    }

    function renderFindingRows(state, items) {
        if (!state.tableBody) return;
        const visibleCols = getVisibleColumns(state);

        state.tableBody.innerHTML = '';

        if (!Array.isArray(items) || !items.length) {
            const msg = (state.currentTeam && state.currentProduct)
                ? 'No SAST findings found.'
                : 'Select a team and product to view findings.';
            state.tableBody.innerHTML = `<tr><td colspan="${visibleCols.length}" class="empty">${msg}</td></tr>`;
            updateSubtitle(state, items);
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

            state.tableBody.appendChild(row);
        });

        updateSubtitle(state, items);
    }

    /* ---- Detail view ---- */

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function showFindingDetail(state, finding) {
        state.view = 'detail';
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

    function switchToListView(state) {
        state.view = 'list';
        if (state.findingsCard) state.findingsCard.hidden = false;
        if (state.detailCard) state.detailCard.hidden = true;
        if (state.detailContent) state.detailContent.innerHTML = '';
        setPageTitle?.('Code');
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

        // Findings card
        const findingsCard = createElementWithAttrs('div', '', { class: 'table-card page-section' });
        findingsCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2>SAST Findings</h2>
                    <p class="table-subtitle" data-code-subtitle>Select a team and product to view findings</p>
                </div>
                <div class="table-header__actions">
                    <div class="inline-filter">
                        <label for="code-team-select">Team</label>
                        <select id="code-team-select" data-code-team>
                            <option value="" disabled selected>Loading…</option>
                        </select>
                    </div>
                    <div class="inline-filter">
                        <label for="code-product-select">Product</label>
                        <select id="code-product-select" data-code-product disabled>
                            <option value="" disabled selected>Select a team first…</option>
                        </select>
                    </div>
                    <div class="column-toggle-wrapper">
                        <button type="button" class="btn secondary" data-code-column-toggle-btn>
                            <i class="fas fa-table-columns"></i> Columns
                        </button>
                        <div class="column-toggle-dropdown" data-code-column-toggle-dropdown></div>
                    </div>
                    <label class="sr-only" for="code-search">Search findings</label>
                    <input
                        type="search"
                        id="code-search"
                        class="table-search"
                        placeholder="Search findings…"
                        data-code-search
                    >
                </div>
            </div>
            <table class="data-table">
                <thead data-code-thead><tr></tr></thead>
                <tbody data-code-rows>
                    <tr><td colspan="${defaultColCount}" class="empty">Select a team and product to view findings.</td></tr>
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
                    <button type="button" class="btn link" data-code-back>
                        <i class="fas fa-arrow-left"></i>
                        Go back
                    </button>
                </div>
            </div>
            <div class="sast-detail-content" data-code-detail-content></div>
        `;

        wrapper.appendChild(findingsCard);
        wrapper.appendChild(detailCard);
        root.appendChild(wrapper);

        return {
            findingsCard,
            detailCard,
            subtitle: findingsCard.querySelector('[data-code-subtitle]'),
            teamSelect: findingsCard.querySelector('[data-code-team]'),
            productSelect: findingsCard.querySelector('[data-code-product]'),
            columnToggleBtn: findingsCard.querySelector('[data-code-column-toggle-btn]'),
            columnToggleDropdown: findingsCard.querySelector('[data-code-column-toggle-dropdown]'),
            searchInput: findingsCard.querySelector('[data-code-search]'),
            tableHead: findingsCard.querySelector('[data-code-thead]'),
            tableBody: findingsCard.querySelector('[data-code-rows]'),
            detailTitle: detailCard.querySelector('[data-code-detail-title]'),
            detailMeta: detailCard.querySelector('[data-code-detail-meta]'),
            detailContent: detailCard.querySelector('[data-code-detail-content]'),
            detailBackButton: detailCard.querySelector('[data-code-back]'),
            columnVisibility: loadColumnVisibility() || getDefaultVisibility(),
            data: { products: [], findings: [] },
            currentTeam: '',
            currentProduct: '',
            view: 'list'
        };
    }

    /* ---- Route registration ---- */

    registerRoute('code', async () => {
        const state = renderCodePage();
        if (!state) return;

        // Load products and populate team select
        await loadProducts(state);
        populateTeamOptions(state);

        // Team change handler
        state.teamSelect.addEventListener('change', () => {
            state.currentTeam = state.teamSelect.value;
            state.currentProduct = '';
            updateProductOptions(state);
            state.data.findings = [];
            applySearch(state);
            if (state.view === 'detail') switchToListView(state);
        });

        // Product change handler
        state.productSelect.addEventListener('change', () => {
            state.currentProduct = state.productSelect.value;
            if (state.view === 'detail') switchToListView(state);
            loadFindings(state);
        });

        // Search handler
        state.searchInput.addEventListener('input', () => applySearch(state));

        // Column toggle
        setupColumnToggle(state);
        renderTableHeader(state);

        // Detail back button
        if (state.detailBackButton) {
            state.detailBackButton.addEventListener('click', () => switchToListView(state));
        }
    });
})();
