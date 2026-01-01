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
        createFormToggle,
        selectHelpers
    } = utils;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Images initialisation skipped: utilities not available.');
        return;
    }


    function parseImageRecord(image) {
        if (!image) {
            return { name: '', version: '', product: '', team: '' };
        }

        if (Array.isArray(image)) {
            return {
                name: image[0] ?? '',
                version: image[1] ?? '',
                product: image[2] ?? '',
                team: image[3] ?? ''
            };
        }

        if (typeof image === 'object') {
            return {
                name: image.name ?? '',
                version: image.version ?? '',
                product: image.product ?? '',
                team: image.team ?? image.team_id ?? ''
            };
        }

        return { name: '', version: '', product: '', team: '' };
    }

    function getImageNamesByProduct(images, productId) {
        if (!Array.isArray(images) || !productId) {
            return [];
        }
        const names = images
            .filter(image => image && image.product === productId)
            .map(image => image.name)
            .filter(Boolean);
        const unique = Array.from(new Set(names));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique;
    }

    function getVersionsForImage(images, productId, imageName) {
        if (!Array.isArray(images) || !productId || !imageName) {
            return [];
        }
        const versions = images
            .filter(image => image && image.product === productId && image.name === imageName)
            .map(image => image.version)
            .filter(Boolean);
        const unique = Array.from(new Set(versions));
        unique.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
        return unique;
    }

    function findProductRecord(products, productId) {
        if (!Array.isArray(products) || !productId) {
            return null;
        }
        return (
            products.find(product => (product.id ?? product.name ?? product[0]) === productId) ||
            null
        );
    }

    function getTeamForProduct(products, productId) {
        const record = findProductRecord(products, productId);
        if (!record) {
            return '';
        }
        return record.team ?? record.team_id ?? record.teamName ?? record[2] ?? '';
    }

    function resetSelectOptions(select, placeholder) {
        selectHelpers.reset(select, placeholder);
    }

    function getUniqueTeamsFromProducts(products) {
        if (!Array.isArray(products)) {
            return [];
        }
        const names = products
            .map(product => product.team ?? product.team_id ?? product[2])
            .filter(Boolean);
        const unique = Array.from(new Set(names));
        unique.sort((a, b) => a.localeCompare(b, undefined, { sensitivity: 'base' }));
        return unique;
    }

    function getTeamsForImageForm(state) {
        const scopeTeams = auth.getWritableTeams?.() || [];
        const teamsFromScope = scopeTeams.map(team => team.name).filter(Boolean);
        const productTeams = getUniqueTeamsFromProducts(state?.data?.products || []);

        if (auth.isRoot?.()) {
            return productTeams.length ? productTeams : teamsFromScope;
        }

        if (teamsFromScope.length) {
            return teamsFromScope;
        }

        return productTeams;
    }

    function populateImageTeamOptions(state) {
        if (!state?.teamSelect) {
            return;
        }
        const select = state.teamSelect;
        const teams = getTeamsForImageForm(state);
        const previous = select.value;
        select.innerHTML = '';

        if (!teams.length) {
            select.innerHTML = '<option value="">No teams available</option>';
            select.disabled = true;
            updateImageProductOptions(state);
            return;
        }

        const placeholder = createElementWithAttrs('option', 'Select a team…', { value: '' });
        placeholder.disabled = true;
        placeholder.selected = true;
        select.appendChild(placeholder);

        teams.forEach(name => {
            const option = createElementWithAttrs('option', name, { value: name });
            select.appendChild(option);
        });

        if (teams.includes(previous)) {
            select.value = previous;
            placeholder.selected = false;
        } else {
            select.value = '';
        }

        select.disabled = false;
        updateImageProductOptions(state);
    }

    function updateImageProductOptions(state) {
        if (!state?.productSelect) {
            return;
        }
        const select = state.productSelect;
        const team = state.teamSelect?.value || '';
        const placeholder = team ? 'Select a product…' : 'Select a team first…';
        resetSelectOptions(select, placeholder);
        select.disabled = true;

        if (!team) {
            return;
        }

        const products = Array.isArray(state?.data?.products) ? state.data.products : [];
        const filtered = products.filter(
            product => (product.team ?? product.team_id ?? product[2]) === team
        );
        filtered.forEach(product => {
            const value = product.id ?? product.name ?? product[0];
            if (!value) {
                return;
            }
            select.appendChild(createElementWithAttrs('option', value, { value }));
        });

        select.disabled = !filtered.length;
    }

    const COMPARISON_LABELS = {
        shared: 'Shared',
        only_version_a: 'Only Version A',
        only_version_b: 'Only Version B'
    };

    const COMPARISON_BADGE_CLASSES = {
        shared: 'badge badge-shared',
        only_version_a: 'badge badge-only-a',
        only_version_b: 'badge badge-only-b'
    };

    function getComparisonLabel(state, key) {
        const fallback = COMPARISON_LABELS[key] || key;
        if (!state || !state.compareSelections) {
            return fallback;
        }

        const { baseVersion, targetVersion } = state.compareSelections;
        if (key === 'only_version_a') {
            return baseVersion ? `Only ${baseVersion}` : fallback;
        }
        if (key === 'only_version_b') {
            return targetVersion ? `Only ${targetVersion}` : fallback;
        }
        return fallback;
    }


    function updateSelectOptions(select, products, placeholder) {
        selectHelpers.populate(select, products, {
            valueKey: item => item.id ?? item.name,
            labelKey: item => item.id ?? item.name,
            placeholder: placeholder,
            preserveValue: true
        });
    }

    function resetCompareSelections(state, { preserveProduct = false } = {}) {
        if (!state) {
            return;
        }

        if (!preserveProduct) {
            state.compareSelections.product = '';
            if (state.compareProductSelect) {
                state.compareProductSelect.value = '';
            }
        } else {
            state.compareSelections.product = state.compareProductSelect?.value || state.compareSelections.product || '';
        }

        state.compareSelections.image = '';
        state.compareSelections.baseVersion = '';
        state.compareSelections.targetVersion = '';

        const hasProduct = preserveProduct && Boolean(state.compareProductSelect?.value);
        const imagePlaceholder = hasProduct ? 'Select an image…' : 'Select a product first…';
        resetSelectOptions(state.compareImageSelect, imagePlaceholder);
        resetSelectOptions(state.compareBaseSelect, 'Select version A…');
        resetSelectOptions(state.compareTargetSelect, 'Select version B…');

        if (state.compareImageSelect) {
            state.compareImageSelect.disabled = true;
        }
        if (state.compareBaseSelect) {
            state.compareBaseSelect.disabled = true;
        }
        if (state.compareTargetSelect) {
            state.compareTargetSelect.disabled = true;
        }
    }

    function updateCompareVersionOptions(state) {
        const { compareProductSelect, compareImageSelect, compareBaseSelect, compareTargetSelect, compareSelections } = state;
        if (!compareBaseSelect || !compareTargetSelect) {
            return [];
        }

        resetSelectOptions(compareBaseSelect, 'Select version A…');
        resetSelectOptions(compareTargetSelect, 'Select version B…');
        compareBaseSelect.disabled = true;
        compareTargetSelect.disabled = true;

        const product = compareProductSelect?.value || '';
        const image = compareImageSelect?.value || '';

        if (!product || !image) {
            compareSelections.baseVersion = '';
            compareSelections.targetVersion = '';
            return [];
        }

        const versions = getVersionsForImage(state.data.images, product, image);
        versions.forEach(version => {
            compareBaseSelect.appendChild(createElementWithAttrs('option', version, { value: version }));
            compareTargetSelect.appendChild(createElementWithAttrs('option', version, { value: version }));
        });

        if (versions.length) {
            compareBaseSelect.disabled = false;
            compareTargetSelect.disabled = false;
        }

        if (versions.includes(compareSelections.baseVersion)) {
            compareBaseSelect.value = compareSelections.baseVersion;
        } else {
            compareSelections.baseVersion = '';
        }

        if (versions.includes(compareSelections.targetVersion)) {
            compareTargetSelect.value = compareSelections.targetVersion;
        } else {
            compareSelections.targetVersion = '';
        }

        if (compareBaseSelect.value && compareBaseSelect.value === compareTargetSelect.value) {
            compareTargetSelect.value = '';
            compareSelections.targetVersion = '';
        }

        return versions;
    }

    function updateCompareImageOptions(state) {
        const { compareProductSelect, compareImageSelect, compareSelections } = state;
        if (!compareImageSelect) {
            return [];
        }

        const product = compareProductSelect?.value || '';
        const placeholder = product ? 'Select an image…' : 'Select a product first…';
        resetSelectOptions(compareImageSelect, placeholder);
        compareImageSelect.disabled = true;

        if (!product) {
            compareSelections.image = '';
            updateCompareVersionOptions(state);
            return [];
        }

        const imageNames = getImageNamesByProduct(state.data.images, product);
        imageNames.forEach(name => {
            compareImageSelect.appendChild(createElementWithAttrs('option', name, { value: name }));
        });

        if (imageNames.length) {
            compareImageSelect.disabled = false;
        }

        if (imageNames.includes(compareSelections.image)) {
            compareImageSelect.value = compareSelections.image;
        } else {
            compareSelections.image = '';
        }

        return updateCompareVersionOptions(state);
    }

    function syncCompareSelectors(state) {
        if (!state || !state.compareProductSelect) {
            return;
        }

        state.compareSelections.product = state.compareProductSelect.value || '';
        if (!state.compareSelections.product) {
            resetCompareSelections(state, { preserveProduct: true });
            updateCompareVersionOptions(state);
            return;
        }

        updateCompareImageOptions(state);
    }

    function resetComparisonResults(state, message = 'Run a comparison to see results.', options = {}) {
        if (!state) {
            return;
        }

        const { keepVisible = false } = options;

        if (state.compareResultsRows) {
            state.compareResultsRows.innerHTML = `<tr><td colspan="7" class="empty">${message}</td></tr>`;
        }
        if (state.compareResultsContainer) {
            state.compareResultsContainer.hidden = !keepVisible;
        }
        if (state.compareResultsSearch) {
            state.compareResultsSearch.value = '';
        }
        if (state.compareResultsMeta) {
            state.compareResultsMeta.textContent = '';
        }
        if (state.compareResultsTitle) {
            state.compareResultsTitle.textContent = 'Comparison Results';
        }
        if (state.compareSummary) {
            state.compareSummary.innerHTML = '';
            state.compareSummary.hidden = true;
        }
        state.currentComparison = [];
        state.compareStats = {};
        state.compareActiveFilter = null;
    }

    function resetDeleteSelections(state) {
        if (!state) {
            return;
        }

        state.deleteSelections = state.deleteSelections || { product: '', image: '', version: '' };

        if (state.deleteProductSelect) {
            state.deleteProductSelect.value = state.deleteSelections.product || '';
        }

        resetSelectOptions(
            state.deleteImageSelect,
            state.deleteSelections.product ? 'Select an image…' : 'Select a product first…'
        );
        resetSelectOptions(state.deleteVersionSelect, 'All versions');

        if (state.deleteImageSelect) {
            state.deleteImageSelect.disabled = true;
        }
        if (state.deleteVersionSelect) {
            state.deleteVersionSelect.disabled = true;
        }
    }

    function updateDeleteImageOptions(state) {
        const { deleteProductSelect, deleteImageSelect, deleteVersionSelect, deleteSelections } = state;
        if (!deleteImageSelect) {
            return;
        }

        const product = deleteProductSelect?.value || '';
        const placeholder = product ? 'Select an image…' : 'Select a product first…';
        resetSelectOptions(deleteImageSelect, placeholder);
        resetSelectOptions(deleteVersionSelect, 'All versions');
        deleteImageSelect.disabled = true;
        deleteVersionSelect.disabled = true;

        if (!product) {
            deleteSelections.product = '';
            deleteSelections.image = '';
            deleteSelections.version = '';
            return;
        }

        const imageNames = getImageNamesByProduct(state.data.images, product);
        imageNames.forEach(name => {
            deleteImageSelect.appendChild(createElementWithAttrs('option', name, { value: name }));
        });

        if (imageNames.length) {
            deleteImageSelect.disabled = false;
        }

        if (imageNames.includes(deleteSelections.image)) {
            deleteImageSelect.value = deleteSelections.image;
        } else {
            deleteSelections.image = '';
        }

        updateDeleteVersionOptions(state);
    }

    function updateDeleteVersionOptions(state) {
        const { deleteProductSelect, deleteImageSelect, deleteVersionSelect, deleteSelections } = state;
        if (!deleteVersionSelect) {
            return;
        }

        const product = deleteProductSelect?.value || '';
        const image = deleteImageSelect?.value || '';
        resetSelectOptions(deleteVersionSelect, 'All versions');
        deleteVersionSelect.disabled = true;

        if (!product || !image) {
            deleteSelections.version = '';
            return;
        }

        const versions = getVersionsForImage(state.data.images, product, image);
        versions.forEach(version => {
            deleteVersionSelect.appendChild(createElementWithAttrs('option', version, { value: version }));
        });

        if (versions.length) {
            deleteVersionSelect.disabled = false;
        }

        if (versions.includes(deleteSelections.version)) {
            deleteVersionSelect.value = deleteSelections.version;
        } else {
            deleteSelections.version = '';
            deleteVersionSelect.value = '';
        }
    }

    function syncDeleteSelectors(state) {
        if (!state || !state.deleteProductSelect) {
            return;
        }
        state.deleteSelections.product = state.deleteProductSelect.value || state.deleteSelections.product || '';
        updateDeleteImageOptions(state);
    }

    function renderComparisonRows(state, items, emptyMessage = 'No vulnerabilities found for this comparison.') {
        if (!state || !state.compareResultsRows) {
            return;
        }

        const target = state.compareResultsRows;

        if (!Array.isArray(items) || !items.length) {
            target.innerHTML = `<tr><td colspan="7" class="empty">${emptyMessage}</td></tr>`;
            return;
        }

        target.innerHTML = '';
        items.forEach(item => {
            const row = document.createElement('tr');
            row.appendChild(createElementWithAttrs('td', item?.cve_id || '—'));
            row.appendChild(createElementWithAttrs('td', item?.component_type || '—'));
            row.appendChild(createElementWithAttrs('td', item?.component || '—'));
            row.appendChild(createElementWithAttrs('td', item?.component_path || '—'));

            const comparisonKey = item?.comparison;
            const presenceCell = document.createElement('td');
            const badgeClass = COMPARISON_BADGE_CLASSES[comparisonKey] || 'badge';
            const label = getComparisonLabel(state, comparisonKey);
            presenceCell.innerHTML = `<span class="${badgeClass}">${label}</span>`;
            row.appendChild(presenceCell);

            row.appendChild(createElementWithAttrs('td', item?.base_severity || '—'));
            const score = item?.base_score;
            const cvssVersion = item?.cvss_version ? `v${item.cvss_version}` : '';
            const scoreText = score === undefined || score === null ? '—' : String(score);
            const scoreWithVersion = scoreText === '—' ? '—' : `${scoreText}${cvssVersion ? ` (${cvssVersion})` : ''}`;
            row.appendChild(createElementWithAttrs('td', scoreWithVersion));

            target.appendChild(row);
        });
    }

    function updateComparisonStats(state, stats = {}) {
        if (!state || !state.compareSummary) {
            return;
        }

        const summary = state.compareSummary;
        state.compareStats = stats || {};
        const entries = [
            {
                key: 'shared',
                count: stats.shared ?? 0,
                className: COMPARISON_BADGE_CLASSES.shared || 'badge'
            },
            {
                key: 'only_version_a',
                count: stats.only_version_a ?? 0,
                className: COMPARISON_BADGE_CLASSES.only_version_a || 'badge'
            },
            {
                key: 'only_version_b',
                count: stats.only_version_b ?? 0,
                className: COMPARISON_BADGE_CLASSES.only_version_b || 'badge'
            }
        ];

        const activeKey = state.compareActiveFilter;
        const hasActiveData = entries.some(entry => entry.key === activeKey && entry.count > 0);
        if (activeKey && !hasActiveData) {
            state.compareActiveFilter = null;
        }

        const hasData = entries.some(entry => entry.count > 0);
        summary.innerHTML = '';
        if (!hasData) {
            summary.hidden = true;
            return;
        }

        summary.hidden = false;

        entries.forEach(({ key, count, className }) => {
            const isActive = state.compareActiveFilter === key;
            const button = createElementWithAttrs('button', '', {
                type: 'button',
                class: `compare-filter${isActive ? ' compare-filter--active' : ''}`,
                'data-compare-filter': key
            });
            button.setAttribute('aria-pressed', isActive ? 'true' : 'false');
            const labelText = getComparisonLabel(state, key);
            button.setAttribute('aria-label', `${labelText} (${count})`);
            if (!count) {
                button.disabled = true;
                button.setAttribute('aria-disabled', 'true');
            } else {
                button.setAttribute('aria-disabled', 'false');
            }

            const labelSpan = createElementWithAttrs(
                'span',
                labelText,
                { class: `${className} compare-filter__label` }
            );
            const countSpan = createElementWithAttrs('span', `(${count})`, { class: 'compare-filter__count' });

            button.appendChild(labelSpan);
            button.appendChild(countSpan);
            summary.appendChild(button);
        });
    }

    function applyComparisonSearch(state) {
        if (!state) {
            return;
        }
        const source = Array.isArray(state.currentComparison) ? state.currentComparison : [];
        const filterKey = state.compareActiveFilter;
        let filteredByKey = filterKey
            ? source.filter(item => item?.comparison === filterKey)
            : source;
        const searchInput = state.compareResultsSearch;
        if (!searchInput) {
            renderComparisonRows(state, filteredByKey);
            return;
        }

        const term = searchInput.value?.trim().toLowerCase();
        if (!term) {
            const emptyMessage = filterKey && source.length
                ? 'No comparison entries in this category.'
                : 'No vulnerabilities found for this comparison.';
            renderComparisonRows(state, filteredByKey, emptyMessage);
            return;
        }

        const searched = filteredByKey.filter(item => {
            const values = [
                item?.cve_id,
                item?.component,
                item?.component_type,
                item?.component_path,
                item?.comparison,
                item?.base_severity,
                item?.base_score,
                item?.cvss_version
            ];

            return values.some(value => {
                if (value === undefined || value === null) {
                    return false;
                }
                return String(value).toLowerCase().includes(term);
            });
        });

        renderComparisonRows(state, searched, 'No comparison entries match this search.');
    }

    function renderImageRows(state, filteredImages, filterValue) {
        const { rowsBody, counter } = state;
        if (!rowsBody || !counter) {
            return;
        }

        if (!Array.isArray(filteredImages) || !filteredImages.length) {
            const message = filterValue ? 'No images match this product.' : 'No images yet.';
            rowsBody.innerHTML = '';
            const row = document.createElement('tr');
            const cell = createElementWithAttrs('td', message, { colspan: '4', class: 'empty' });
            row.appendChild(cell);
            rowsBody.appendChild(row);
            counter.textContent = '0';
            return;
        }

        rowsBody.innerHTML = '';
        filteredImages.forEach(image => {
            const name = image.name ?? image[0] ?? '—';
            const version = image.version ?? image[1] ?? '—';
            const productId = image.product ?? image[2] ?? '—';
            const teamId = image.team ?? image.team_id ?? image[3] ?? '';

            const row = document.createElement('tr');
            row.appendChild(createElementWithAttrs('td', name));
            row.appendChild(createElementWithAttrs('td', version));
            row.appendChild(createElementWithAttrs('td', productId));
            const actionCell = document.createElement('td');
            const detailsButton = createElementWithAttrs('button', 'View details', {
                type: 'button',
                class: 'btn link',
                'data-image-action': 'details',
                'data-image-name': name,
                'data-image-version': version,
                'data-image-product': productId,
                'data-image-team': teamId
            });
            actionCell.appendChild(detailsButton);
            row.appendChild(actionCell);
            rowsBody.appendChild(row);
        });

        counter.textContent = filteredImages.length;
    }

    function renderImagesPage() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return null;
        }

        setActiveRoute?.('images');
        setPageTitle?.('Images');
        clearElement(root);

        const wrapper = createElementWithAttrs('section', '', { class: 'images-page' });

        const toolbar = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        const toolbarTitle = createElementWithAttrs('h2', 'Images');
        const toolbarActions = createElementWithAttrs('div', '', { class: 'toolbar-actions' });
        const toggleFormButton = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn primary',
            'data-image-form-toggle': ''
        });
        toggleFormButton.innerHTML = '<i class="fas fa-plus"></i> Create Image';
        const toggleDeleteButton = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn danger',
            'data-image-delete-toggle': ''
        });
        toggleDeleteButton.innerHTML = '<i class="fas fa-trash"></i> Delete Images';
        const toggleCompareButton = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn secondary',
            'data-image-compare-toggle': ''
        });
        toggleCompareButton.innerHTML = '<i class="fas fa-code-compare"></i> Compare Images';
        toolbarActions.appendChild(toggleFormButton);
        toolbarActions.appendChild(toggleDeleteButton);
        toolbarActions.appendChild(toggleCompareButton);
        toolbar.appendChild(toolbarTitle);
        toolbar.appendChild(toolbarActions);

        const formCard = createElementWithAttrs('div', '', {
            class: 'form-card page-section hidden-form',
            'data-image-form-card': ''
        });
        formCard.innerHTML = `
            <h3>Create Image</h3>
            <form data-image-form>
                <div class="form-group">
                    <label for="image-name">Image name</label>
                    <input type="text" id="image-name" name="name" placeholder="backend-service" required>
                </div>
                <div class="form-group">
                    <label for="image-version">Version</label>
                    <input type="text" id="image-version" name="version" placeholder="1.0.0" required>
                </div>
                <div class="form-group">
                    <label for="image-team">Team</label>
                    <select id="image-team" name="team" required disabled>
                        <option value="">Loading teams…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-product">Product</label>
                    <select id="image-product" name="product" required disabled>
                        <option value="">Select a team first…</option>
                    </select>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Save Image
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-image-form-feedback hidden></div>
        `;

        const deleteCard = createElementWithAttrs('div', '', {
            class: 'form-card page-section hidden-form',
            'data-image-delete-card': ''
        });
        deleteCard.innerHTML = `
            <h3>Delete Images</h3>
            <form class="compare-form" data-image-delete-form>
                <div class="form-group">
                    <label for="image-delete-product">Product</label>
                    <select id="image-delete-product" name="product" required>
                        <option value="">Select a product…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-delete-name">Image</label>
                    <select id="image-delete-name" name="image" required disabled>
                        <option value="">Select a product first…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-delete-version">Version</label>
                    <select id="image-delete-version" name="version" disabled>
                        <option value="">All versions</option>
                    </select>
                </div>
                <div class="form-actions compare-actions">
                    <button type="submit" class="btn danger">
                        <i class="fas fa-trash"></i>
                        Delete
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <p class="compare-tip">Pick a version to delete only that build. Leave the version at “All versions” to remove the entire image.</p>
            <div class="inline-message" data-image-delete-feedback hidden></div>
        `;

        const compareCard = createElementWithAttrs('div', '', {
            class: 'form-card page-section hidden-form',
            'data-image-compare-card': ''
        });
        compareCard.innerHTML = `
            <h3>Compare Images</h3>
            <form class="compare-form" data-image-compare-form>
                <div class="form-group">
                    <label for="image-compare-product">Product</label>
                    <select id="image-compare-product" name="product" required>
                        <option value="">Select a product…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-compare-name">Image</label>
                    <select id="image-compare-name" name="image" required disabled>
                        <option value="">Select a product first…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-compare-base">Version A</label>
                    <select id="image-compare-base" name="version_a" required disabled>
                        <option value="">Select an image first…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="image-compare-target">Version B</label>
                    <select id="image-compare-target" name="version_b" required disabled>
                        <option value="">Select an image first…</option>
                    </select>
                </div>
                <div class="form-actions compare-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-code-branch"></i>
                        Compare
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="compare-tip">Select two versions of the same image to compare their vulnerabilities.</div>
            <div class="inline-message" data-image-compare-feedback hidden></div>
            <div class="comparison-results" data-image-compare-results hidden>
                <div class="table-header table-header--stacked">
                    <div>
                        <h3 data-image-compare-title>Comparison Results</h3>
                        <p class="table-subtitle" data-image-compare-meta></p>
                    </div>
                    <div class="table-header__actions">
                        <label class="sr-only" for="image-compare-search">Search comparison</label>
                        <input
                            type="search"
                            id="image-compare-search"
                            class="table-search"
                            placeholder="Search CVE, package, path, severity…"
                            data-image-compare-search
                        >
                    </div>
                </div>
                <div class="compare-summary" data-image-compare-summary hidden></div>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>CVE</th>
                            <th>Type</th>
                            <th>Package</th>
                            <th>Path</th>
                            <th>Presence</th>
                            <th>Severity</th>
                            <th>Score</th>
                        </tr>
                    </thead>
                    <tbody data-image-compare-rows>
                        <tr><td colspan="7" class="empty">Run a comparison to see results.</td></tr>
                    </tbody>
                </table>
            </div>
        `;

        const listCard = createElementWithAttrs('div', '', { class: 'table-card page-section' });
        listCard.innerHTML = `
            <div class="table-header">
                <h2>Images</h2>
                <div class="inline-filter">
                    <label class="sr-only" for="image-filter">Filter by product</label>
                    <select id="image-filter" data-image-filter>
                        <option value="">All products</option>
                    </select>
                    <span class="badge" data-image-count>0</span>
                </div>
            </div>
            <div class="inline-message" data-image-list-feedback hidden></div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Version</th>
                        <th>Product</th>
                        <th></th>
                    </tr>
                </thead>
                <tbody data-image-rows>
                    <tr><td colspan="4" class="empty">Loading…</td></tr>
                </tbody>
            </table>
        `;

        const detailCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: true,
            'data-image-detail-card': ''
        });
        detailCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2 data-image-detail-title>Image Vulnerabilities</h2>
                    <p class="table-subtitle" data-image-detail-meta></p>
                </div>
                <div class="table-header__actions">
                    <button type="button" class="btn link" data-image-back>
                        <i class="fas fa-arrow-left"></i>
                        Go back
                    </button>
                    <label class="sr-only" for="image-detail-search">Search vulnerabilities</label>
                    <input
                        type="search"
                        id="image-detail-search"
                        class="table-search"
                        placeholder="Search vulnerabilities…"
                        data-image-detail-search
                    >
                </div>
            </div>
            <div class="inline-message" data-image-detail-feedback hidden></div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>CVE</th>
                        <th>Component</th>
                        <th>Type</th>
                        <th>Fix Versions</th>
                        <th>Detected Version</th>
                        <th>Path</th>
                        <th>First Seen</th>
                        <th>Last Seen</th>
                        <th>CVSS</th>
                    </tr>
                </thead>
                <tbody data-image-detail-rows>
                    <tr><td colspan="9" class="empty">Select an image to view vulnerabilities.</td></tr>
                </tbody>
            </table>
        `;

        wrapper.appendChild(toolbar);
        wrapper.appendChild(formCard);
        wrapper.appendChild(deleteCard);
        wrapper.appendChild(compareCard);
        wrapper.appendChild(listCard);
        wrapper.appendChild(detailCard);
        root.appendChild(wrapper);

        return {
            toggleFormButton,
            toggleDeleteButton,
            toggleCompareButton,
            formCard,
            deleteCard,
            compareCard,
            listCard,
            detailCard,
            form: formCard.querySelector('[data-image-form]'),
            teamSelect: formCard.querySelector('#image-team'),
            formFeedback: formCard.querySelector('[data-image-form-feedback]'),
            productSelect: formCard.querySelector('#image-product'),
            listFeedback: listCard.querySelector('[data-image-list-feedback]'),
            filterSelect: listCard.querySelector('[data-image-filter]'),
            rowsBody: listCard.querySelector('[data-image-rows]'),
            counter: listCard.querySelector('[data-image-count]'),
            detailFeedback: detailCard.querySelector('[data-image-detail-feedback]'),
            detailRows: detailCard.querySelector('[data-image-detail-rows]'),
            detailTitle: detailCard.querySelector('[data-image-detail-title]'),
            detailMeta: detailCard.querySelector('[data-image-detail-meta]'),
            detailSearchInput: detailCard.querySelector('[data-image-detail-search]'),
            detailBackButton: detailCard.querySelector('[data-image-back]'),
            deleteForm: deleteCard.querySelector('[data-image-delete-form]'),
            deleteFeedback: deleteCard.querySelector('[data-image-delete-feedback]'),
            deleteProductSelect: deleteCard.querySelector('#image-delete-product'),
            deleteImageSelect: deleteCard.querySelector('#image-delete-name'),
            deleteVersionSelect: deleteCard.querySelector('#image-delete-version'),
            compareForm: compareCard.querySelector('[data-image-compare-form]'),
            compareFeedback: compareCard.querySelector('[data-image-compare-feedback]'),
            compareProductSelect: compareCard.querySelector('#image-compare-product'),
            compareImageSelect: compareCard.querySelector('#image-compare-name'),
            compareBaseSelect: compareCard.querySelector('#image-compare-base'),
            compareTargetSelect: compareCard.querySelector('#image-compare-target'),
            compareResultsContainer: compareCard.querySelector('[data-image-compare-results]'),
            compareResultsRows: compareCard.querySelector('[data-image-compare-rows]'),
            compareResultsSearch: compareCard.querySelector('[data-image-compare-search]'),
            compareResultsTitle: compareCard.querySelector('[data-image-compare-title]'),
            compareResultsMeta: compareCard.querySelector('[data-image-compare-meta]'),
            compareSummary: compareCard.querySelector('[data-image-compare-summary]'),
            data: {
                images: [],
                products: []
            },
            view: 'list',
            currentVulns: [],
            compareSelections: {
                product: '',
                image: '',
                baseVersion: '',
                targetVersion: ''
            },
            deleteSelections: {
                product: '',
                image: '',
                version: ''
            },
            currentComparison: [],
            compareStats: {},
            compareActiveFilter: null,
            previousView: 'list'
        };
    }

    async function loadData(state, helpers) {
        if (!state.rowsBody) {
            return;
        }

        state.rowsBody.innerHTML = '';
        const loadingRow = document.createElement('tr');
        loadingRow.appendChild(createElementWithAttrs('td', 'Loading…', { colspan: '4', class: 'empty' }));
        state.rowsBody.appendChild(loadingRow);
        helpers.list?.hide();
        helpers.delete?.hide();

        try {
            const [imagesPayload, productsPayload] = await Promise.all([
                fetchJSON(apiUrl('/images')),
                fetchJSON(apiUrl('/products'))
            ]);

            state.data.images = normalizeApiResponse(imagesPayload).map(parseImageRecord);
            state.data.products = normalizeApiResponse(productsPayload);
        } catch (error) {
            state.rowsBody.innerHTML = '';
            const row = document.createElement('tr');
            row.appendChild(
                createElementWithAttrs('td', 'Unable to load images.', { colspan: '4', class: 'empty' })
            );
            state.rowsBody.appendChild(row);
            state.counter.textContent = '0';
            helpers.list?.show(error.message || 'Failed to fetch images.', 'error');
        }

        state.data.images = Array.isArray(state.data.images) ? state.data.images : [];
        state.data.products = Array.isArray(state.data.products) ? state.data.products : [];

        populateImageTeamOptions(state);
        updateImageProductOptions(state);
        updateSelectOptions(state.filterSelect, state.data.products, 'All products');
        updateSelectOptions(state.compareProductSelect, state.data.products, 'Select a product…');
        updateSelectOptions(state.deleteProductSelect, state.data.products, 'Select a product…');
        state.compareSelections.product = state.compareProductSelect?.value || state.compareSelections.product || '';
        state.deleteSelections.product = state.deleteProductSelect?.value || state.deleteSelections.product || '';

        const hasProducts = Boolean(state.data.products.length);
        const formElements = state.form ? Array.from(state.form.elements) : [];
        formElements.forEach(element => {
            if (element.tagName === 'BUTTON') {
                element.disabled = !hasProducts && element.type !== 'reset';
            } else if (element.tagName === 'SELECT' || element.tagName === 'INPUT' || element.tagName === 'TEXTAREA') {
                element.disabled = !hasProducts;
            }
        });

            const compareElements = state.compareForm ? Array.from(state.compareForm.elements) : [];
            compareElements.forEach(element => {
                if (element.tagName === 'BUTTON') {
                    element.disabled = !hasProducts && element.type !== 'reset';
                } else if (element.tagName === 'SELECT') {
                    element.disabled = !hasProducts;
                }
            });

            const deleteElements = state.deleteForm ? Array.from(state.deleteForm.elements) : [];
            deleteElements.forEach(element => {
                if (element.tagName === 'BUTTON') {
                    element.disabled = !hasProducts && element.type !== 'reset';
                } else if (element.tagName === 'SELECT') {
                    element.disabled = !hasProducts;
                }
            });

            if (state.toggleDeleteButton) {
                state.toggleDeleteButton.disabled = !hasProducts;
            }

        if (!hasProducts) {
            helpers.form.show('Create a product before registering images.', 'info');
            helpers.compare?.show('Create a product before comparing images.', 'info');
            helpers.delete?.show('Create a product before deleting images.', 'info');
            resetCompareSelections(state);
            resetComparisonResults(state);
            resetDeleteSelections(state);
        } else {
            helpers.form.hide();
            helpers.compare?.hide();
            helpers.delete?.hide();
            syncCompareSelectors(state);
            syncDeleteSelectors(state);
            if (!state.compareCard?.classList.contains('show')) {
                resetComparisonResults(state);
            }
        }

        const filterValue = state.filterSelect?.value || '';
        const filtered = filterValue
            ? state.data.images.filter(image => (image.product ?? image[2]) === filterValue)
            : state.data.images;
        renderImageRows(state, filtered, filterValue);
    }

    function handleForm(state, helpers) {
        if (!state.form) {
            return;
        }

        state.form.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.form.hide();

            const formData = new FormData(state.form);
            const payload = {
                name: formData.get('name')?.trim(),
                version: formData.get('version')?.trim(),
                product: formData.get('product')?.trim(),
                team: formData.get('team')?.trim()
            };

            if (!payload.name || !payload.version || !payload.product || !payload.team) {
                helpers.form.show('All fields are required to register an image.', 'error');
                return;
            }

            try {
                const response = await fetchJSON(apiUrl('/image'), {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });

                if (!response || response.status === false) {
                    throw new Error('The image could not be saved.');
                }

                state.setFormVisible?.(false);
                helpers.form.show('Image saved successfully.', 'success');
                loadData(state, helpers);
            } catch (error) {
                helpers.form.show(error.message || 'Failed to save image.', 'error');
            }
        });

        state.form.addEventListener('reset', () => {
            helpers.form.hide();
            if (state.teamSelect) {
                state.teamSelect.value = '';
            }
            updateImageProductOptions(state);
        });
    }

    function handleImageFormTeamSelection(state, helpers) {
        if (!state.teamSelect) {
            return;
        }
        state.teamSelect.addEventListener('change', () => {
            updateImageProductOptions(state);
            helpers.form?.hide();
        });
    }

    function handleFilter(state) {
        if (!state.filterSelect) {
            return;
        }

        state.filterSelect.addEventListener('change', () => {
            if (state.view === 'detail') {
                switchToListView(state);
            }
            const filterValue = state.filterSelect.value || '';
            const filtered = filterValue
                ? state.data.images.filter(image => (image.product ?? image[2]) === filterValue)
                : state.data.images;
            renderImageRows(state, filtered, filterValue);
        });
    }

    function handleCompareInteractions(state, helpers) {
        const {
            compareProductSelect,
            compareImageSelect,
            compareBaseSelect,
            compareTargetSelect,
            compareResultsSearch
        } = state;

        if (compareProductSelect) {
            compareProductSelect.addEventListener('change', () => {
                state.compareSelections.product = compareProductSelect.value || '';
                state.compareSelections.image = '';
                state.compareSelections.baseVersion = '';
                state.compareSelections.targetVersion = '';
                updateCompareImageOptions(state);
                resetComparisonResults(state);
                const hasImages = Boolean(state.compareImageSelect && state.compareImageSelect.options.length > 1);
                if (!state.compareSelections.product) {
                    helpers.compare?.show('Select a product to begin comparing images.', 'info');
                } else if (!hasImages) {
                    helpers.compare?.show('No images available for the selected product yet.', 'info');
                } else {
                    helpers.compare?.hide();
                }
            });
        }

        if (compareImageSelect) {
            compareImageSelect.addEventListener('change', () => {
                state.compareSelections.image = compareImageSelect.value || '';
                state.compareSelections.baseVersion = '';
                state.compareSelections.targetVersion = '';
                const versions = updateCompareVersionOptions(state);
                resetComparisonResults(state);
                if (state.compareSelections.image && versions.length < 2) {
                    helpers.compare?.show('Select an image with at least two versions to compare.', 'info');
                } else {
                    helpers.compare?.hide();
                }
            });
        }

        if (compareBaseSelect) {
            compareBaseSelect.addEventListener('change', () => {
                state.compareSelections.baseVersion = compareBaseSelect.value || '';
            });
        }

        if (compareTargetSelect) {
            compareTargetSelect.addEventListener('change', () => {
                state.compareSelections.targetVersion = compareTargetSelect.value || '';
            });
        }

        if (compareResultsSearch) {
            compareResultsSearch.addEventListener('input', () => applyComparisonSearch(state));
        }

        if (state.compareSummary) {
            state.compareSummary.addEventListener('click', event => {
                const button = event.target.closest('[data-compare-filter]');
                if (!button || button.disabled) {
                    return;
                }

                const key = button.getAttribute('data-compare-filter');
                state.compareActiveFilter = state.compareActiveFilter === key ? null : key;
                updateComparisonStats(state, state.compareStats || {});
                applyComparisonSearch(state);
            });
        }
    }

    function handleDeleteInteractions(state, helpers) {
        const { deleteProductSelect, deleteImageSelect, deleteVersionSelect, deleteSelections } = state;
        if (deleteProductSelect) {
            deleteProductSelect.addEventListener('change', () => {
                deleteSelections.product = deleteProductSelect.value || '';
                deleteSelections.image = '';
                deleteSelections.version = '';
                updateDeleteImageOptions(state);
                helpers.delete?.hide();
            });
        }

        if (deleteImageSelect) {
            deleteImageSelect.addEventListener('change', () => {
                deleteSelections.image = deleteImageSelect.value || '';
                deleteSelections.version = '';
                updateDeleteVersionOptions(state);
                helpers.delete?.hide();
            });
        }

        if (deleteVersionSelect) {
            deleteVersionSelect.addEventListener('change', () => {
                deleteSelections.version = deleteVersionSelect.value || '';
            });
        }
    }

    function handleDeleteForm(state, helpers) {
        if (!state.deleteForm) {
            return;
        }

        state.deleteForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.delete?.hide();

            const product = state.deleteProductSelect?.value?.trim();
            const image = state.deleteImageSelect?.value?.trim();
            const version = state.deleteVersionSelect?.value?.trim();

            if (!product || !image) {
                helpers.delete?.show('Product and image are required.', 'error');
                return;
            }

            const team = getTeamForProduct(state.data?.products || [], product);
            if (!team) {
                helpers.delete?.show('Unable to determine the team for this product.', 'error');
                return;
            }

            const confirmation = version
                ? `Delete version "${version}" of "${image}" for product "${product}"?`
                : `Delete all versions of "${image}" for product "${product}"?`;

            if (!window.confirm(confirmation)) {
                return;
            }

            const params = new URLSearchParams({ n: image });
            if (version) {
                params.append('ver', version);
            }

            const endpoint = `/image/${encodeURIComponent(team)}/${encodeURIComponent(product)}?${params.toString()}`;

            try {
                await fetchJSON(apiUrl(endpoint), { method: 'DELETE' });
                await loadData(state, helpers);
                helpers.delete?.show(
                    version
                        ? `Version "${version}" deleted successfully.`
                        : `All versions of "${image}" were deleted.`,
                    'success'
                );
                state.deleteForm.reset();
                resetDeleteSelections(state);
                updateDeleteImageOptions(state);
            } catch (error) {
                helpers.delete?.show(error.message || 'Failed to delete image.', 'error');
            }
        });

        state.deleteForm.addEventListener('reset', () => {
            helpers.delete?.hide();
            resetDeleteSelections(state);
            updateDeleteImageOptions(state);
        });
    }

    function handleCompareForm(state, helpers) {
        if (!state.compareForm) {
            return;
        }

        state.compareForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.compare?.hide();

            const product = state.compareProductSelect?.value?.trim();
            const image = state.compareImageSelect?.value?.trim();
            const baseVersion = state.compareBaseSelect?.value?.trim();
            const targetVersion = state.compareTargetSelect?.value?.trim();

            if (!product || !image || !baseVersion || !targetVersion) {
                helpers.compare?.show('All fields are required to compare images.', 'error');
                return;
            }

            if (baseVersion === targetVersion) {
                helpers.compare?.show('Select two different versions to compare.', 'error');
                return;
            }

            const team = getTeamForProduct(state.data?.products || [], product);
            if (!team) {
                helpers.compare?.show('Unable to determine the team for this product.', 'error');
                return;
            }

            resetComparisonResults(state, 'Loading comparison…', { keepVisible: true });
            state.compareSelections.product = product;
            state.compareSelections.image = image;
            state.compareSelections.baseVersion = baseVersion;
            state.compareSelections.targetVersion = targetVersion;
            state.compareActiveFilter = null;

            if (state.compareResultsMeta) {
                state.compareResultsMeta.textContent = `Product: ${product} · ${baseVersion} → ${targetVersion}`;
            }
            if (state.compareResultsTitle) {
                state.compareResultsTitle.textContent = `${image} Comparison`;
            }

            try {
                const endpoint = `/image/compare/${encodeURIComponent(team)}/${encodeURIComponent(product)}/${encodeURIComponent(image)}/${encodeURIComponent(baseVersion)}/${encodeURIComponent(targetVersion)}`;
                const payload = await fetchJSON(apiUrl(endpoint));
                const result = payload?.result || {};
                const comparison = Array.isArray(result.comparison) ? result.comparison : [];
                const stats = result.stats || {};
                state.currentComparison = comparison;
                state.compareActiveFilter = null;
                if (state.compareResultsSearch) {
                    state.compareResultsSearch.value = '';
                }
                updateComparisonStats(state, stats);
                applyComparisonSearch(state);
                if (state.compareResultsContainer) {
                    state.compareResultsContainer.hidden = false;
                }

                if (!comparison.length) {
                    helpers.compare?.show('No differences were found between these versions.', 'info');
                } else {
                    helpers.compare?.hide();
                }
            } catch (error) {
                helpers.compare?.show(error.message || 'Failed to compare images.', 'error');
                resetComparisonResults(state, 'Comparison failed.');
            }
        });

        state.compareForm.addEventListener('reset', () => {
            helpers.compare?.hide();
            resetCompareSelections(state);
            updateCompareImageOptions(state);
            resetComparisonResults(state);
        });
    }

    function renderVulnerabilityRows(state, items) {
        const { detailRows } = state;
        if (!detailRows) {
            return;
        }

        if (!Array.isArray(items) || !items.length) {
            detailRows.innerHTML = '<tr><td colspan="9" class="empty">No vulnerabilities found for this image.</td></tr>';
            return;
        }

        detailRows.innerHTML = '';
        items.forEach(item => {
            const row = document.createElement('tr');
            const cvssInfo = item?.cvss || {};
            const cvssScore = cvssInfo.score ?? '—';
            const severity = cvssInfo.severity ?? '—';
            const cvssVersion = cvssInfo.version ? `v${cvssInfo.version}` : '';

            row.appendChild(createElementWithAttrs('td', item.cve || '—'));
            row.appendChild(createElementWithAttrs('td', item.component || '—'));
            row.appendChild(createElementWithAttrs('td', item.component_type || '—'));
            row.appendChild(createElementWithAttrs('td', item.fix_versions || '—'));
            row.appendChild(createElementWithAttrs('td', item.component_version || '—'));
            row.appendChild(createElementWithAttrs('td', item.component_path || '—'));
            row.appendChild(createElementWithAttrs('td', item.first_seen || '—'));
            row.appendChild(createElementWithAttrs('td', item.last_seen || '—'));

            const cvssCell = document.createElement('td');
            cvssCell.className = 'cvss-cell';
            cvssCell.innerHTML = `
                <span class="cvss-chip">${cvssScore}</span>
                <span class="cvss-chip">${severity}</span>
                <span class="cvss-chip cvss-chip--muted">${cvssVersion}</span>
            `;
            row.appendChild(cvssCell);

            detailRows.appendChild(row);
        });
    }

    function switchToDetailView(state, imageMeta) {
        const { listCard, formCard, deleteCard, compareCard, detailCard, detailTitle, detailMeta } = state;
        state.setCompareVisible?.(false, { suppressListToggle: true, nextView: 'detail' });
        state.view = 'detail';
        if (listCard) {
            listCard.hidden = true;
        }
        if (formCard) {
            formCard.hidden = true;
        }
        if (deleteCard) {
            deleteCard.hidden = true;
        }
        if (compareCard) {
            compareCard.hidden = true;
        }
        if (detailCard) {
            detailCard.hidden = false;
        }
        if (detailTitle) {
            detailTitle.textContent = `${imageMeta.name} · ${imageMeta.version}`;
        }
        if (detailMeta) {
            const teamValue = imageMeta.team || getTeamForProduct(state.data?.products || [], imageMeta.product);
            const teamLabel = teamValue ? ` · Team: ${teamValue}` : '';
            detailMeta.textContent = `Product: ${imageMeta.product}${teamLabel}`;
        }
        setPageTitle?.(`Images · ${imageMeta.name} ${imageMeta.version}`);
    }

    function switchToListView(state) {
        const { listCard, formCard, deleteCard, compareCard, detailCard, detailRows, detailFeedback, detailSearchInput } = state;
        state.view = 'list';
        state.currentVulns = [];
        if (detailCard) {
            detailCard.hidden = true;
        }
        if (listCard) {
            listCard.hidden = false;
        }
        if (formCard) {
            formCard.hidden = false;
        }
        if (deleteCard) {
            deleteCard.hidden = false;
        }
        if (compareCard) {
            compareCard.hidden = false;
        }
        if (detailRows) {
            detailRows.innerHTML = '<tr><td colspan="9" class="empty">Select an image to view vulnerabilities.</td></tr>';
        }
        if (detailFeedback) {
            detailFeedback.hidden = true;
            detailFeedback.textContent = '';
        }
        if (detailSearchInput) {
            detailSearchInput.value = '';
        }
        setPageTitle?.('Images');
    }

    async function showImageDetails(state, imageMeta) {
        const { detailFeedback, detailSearchInput } = state;
        switchToDetailView(state, imageMeta);

        if (detailFeedback) {
            detailFeedback.hidden = true;
            detailFeedback.textContent = '';
        }
        if (state.detailRows) {
            state.detailRows.innerHTML = '<tr><td colspan="9" class="empty">Loading vulnerabilities…</td></tr>';
        }
        if (detailSearchInput) {
            detailSearchInput.value = '';
        }

        const team = imageMeta.team || getTeamForProduct(state.data?.products || [], imageMeta.product);
        if (!team) {
            state.currentVulns = [];
            renderVulnerabilityRows(state, []);
            if (detailFeedback) {
                detailFeedback.textContent = 'Unable to determine the team for this image.';
                detailFeedback.className = 'inline-message inline-message--error';
                detailFeedback.hidden = false;
            }
            return;
        }
        imageMeta.team = team;

        try {
            const endpoint = `/image/${encodeURIComponent(team)}/${encodeURIComponent(imageMeta.product)}/${encodeURIComponent(imageMeta.name)}/${encodeURIComponent(imageMeta.version)}/vuln`;
            const payload = await fetchJSON(apiUrl(endpoint));
            const items = payload && Array.isArray(payload.result) ? payload.result : [];
            state.currentVulns = items;
            applyDetailSearch(state);
        } catch (error) {
            state.currentVulns = [];
            renderVulnerabilityRows(state, []);
            if (detailFeedback) {
                detailFeedback.textContent = error.message || 'Unable to load vulnerabilities.';
                detailFeedback.className = 'inline-message inline-message--error';
                detailFeedback.hidden = false;
            }
        }
    }

    function applyDetailSearch(state) {
        const { currentVulns, detailSearchInput } = state;
        const source = Array.isArray(currentVulns) ? currentVulns : [];
        if (!detailSearchInput) {
            renderVulnerabilityRows(state, source);
            return;
        }

        const term = detailSearchInput.value?.trim().toLowerCase();
        if (!term) {
            renderVulnerabilityRows(state, source);
            return;
        }

        const filtered = source.filter(item => {
            const fields = [
                item?.cve,
                item?.component,
                item?.component_type,
                item?.fix_versions,
                item?.component_version,
                item?.component_path,
                item?.first_seen,
                item?.last_seen,
                item?.cvss?.severity,
                item?.cvss?.score,
                item?.cvss?.version
            ];

            return fields.some(value => {
                if (value === undefined || value === null) {
                    return false;
                }
                return String(value).toLowerCase().includes(term);
            });
        });

        renderVulnerabilityRows(state, filtered);
    }

    function attachListInteractions(state, helpers) {
        if (!state.rowsBody) {
            return;
        }

        state.rowsBody.addEventListener('click', event => {
            const trigger = event.target.closest('[data-image-action="details"]');
            if (!trigger) {
                return;
            }

            const name = trigger.getAttribute('data-image-name');
            const version = trigger.getAttribute('data-image-version');
            const product = trigger.getAttribute('data-image-product');
            let team = trigger.getAttribute('data-image-team') || '';
            if (!team) {
                team = getTeamForProduct(state.data?.products || [], product);
            }
            if (!name || !version || !product) {
                return;
            }

            showImageDetails(state, { name, version, product, team });
        });
    }

    function setupFormToggle(state, helpers) {
        const toggle = createFormToggle({
            button: state.toggleFormButton,
            container: state.formCard,
            form: state.form,
            labels: {
                open: '<i class="fas fa-plus"></i> Create Image',
                close: '<i class="fas fa-times"></i> Cancel'
            },
            onShow: () => helpers.form.hide(),
            onHide: () => {
                if (state.teamSelect) {
                    state.teamSelect.value = '';
                }
                updateImageProductOptions(state);
            }
        });

        state.setFormVisible = toggle.setVisible;
    }

    function setupDeleteToggle(state, helpers) {
        const toggle = createFormToggle({
            button: state.toggleDeleteButton,
            container: state.deleteCard,
            form: state.deleteForm,
            labels: {
                open: '<i class="fas fa-trash"></i> Delete Images',
                close: '<i class="fas fa-times"></i> Cancel Delete'
            },
            onShow: () => helpers.delete?.hide(),
            onHide: () => resetDeleteSelections(state)
        });

        state.setDeleteVisible = toggle.setVisible;
    }

    function setupCompareToggle(state, helpers) {
        const { toggleCompareButton, compareCard, compareForm } = state;
        if (!toggleCompareButton || !compareCard) {
            return;
        }

        const firstField = compareForm?.querySelector('select, input, textarea');

        const updateButtonLabel = visible => {
            toggleCompareButton.innerHTML = visible
                ? '<i class="fas fa-times"></i> Cancel Compare'
                : '<i class="fas fa-code-compare"></i> Compare Images';
            toggleCompareButton.setAttribute('aria-expanded', String(visible));
        };

        const setCompareVisible = (visible, options = {}) => {
            const { suppressListToggle = false, nextView } = options;
            compareCard.hidden = false;
            const wasVisible = compareCard.classList.contains('show');
            if (visible === wasVisible && !visible && !nextView) {
                updateButtonLabel(visible);
                return;
            }

            compareCard.classList.toggle('show', visible);
            updateButtonLabel(visible);

            if (visible) {
                state.previousView = state.view || 'list';
                state.view = 'compare';
                if (!suppressListToggle) {
                    if (state.listCard) {
                        state.listCard.hidden = true;
                    }
                    if (state.formCard) {
                        state.formCard.hidden = true;
                    }
                }
                if (state.detailCard) {
                    state.detailCard.hidden = true;
                }
                helpers.compare?.hide();
                firstField?.focus();
                return;
            }

            const targetView = nextView || state.previousView || 'list';

            if (state.view === 'compare') {
                state.view = targetView;
            } else if (!state.view) {
                state.view = targetView;
            }

            if (targetView === 'list') {
                if (!suppressListToggle) {
                    if (state.listCard) {
                        state.listCard.hidden = false;
                    }
                    if (state.formCard) {
                        state.formCard.hidden = false;
                    }
                }
                if (state.detailCard) {
                    state.detailCard.hidden = true;
                }
                compareForm?.reset();
                resetCompareSelections(state);
                resetComparisonResults(state);
                return;
            }

            if (targetView === 'detail') {
                if (!suppressListToggle) {
                    if (state.listCard) {
                        state.listCard.hidden = true;
                    }
                    if (state.formCard) {
                        state.formCard.hidden = true;
                    }
                }
                if (state.detailCard) {
                    state.detailCard.hidden = false;
                }
            }
        };

        toggleCompareButton.addEventListener('click', () => {
            const shouldShow = !compareCard.classList.contains('show');
            setCompareVisible(shouldShow);
        });

        updateButtonLabel(false);
        state.setCompareVisible = setCompareVisible;
    }

    registerRoute('images', () => {
        const state = renderImagesPage();
        if (!state) {
            return;
        }

        const helpers = {
            form: createMessageHelper(state.formFeedback),
            list: createMessageHelper(state.listFeedback),
            delete: createMessageHelper(state.deleteFeedback),
            compare: createMessageHelper(state.compareFeedback)
        };

        resetCompareSelections(state);
        resetComparisonResults(state);
        resetDeleteSelections(state);
        populateImageTeamOptions(state);
        updateImageProductOptions(state);
        loadData(state, helpers);
        handleForm(state, helpers);
        handleImageFormTeamSelection(state, helpers);
        handleDeleteForm(state, helpers);
        handleCompareForm(state, helpers);
        handleDeleteInteractions(state, helpers);
        handleCompareInteractions(state, helpers);
        handleFilter(state);
        setupFormToggle(state, helpers);
        setupDeleteToggle(state, helpers);
        setupCompareToggle(state, helpers);
        attachListInteractions(state, helpers);

        if (state.detailBackButton) {
            state.detailBackButton.addEventListener('click', () => {
                switchToListView(state);
            });
        }

        if (state.detailSearchInput) {
            state.detailSearchInput.addEventListener('input', () => applyDetailSearch(state));
        }
    });
})();
