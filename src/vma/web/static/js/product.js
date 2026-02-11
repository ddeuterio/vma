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
        selectHelpers,
        components
    } = utils;

    const {
        createToolbar,
        createTableCard,
        createFormCard,
        createEmptyState
    } = components;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Products initialisation skipped: utilities not available.');
        return;
    }


    function findProductRecord(products, id) {
        if (!Array.isArray(products) || !id) {
            return null;
        }
        return (
            products.find(product => (product.id ?? product.name ?? product[0]) === id) || null
        );
    }

    function renderProductsView() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return null;
        }

        setActiveRoute?.('products');
        setPageTitle?.('Products');
        clearElement(root);

        const wrapper = createElementWithAttrs('section', '', { class: 'products-page' });

        // List view toolbar
        const toolbar = createToolbar({
            title: 'Products',
            buttons: [
                {
                    label: 'Create Product',
                    icon: 'fas fa-plus',
                    className: 'btn primary',
                    attributes: { 'data-product-form-toggle': '' }
                },
                {
                    label: 'Delete Product',
                    icon: 'fas fa-trash',
                    className: 'btn danger',
                    attributes: { 'data-product-delete-toggle': '' }
                }
            ]
        });
        const [toggleFormButton, toggleDeleteButton] = toolbar.buttons;

        const formCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
        formCard.innerHTML = `
            <h3>Create Product</h3>
            <form data-product-form>
                <div class="form-group">
                    <label for="product-id">Product ID</label>
                    <input type="text" id="product-id" name="id" placeholder="example-product" required>
                </div>
                <div class="form-group">
                    <label for="product-team">Team</label>
                    <select id="product-team" name="team" required disabled>
                        <option value="">Loading teams…</option>
                    </select>
                </div>
                <div class="form-group">
                    <label for="product-description">Description</label>
                    <textarea id="product-description" name="description" rows="3" placeholder="Short description (optional)"></textarea>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-check"></i>
                        Save Product
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-product-feedback hidden></div>
        `;

        const deleteCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
        deleteCard.innerHTML = `
            <h3>Delete Product</h3>
            <form data-product-delete-form>
                <div class="form-group">
                    <label for="product-delete-id">Product</label>
                    <select id="product-delete-id" name="id" required disabled>
                        <option value="">Select a product…</option>
                    </select>
                </div>
                <div class="form-actions compare-actions">
                    <button type="submit" class="btn danger">
                        <i class="fas fa-trash"></i>
                        Delete Product
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-product-delete-feedback hidden></div>
        `;

        const { element: listCard, tbody: rowsBody, counter, feedback: listFeedback } = createTableCard({
            title: 'Existing Products',
            columns: ['ID', 'Description', 'Team'],
            dataAttribute: 'data-product-rows',
            countAttribute: 'data-product-count',
            feedbackAttribute: 'data-product-list-feedback'
        });

        // Edit view (separate full-page view)
        const editView = createElementWithAttrs('div', '', { class: 'edit-view', 'data-edit-view': '', hidden: true });
        const editViewHeader = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        editViewHeader.innerHTML = `
            <h2>Edit Product</h2>
            <div class="toolbar-actions">
                <button type="button" class="btn secondary" data-back-to-list>
                    <i class="fas fa-arrow-left"></i> Back to Products
                </button>
            </div>
        `;

        const editCard = createElementWithAttrs('div', '', { class: 'form-card page-section' });
        editCard.innerHTML = `
            <form data-product-edit-form>
                <div class="form-group">
                    <label for="product-edit-id">Product ID</label>
                    <input type="text" id="product-edit-id" name="id" disabled>
                </div>
                <div class="form-group">
                    <label for="product-edit-team">Team</label>
                    <input type="text" id="product-edit-team" name="team" disabled>
                </div>
                <div class="form-group">
                    <label for="product-edit-description">Description</label>
                    <textarea id="product-edit-description" name="description" rows="3" placeholder="Add a description"></textarea>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Update Product
                    </button>
                    <button type="button" class="btn secondary" data-product-edit-cancel>Cancel</button>
                </div>
            </form>
            <div class="inline-message" data-product-edit-feedback hidden></div>
        `;

        // List view (contains toolbar, create/delete forms, and table)
        const listView = createElementWithAttrs('div', '', { class: 'list-view', 'data-list-view': '' });
        listView.appendChild(toolbar);
        listView.appendChild(formCard);
        listView.appendChild(deleteCard);
        listView.appendChild(listCard);

        // Edit view assembly
        editView.appendChild(editViewHeader);
        editView.appendChild(editCard);

        wrapper.appendChild(listView);
        wrapper.appendChild(editView);
        root.appendChild(wrapper);

        return {
            listView,
            editView,
            backToListBtn: editViewHeader.querySelector('[data-back-to-list]'),
            toolbar,
            toggleFormButton,
            toggleDeleteButton,
            formCard,
            deleteCard,
            listCard,
            form: formCard.querySelector('[data-product-form]'),
            feedback: formCard.querySelector('[data-product-feedback]'),
            listFeedback,
            rowsBody,
            counter,
            deleteForm: deleteCard.querySelector('[data-product-delete-form]'),
            deleteFeedback: deleteCard.querySelector('[data-product-delete-feedback]'),
            deleteSelect: deleteCard.querySelector('#product-delete-id'),
            teamSelect: formCard.querySelector('#product-team'),
            editCard,
            editForm: editCard.querySelector('[data-product-edit-form]'),
            editFeedback: editCard.querySelector('[data-product-edit-feedback]'),
            editCancel: editCard.querySelector('[data-product-edit-cancel]'),
            editIdInput: editCard.querySelector('#product-edit-id'),
            editTeamInput: editCard.querySelector('#product-edit-team'),
            editDescriptionInput: editCard.querySelector('#product-edit-description'),
            editingProductId: null,
            editingProductTeam: null
        };
    }

    function renderRows(rowsBody, counter, items) {
        if (!rowsBody || !counter) {
            return;
        }

        if (!Array.isArray(items) || !items.length) {
            rowsBody.innerHTML = createEmptyState({
                message: 'No products yet.',
                colspan: 3,
                context: 'table'
            });
            counter.textContent = '0';
            return;
        }

        rowsBody.innerHTML = '';
        items.forEach(item => {
            const id = item.id ?? item.name ?? item[0];
            const description = item.description ?? item[1] ?? '—';
            const team = item.team ?? item.team_id ?? item[2] ?? '—';

            const row = document.createElement('tr');
            row.appendChild(createElementWithAttrs('td', id || '—'));
            row.appendChild(createElementWithAttrs('td', description || '—'));
            row.appendChild(createElementWithAttrs('td', team || '—'));
            if (id && team) {
                row.setAttribute('data-product-id', id);
                row.setAttribute('data-product-team', team);
                row.setAttribute('data-product-description', description || '');
            }
            rowsBody.appendChild(row);
        });
        counter.textContent = items.length;
    }

    function showListView(state) {
        if (state.listView) {
            state.listView.hidden = false;
        }
        if (state.editView) {
            state.editView.hidden = true;
        }
        setPageTitle?.('Products');
    }

    function showEditView(state) {
        if (state.listView) {
            state.listView.hidden = true;
        }
        if (state.editView) {
            state.editView.hidden = false;
        }
    }

    function hideEditForm(state) {
        showListView(state);
        state.editingProductId = null;
        state.editingProductTeam = null;
        state.editForm?.reset();
    }

    function populateEditForm(state, product) {
        if (!state.editCard) {
            return;
        }
        state.editingProductId = product.id;
        state.editingProductTeam = product.team;

        if (state.editIdInput) {
            state.editIdInput.value = product.id || '';
        }
        if (state.editTeamInput) {
            state.editTeamInput.value = product.team || '';
        }
        if (state.editDescriptionInput) {
            state.editDescriptionInput.value = product.description || '';
        }

        showEditView(state);
        setPageTitle?.(`Products · ${product.id}`);
        state.editDescriptionInput?.focus();
    }

    function populateTeamOptions(state, teams) {
        if (!state.teamSelect) {
            return;
        }

        selectHelpers.populate(state.teamSelect, teams, {
            valueKey: item => item.name ?? item.id ?? item.value ?? item[0],
            labelKey: item => item.label ?? item.name ?? item.id ?? item[0],
            placeholder: 'Select a team…',
            preserveValue: true
        });
    }

    async function loadTeams(state, helpers = {}) {
        if (!state.teamSelect) {
            return;
        }
        state.teamSelect.disabled = true;
        state.teamSelect.innerHTML = '<option value="">Loading teams…</option>';

        const isRoot = auth.isRoot?.() ?? false;

        if (isRoot) {
            try {
                const response = await fetchJSON(apiUrl('/teams'));
                const teams = normalizeApiResponse(response);
                state.teamsData = teams;
                populateTeamOptions(state, teams);
                if (!teams.length) {
                    helpers.form?.show('Create a team before adding products.', 'info');
                } else {
                    helpers.form?.hide();
                }
            } catch (error) {
                state.teamSelect.innerHTML = '<option value="">Unable to load teams</option>';
                state.teamSelect.disabled = true;
                helpers.form?.show(error.message || 'Unable to load teams.', 'error');
            }
            return;
        }

        const scopeTeams = auth.getWritableTeams?.() || [];
        if (!scopeTeams.length) {
            state.teamSelect.innerHTML = '<option value="">No writable teams available</option>';
            helpers.form?.show('Your account does not have write access to any team.', 'error');
            return;
        }

        const mapped = scopeTeams.map(team => ({
            name: team.name,
            label: team.name,
            description: team.permission
        }));
        state.teamsData = mapped;
        populateTeamOptions(state, mapped);
        helpers.form?.hide();
    }

    async function loadProducts(state, helpers = {}) {
        if (!state.rowsBody || !state.counter) {
            return;
        }

        state.rowsBody.innerHTML = '<tr><td colspan="3" class="empty">Loading…</td></tr>';
        helpers.form?.hide();
        helpers.list?.hide();
        helpers.delete?.hide();

        try {
            const payload = await fetchJSON(apiUrl('/products'));
            const products = normalizeApiResponse(payload);
            renderRows(state.rowsBody, state.counter, products);
            state.productsData = products;
            updateDeleteOptions(state);
        } catch (error) {
            renderRows(state.rowsBody, state.counter, []);
            helpers.list?.show(error.message || 'Unable to load products.', 'error');
        }
    }

    function handleEditForm(state, helpers) {
        if (!state.editForm) {
            return;
        }

        state.editForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.edit?.hide();

            const name = state.editIdInput?.value?.trim();
            const team = state.editTeamInput?.value?.trim();
            const description = state.editDescriptionInput?.value?.trim() || null;

            if (!name || !team) {
                helpers.edit?.show('Unable to identify the selected product.', 'error');
                return;
            }

            try {
                const response = await fetchJSON(apiUrl('/product'), {
                    method: 'PATCH',
                    body: JSON.stringify({ name, team, description })
                });

                if (!response || response.status === false) {
                    throw new Error('The product could not be updated.');
                }

                await loadProducts(state, helpers);
                hideEditForm(state);
                helpers.list?.show(`Product "${name}" updated successfully.`, 'success');
            } catch (error) {
                helpers.edit?.show(error.message || 'Failed to update product.', 'error');
            }
        });

        state.editCancel?.addEventListener('click', () => {
            helpers.edit?.hide();
            hideEditForm(state);
        });
    }

    function attachProductRowInteractions(state, helpers) {
        if (!state.rowsBody) {
            return;
        }
        state.rowsBody.addEventListener('click', async event => {
            const row = event.target.closest('tr[data-product-id]');
            if (!row) {
                return;
            }
            const id = row.getAttribute('data-product-id');
            const team = row.getAttribute('data-product-team');
            const description = row.getAttribute('data-product-description') || '';
            if (!id) {
                return;
            }
            helpers.edit?.hide();
            populateEditForm(state, { id, team, description });
        });
    }

    function setupBackButton(state, helpers) {
        if (!state.backToListBtn) {
            return;
        }
        state.backToListBtn.addEventListener('click', () => {
            helpers.edit?.hide();
            hideEditForm(state);
        });
    }

    function handleSubmit(state, helpers) {
        if (!state.form) {
            return;
        }

        state.form.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.form?.hide();

            const formData = new FormData(state.form);
            const payload = {
                name: formData.get('id')?.trim(),
                description: formData.get('description')?.trim() || null,
                team: formData.get('team')?.trim()
            };

            if (!payload.name) {
                helpers.form?.show('Product ID is required.', 'error');
                return;
            }
            if (!payload.team) {
                helpers.form?.show('A team must be selected.', 'error');
                return;
            }

            try {
                const response = await fetchJSON(apiUrl('/product'), {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });

                if (!response || response.status === false) {
                    throw new Error('The product could not be created.');
                }

                state.setFormVisible?.(false);
                await loadProducts(state, helpers);
                helpers.form?.show('Product created successfully.', 'success');
            } catch (error) {
                helpers.form?.show(error.message || 'Failed to create product.', 'error');
            }
        });

        state.form.addEventListener('reset', () => {
            helpers.form?.hide();
        });
    }

    function resetDeleteForm(state) {
        if (!state.deleteForm) {
            return;
        }
        state.deleteForm.reset();
        updateDeleteOptions(state);
    }

    function updateDeleteOptions(state) {
        if (!state.deleteSelect) {
            return;
        }

        const products = Array.isArray(state.productsData) ? state.productsData : [];
        const select = state.deleteSelect;
        const previous = select.value;

        select.innerHTML = '<option value="">Select a product…</option>';
        let allowedCount = 0;
        products.forEach(product => {
            const value = product.id ?? product.name ?? product[0];
            const team = product.team ?? product.team_id ?? product[2];
            if (!value || !team) {
                return;
            }
            if (!auth.hasTeamPermission?.(team, ['admin'])) {
                return;
            }
            allowedCount += 1;
            select.appendChild(createElementWithAttrs('option', value, { value }));
        });

        if (products.some(product => (product.id ?? product.name ?? product[0]) === previous)) {
            select.value = previous;
        } else {
            select.value = '';
        }

        select.disabled = !allowedCount;
    }

    function handleDeleteForm(state, helpers) {
        if (!state.deleteForm) {
            return;
        }

        state.deleteForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.delete?.hide();

            const productId = state.deleteSelect?.value?.trim();
            if (!productId) {
                helpers.delete?.show('Select a product to delete.', 'error');
                return;
            }

            const productRecord = findProductRecord(state.productsData, productId);
            const team = productRecord?.team ?? productRecord?.team_id ?? null;
            if (!team) {
                helpers.delete?.show('Unable to determine the team for this product.', 'error');
                return;
            }

            const confirmed = window.confirm(`Delete product "${productId}"? This action cannot be undone.`);
            if (!confirmed) {
                return;
            }

            try {
                const endpoint = `/product/${encodeURIComponent(team)}/${encodeURIComponent(productId)}`;
                await fetchJSON(apiUrl(endpoint), {
                    method: 'DELETE'
                });
                await loadProducts(state, helpers);
                helpers.delete?.show(`Product "${productId}" deleted successfully.`, 'success');
                resetDeleteForm(state);
            } catch (error) {
                helpers.delete?.show(error.message || 'Failed to delete product.', 'error');
            }
        });

        state.deleteForm.addEventListener('reset', () => {
            helpers.delete?.hide();
            resetDeleteForm(state);
        });
    }

    function setupFormToggle(state, helpers) {
        const toggle = createFormToggle({
            button: state.toggleFormButton,
            container: state.formCard,
            form: state.form,
            labels: {
                open: '<i class="fas fa-plus"></i> Create Product',
                close: '<i class="fas fa-times"></i> Cancel'
            },
            onShow: () => helpers.form?.hide()
        });

        state.setFormVisible = toggle.setVisible;
    }

    function setupDeleteToggle(state, helpers) {
        const toggle = createFormToggle({
            button: state.toggleDeleteButton,
            container: state.deleteCard,
            form: state.deleteForm,
            labels: {
                open: '<i class="fas fa-trash"></i> Delete Product',
                close: '<i class="fas fa-times"></i> Cancel Delete'
            },
            onShow: () => helpers.delete?.hide(),
            onHide: () => resetDeleteForm(state)
        });

        state.setDeleteVisible = toggle.setVisible;
    }

    registerRoute('products', () => {
        const state = renderProductsView();
        if (!state) {
            return;
        }

        const helpers = {
            form: createMessageHelper(state.feedback, { closeButton: false }),
            list: createMessageHelper(state.listFeedback, { closeButton: false }),
            delete: createMessageHelper(state.deleteFeedback, { closeButton: false }),
            edit: createMessageHelper(state.editFeedback, { closeButton: false })
        };

        loadTeams(state, helpers);
        loadProducts(state, helpers);
        handleSubmit(state, helpers);
        handleEditForm(state, helpers);
        setupFormToggle(state, helpers);
        setupDeleteToggle(state, helpers);
        handleDeleteForm(state, helpers);
        attachProductRowInteractions(state, helpers);
        setupBackButton(state, helpers);
    });
})();
