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

        const detailCard = createElementWithAttrs('div', '', {
            class: 'table-card page-section',
            hidden: true,
            'data-product-detail-card': ''
        });
        detailCard.innerHTML = `
            <div class="table-header table-header--stacked">
                <div>
                    <h2 data-product-detail-title>Product Details</h2>
                    <p class="table-subtitle" data-product-detail-meta></p>
                </div>
                <div class="table-header__actions">
                    <button type="button" class="btn link" data-product-detail-back>
                        <i class="fas fa-arrow-left"></i>
                        Go back
                    </button>
                </div>
            </div>
            <form data-product-update-form>
                <div class="form-group">
                    <label for="product-detail-id">Product ID</label>
                    <input type="text" id="product-detail-id" name="id" disabled>
                </div>
                <div class="form-group">
                    <label for="product-detail-team">Team</label>
                    <input type="text" id="product-detail-team" name="team" disabled>
                </div>
                <div class="form-group">
                    <label for="product-detail-description">Description</label>
                    <textarea id="product-detail-description" name="description" rows="3" placeholder="Add a description" required></textarea>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Update Product
                    </button>
                </div>
            </form>
            <div class="inline-message" data-product-update-feedback hidden></div>
        `;

        wrapper.appendChild(toolbar);
        wrapper.appendChild(formCard);
        wrapper.appendChild(deleteCard);
        wrapper.appendChild(listCard);
        wrapper.appendChild(detailCard);
        root.appendChild(wrapper);

        return {
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
            detailCard,
            detailBackButton: detailCard.querySelector('[data-product-detail-back]'),
            detailTitle: detailCard.querySelector('[data-product-detail-title]'),
            detailMeta: detailCard.querySelector('[data-product-detail-meta]'),
            updateForm: detailCard.querySelector('[data-product-update-form]'),
            updateFeedback: detailCard.querySelector('[data-product-update-feedback]'),
            detailIdInput: detailCard.querySelector('#product-detail-id'),
            detailTeamInput: detailCard.querySelector('#product-detail-team'),
            detailDescriptionInput: detailCard.querySelector('#product-detail-description'),
            currentProduct: null,
            view: 'list'
        };
    }

    function renderRows(rowsBody, counter, items, onRowClick) {
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
            if (id && team && typeof onRowClick === 'function') {
                row.setAttribute('data-product-id', id);
                row.setAttribute('data-product-team', team);
                row.setAttribute('data-product-description', description || '');
                row.addEventListener('click', () => onRowClick({
                    id,
                    description: description || '',
                    team
                }));
            }
            rowsBody.appendChild(row);
        });
        counter.textContent = items.length;
    }

    function switchToDetailView(state, product) {
        state.view = 'detail';
        state.currentProduct = product;
        if (state.listCard) {
            state.listCard.hidden = true;
        }
        if (state.formCard) {
            state.formCard.hidden = true;
        }
        if (state.deleteCard) {
            state.deleteCard.hidden = true;
        }
        if (state.detailCard) {
            state.detailCard.hidden = false;
        }
        if (state.detailTitle) {
            state.detailTitle.textContent = product?.id ? `Product · ${product.id}` : 'Product Details';
        }
        if (state.detailMeta) {
            state.detailMeta.textContent = product?.team ? `Team: ${product.team}` : '';
        }
        if (state.detailIdInput) {
            state.detailIdInput.value = product?.id || '';
        }
        if (state.detailTeamInput) {
            state.detailTeamInput.value = product?.team || '';
        }
        if (state.detailDescriptionInput) {
            state.detailDescriptionInput.value = product?.description || '';
        }
        if (state.updateFeedback) {
            state.updateFeedback.hidden = true;
            state.updateFeedback.textContent = '';
        }
        setPageTitle?.(product?.id ? `Products · ${product.id}` : 'Products');
    }

    function switchToListView(state) {
        state.view = 'list';
        state.currentProduct = null;
        if (state.detailCard) {
            state.detailCard.hidden = true;
        }
        if (state.listCard) {
            state.listCard.hidden = false;
        }
        if (state.formCard) {
            state.formCard.hidden = false;
        }
        if (state.deleteCard) {
            state.deleteCard.hidden = false;
        }
        if (state.updateFeedback) {
            state.updateFeedback.hidden = true;
            state.updateFeedback.textContent = '';
        }
        setPageTitle?.('Products');
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
            renderRows(state.rowsBody, state.counter, products, product => {
                switchToDetailView(state, product);
            });
            state.productsData = products;
            updateDeleteOptions(state);
        } catch (error) {
            renderRows(state.rowsBody, state.counter, []);
            helpers.list?.show(error.message || 'Unable to load products.', 'error');
        }
    }

    function handleUpdateForm(state, helpers) {
        if (!state.updateForm) {
            return;
        }

        state.updateForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.update?.hide();

            const name = state.detailIdInput?.value?.trim();
            const team = state.detailTeamInput?.value?.trim();
            const description = state.detailDescriptionInput?.value?.trim();

            if (!name || !team) {
                helpers.update?.show('Unable to identify the selected product.', 'error');
                return;
            }

            if (!description) {
                helpers.update?.show('Description is required to update the product.', 'error');
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
                switchToDetailView(state, { id: name, team, description });
                helpers.update?.show('Product updated successfully.', 'success');
            } catch (error) {
                helpers.update?.show(error.message || 'Failed to update product.', 'error');
            }
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
            update: createMessageHelper(state.updateFeedback, { closeButton: false })
        };

        loadTeams(state, helpers);
        loadProducts(state, helpers);
        handleSubmit(state, helpers);
        handleUpdateForm(state, helpers);
        setupFormToggle(state, helpers);
        setupDeleteToggle(state, helpers);
        handleDeleteForm(state, helpers);
        state.detailBackButton?.addEventListener('click', () => switchToListView(state));
    });
})();
