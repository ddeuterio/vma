(function () {
    const utils = window.vmaUtils || {};
    const router = window.vmaRouter || {};

    const {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle
    } = utils;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Products initialisation skipped: utilities not available.');
        return;
    }

    function normaliseProducts(payload) {
        if (!payload || typeof payload !== 'object') {
            return [];
        }

        if (Array.isArray(payload)) {
            return payload;
        }

        if ('result' in payload) {
            return Array.isArray(payload.result) ? payload.result : [];
        }

        return [];
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

        const toolbar = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        const toolbarTitle = createElementWithAttrs('h2', 'Products');
        const toolbarActions = createElementWithAttrs('div', '', { class: 'toolbar-actions' });
        const toggleFormButton = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn primary',
            'data-product-form-toggle': ''
        });
        toggleFormButton.innerHTML = '<i class="fas fa-plus"></i> Create Product';
        const toggleDeleteButton = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn danger',
            'data-product-delete-toggle': ''
        });
        toggleDeleteButton.innerHTML = '<i class="fas fa-trash"></i> Delete Product';
        toolbarActions.appendChild(toggleFormButton);
        toolbarActions.appendChild(toggleDeleteButton);
        toolbar.appendChild(toolbarTitle);
        toolbar.appendChild(toolbarActions);

        const formCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
        formCard.innerHTML = `
            <h3>Create Product</h3>
            <form data-product-form>
                <div class="form-group">
                    <label for="product-id">Product ID</label>
                    <input type="text" id="product-id" name="id" placeholder="example-product" required>
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

        const listCard = createElementWithAttrs('div', '', { class: 'table-card page-section' });
        listCard.innerHTML = `
            <div class="table-header">
                <h2>Existing Products</h2>
                <span class="badge" data-product-count>0</span>
            </div>
            <div class="inline-message" data-product-list-feedback hidden></div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody data-product-rows>
                    <tr><td colspan="2" class="empty">Loading…</td></tr>
                </tbody>
            </table>
        `;

        wrapper.appendChild(toolbar);
        wrapper.appendChild(formCard);
        wrapper.appendChild(deleteCard);
        wrapper.appendChild(listCard);
        root.appendChild(wrapper);

        return {
            toggleFormButton,
            toggleDeleteButton,
            formCard,
            deleteCard,
            listCard,
            form: formCard.querySelector('[data-product-form]'),
            feedback: formCard.querySelector('[data-product-feedback]'),
            listFeedback: listCard.querySelector('[data-product-list-feedback]'),
            rowsBody: listCard.querySelector('[data-product-rows]'),
            counter: listCard.querySelector('[data-product-count]'),
            deleteForm: deleteCard.querySelector('[data-product-delete-form]'),
            deleteFeedback: deleteCard.querySelector('[data-product-delete-feedback]'),
            deleteSelect: deleteCard.querySelector('#product-delete-id')
        };
    }

    function renderRows(rowsBody, counter, items) {
        if (!rowsBody || !counter) {
            return;
        }

        if (!Array.isArray(items) || !items.length) {
            rowsBody.innerHTML = '<tr><td colspan="2" class="empty">No products yet.</td></tr>';
            counter.textContent = '0';
            return;
        }

        rowsBody.innerHTML = '';
        items.forEach(item => {
            const id = item.id ?? item.name ?? item[0];
            const description = item.description ?? item[1] ?? '—';

            const row = document.createElement('tr');
            row.appendChild(createElementWithAttrs('td', id || '—'));
            row.appendChild(createElementWithAttrs('td', description || '—'));
            rowsBody.appendChild(row);
        });
        counter.textContent = items.length;
    }

    async function loadProducts(state, helpers = {}) {
        if (!state.rowsBody || !state.counter) {
            return;
        }

        state.rowsBody.innerHTML = '<tr><td colspan="2" class="empty">Loading…</td></tr>';
        helpers.form?.hideMessage();
        helpers.list?.hideMessage();
        helpers.delete?.hideMessage();

        try {
            const payload = await fetchJSON(apiUrl('/products'));
            const products = normaliseProducts(payload);
            renderRows(state.rowsBody, state.counter, products);
            state.productsData = products;
            updateDeleteOptions(state);
        } catch (error) {
            renderRows(state.rowsBody, state.counter, []);
            helpers.list?.showMessage(error.message || 'Unable to load products.', 'error');
        }
    }

    function handleSubmit(state, helpers) {
        if (!state.form) {
            return;
        }

        state.form.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.form?.hideMessage();

            const formData = new FormData(state.form);
            const payload = {
                name: formData.get('id')?.trim(),
                description: formData.get('description')?.trim() || null
            };

            if (!payload.name) {
                helpers.form?.showMessage('Product ID is required.', 'error');
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
                helpers.form?.showMessage('Product created successfully.', 'success');
            } catch (error) {
                helpers.form?.showMessage(error.message || 'Failed to create product.', 'error');
            }
        });

        state.form.addEventListener('reset', () => {
            helpers.form?.hideMessage();
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
        products.forEach(product => {
            const value = product.id ?? product.name ?? product[0];
            if (!value) {
                return;
            }
            select.appendChild(createElementWithAttrs('option', value, { value }));
        });

        if (products.some(product => (product.id ?? product.name ?? product[0]) === previous)) {
            select.value = previous;
        } else {
            select.value = '';
        }

        select.disabled = !products.length;
    }

    function handleDeleteForm(state, helpers) {
        if (!state.deleteForm) {
            return;
        }

        state.deleteForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.delete?.hideMessage();

            const productId = state.deleteSelect?.value?.trim();
            if (!productId) {
                helpers.delete?.showMessage('Select a product to delete.', 'error');
                return;
            }

            const confirmed = window.confirm(`Delete product "${productId}"? This action cannot be undone.`);
            if (!confirmed) {
                return;
            }

            try {
                await fetchJSON(apiUrl(`/product/${encodeURIComponent(productId)}`), {
                    method: 'DELETE'
                });
                await loadProducts(state, helpers);
                helpers.delete?.showMessage(`Product "${productId}" deleted successfully.`, 'success');
                resetDeleteForm(state);
            } catch (error) {
                helpers.delete?.showMessage(error.message || 'Failed to delete product.', 'error');
            }
        });

        state.deleteForm.addEventListener('reset', () => {
            helpers.delete?.hideMessage();
            resetDeleteForm(state);
        });
    }

    function setupFormToggle(state, helpers) {
        const { toggleFormButton, formCard, form } = state;
        if (!toggleFormButton || !formCard) {
            return;
        }

        const firstField = form?.querySelector('input, textarea, select');

        const updateButtonLabel = visible => {
            toggleFormButton.innerHTML = visible
                ? '<i class="fas fa-times"></i> Cancel'
                : '<i class="fas fa-plus"></i> Create Product';
            toggleFormButton.setAttribute('aria-expanded', String(visible));
        };

        const setFormVisible = visible => {
            formCard.classList.toggle('show', visible);
            updateButtonLabel(visible);
            if (visible) {
                helpers.form?.hideMessage();
                firstField?.focus();
            } else {
                form?.reset();
            }
        };

        toggleFormButton.addEventListener('click', () => {
            const shouldShow = !formCard.classList.contains('show');
            setFormVisible(shouldShow);
        });

        updateButtonLabel(false);
        state.setFormVisible = setFormVisible;
    }

    function createMessageHelpers(feedbackElement) {
        const showMessage = (message, type = 'info') => {
            if (!feedbackElement) {
                return;
            }
            feedbackElement.textContent = message;
            feedbackElement.className = `inline-message inline-message--${type}`;
            feedbackElement.hidden = false;
        };

        const hideMessage = () => {
            if (!feedbackElement) {
                return;
            }
            feedbackElement.hidden = true;
            feedbackElement.textContent = '';
        };

        return { showMessage, hideMessage };
    }

    function setupDeleteToggle(state, helpers) {
        const { toggleDeleteButton, deleteCard, deleteForm } = state;
        if (!toggleDeleteButton || !deleteCard) {
            return;
        }

        const firstField = deleteForm?.querySelector('select');

        const updateButtonLabel = visible => {
            toggleDeleteButton.innerHTML = visible
                ? '<i class="fas fa-times"></i> Cancel Delete'
                : '<i class="fas fa-trash"></i> Delete Product';
            toggleDeleteButton.setAttribute('aria-expanded', String(visible));
        };

        const setDeleteVisible = visible => {
            deleteCard.classList.toggle('show', visible);
            updateButtonLabel(visible);
            if (visible) {
                helpers.delete?.hideMessage();
                firstField?.focus();
            } else {
                resetDeleteForm(state);
            }
        };

        toggleDeleteButton.addEventListener('click', () => {
            const shouldShow = !deleteCard.classList.contains('show');
            setDeleteVisible(shouldShow);
        });

        updateButtonLabel(false);
        state.setDeleteVisible = setDeleteVisible;
    }

    registerRoute('products', () => {
        const state = renderProductsView();
        if (!state) {
            return;
        }

        const helpers = {
            form: createMessageHelpers(state.feedback),
            list: createMessageHelpers(state.listFeedback),
            delete: createMessageHelpers(state.deleteFeedback)
        };

        loadProducts(state, helpers);
        handleSubmit(state, helpers);
        setupFormToggle(state, helpers);
        setupDeleteToggle(state, helpers);
        handleDeleteForm(state, helpers);
    });
})();
