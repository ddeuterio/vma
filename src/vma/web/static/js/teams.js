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
        createEmptyState
    } = components;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Teams initialisation skipped: utilities not available.');
        return;
    }

    const ensureRoot = () => Boolean(auth.isRoot?.());


    function renderRestrictedView() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return;
        }
        setActiveRoute?.(null);
        setPageTitle?.('Teams');
        clearElement(root);
        const message = createElementWithAttrs(
            'div',
            'You need root privileges to manage teams.',
            { class: 'inline-message inline-message--error' }
        );
        root.appendChild(message);
    }

    function renderTeamsView() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return null;
        }

        setActiveRoute?.('teams');
        setPageTitle?.('Teams');
        clearElement(root);

        const wrapper = createElementWithAttrs('section', '', { class: 'teams-page' });

        const toolbar = createToolbar({
            title: 'Teams',
            buttons: [
                {
                    label: 'Create Team',
                    icon: 'fas fa-plus',
                    className: 'btn primary',
                    attributes: { 'data-team-create-toggle': '' }
                },
                {
                    label: 'Delete Team',
                    icon: 'fas fa-trash',
                    className: 'btn danger',
                    attributes: { 'data-team-delete-toggle': '' }
                }
            ]
        });
        const [createToggle, deleteToggle] = toolbar.buttons;

        const createCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
        createCard.innerHTML = `
            <h3>Create Team</h3>
            <form data-team-form>
                <div class="form-group">
                    <label for="team-name">Team name</label>
                    <input type="text" id="team-name" name="name" placeholder="backend-team" required>
                </div>
                <div class="form-group">
                    <label for="team-description">Description</label>
                    <textarea id="team-description" name="description" rows="3" placeholder="Optional description"></textarea>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Save Team
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-team-form-feedback hidden></div>
        `;

        const deleteCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
        deleteCard.innerHTML = `
            <h3>Delete Team</h3>
            <form data-team-delete-form>
                <div class="form-group">
                    <label for="team-delete-select">Team</label>
                    <select id="team-delete-select" name="team" required disabled>
                        <option value="">Select a team…</option>
                    </select>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn danger">
                        <i class="fas fa-trash"></i>
                        Delete
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-team-delete-feedback hidden></div>
        `;

        const { element: listCard, tbody: rowsBody, counter, feedback: listFeedback } = createTableCard({
            title: 'Existing Teams',
            columns: ['Name', 'Description'],
            dataAttribute: 'data-team-rows',
            countAttribute: 'data-team-count',
            feedbackAttribute: 'data-team-list-feedback'
        });

        wrapper.appendChild(toolbar);
        wrapper.appendChild(createCard);
        wrapper.appendChild(deleteCard);
        wrapper.appendChild(listCard);
        root.appendChild(wrapper);

        return {
            wrapper,
            createToggle,
            deleteToggle,
            createFormCard: createCard,
            deleteFormCard: deleteCard,
            createForm: createCard.querySelector('[data-team-form]'),
            createFeedback: createCard.querySelector('[data-team-form-feedback]'),
            deleteForm: deleteCard.querySelector('[data-team-delete-form]'),
            deleteFeedback: deleteCard.querySelector('[data-team-delete-feedback]'),
            deleteSelect: deleteCard.querySelector('#team-delete-select'),
            listFeedback,
            rowsBody,
            counter,
            teams: []
        };
    }

    function renderRows(state) {
        if (!state.rowsBody || !state.counter) {
            return;
        }
        const data = Array.isArray(state.teams) ? state.teams : [];
        if (!data.length) {
            state.rowsBody.innerHTML = createEmptyState({
                message: 'No teams yet.',
                colspan: 2,
                context: 'table'
            });
            state.counter.textContent = '0';
            return;
        }
        state.rowsBody.innerHTML = '';
        data.forEach(team => {
            const name = team.name ?? team.id ?? team[0] ?? '—';
            const description = team.description ?? team[1] ?? '—';
            const row = document.createElement('tr');
            row.appendChild(createElementWithAttrs('td', name));
            row.appendChild(createElementWithAttrs('td', description || '—'));
            state.rowsBody.appendChild(row);
        });
        state.counter.textContent = String(data.length);
    }

    function updateDeleteOptions(state) {
        if (!state.deleteSelect) {
            return;
        }
        selectHelpers.populate(state.deleteSelect, state.teams, {
            valueKey: item => item.name ?? item.id ?? item[0],
            labelKey: item => item.name ?? item.id ?? item[0],
            placeholder: 'Select a team…',
            preserveValue: true
        });
    }

    async function loadTeams(state, helpers) {
        if (!state.rowsBody) {
            return;
        }
        state.rowsBody.innerHTML = '<tr><td colspan="2" class="empty">Loading…</td></tr>';
        helpers.list.hide();
        helpers.create.hide();
        helpers.delete.hide();
        try {
            const payload = await fetchJSON(apiUrl('/teams'));
            state.teams = normalizeApiResponse(payload);
            renderRows(state);
            updateDeleteOptions(state);
        } catch (error) {
            state.rowsBody.innerHTML = '<tr><td colspan="2" class="empty">Unable to load teams.</td></tr>';
            state.counter.textContent = '0';
            helpers.list.show(error.message || 'Failed to fetch teams.', 'error');
        }
    }

    function handleCreateForm(state, helpers) {
        if (!state.createForm) {
            return;
        }
        state.createForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.create.hide();
            const formData = new FormData(state.createForm);
            const payload = {
                name: formData.get('name')?.trim(),
                description: formData.get('description')?.trim() || null
            };
            if (!payload.name) {
                helpers.create.show('Team name is required.', 'error');
                return;
            }
            try {
                await fetchJSON(apiUrl('/team'), {
                    method: 'POST',
                    body: JSON.stringify(payload)
                });
                helpers.create.show(`Team "${payload.name}" created successfully.`, 'success');
                state.createForm.reset();
                await loadTeams(state, helpers);
            } catch (error) {
                helpers.create.show(error.message || 'Failed to create team.', 'error');
            }
        });
        state.createForm.addEventListener('reset', () => {
            helpers.create.hide();
        });
    }

    function handleDeleteForm(state, helpers) {
        if (!state.deleteForm) {
            return;
        }
        state.deleteForm.addEventListener('submit', async event => {
            event.preventDefault();
            helpers.delete.hide();
            const teamName = state.deleteSelect?.value?.trim();
            if (!teamName) {
                helpers.delete.show('Select a team to delete.', 'error');
                return;
            }
            if (
                !window.confirm(`Delete team "${teamName}"? This action cannot be undone and may impact access.`)
            ) {
                return;
            }
            try {
                await fetchJSON(apiUrl(`/team/${encodeURIComponent(teamName)}`), {
                    method: 'DELETE'
                });
                helpers.delete.show(`Team "${teamName}" deleted successfully.`, 'success');
                state.deleteForm.reset();
                await loadTeams(state, helpers);
            } catch (error) {
                helpers.delete.show(error.message || 'Failed to delete team.', 'error');
            }
        });
        state.deleteForm.addEventListener('reset', () => {
            helpers.delete.hide();
        });
    }

    function setupFormToggle(button, card, helpers, options = {}) {
        const { openLabel, closeLabel } = options;
        const toggle = createFormToggle({
            button: button,
            container: card,
            form: card?.querySelector('form'),
            labels: {
                open: openLabel,
                close: closeLabel
            },
            onShow: () => helpers.hide()
        });

        return toggle.setVisible;
    }

    registerRoute('teams', () => {
        if (!ensureRoot()) {
            renderRestrictedView();
            return;
        }

        const state = renderTeamsView();
        if (!state) {
            return;
        }

        const helpers = {
            list: createMessageHelper(state.listFeedback),
            create: createMessageHelper(state.createFeedback),
            delete: createMessageHelper(state.deleteFeedback)
        };

        state.setCreateVisible = setupFormToggle(state.createToggle, state.createFormCard, helpers.create, {
            openLabel: '<i class="fas fa-plus"></i> Create Team',
            closeLabel: '<i class="fas fa-times"></i> Cancel'
        });
        state.setDeleteVisible = setupFormToggle(state.deleteToggle, state.deleteFormCard, helpers.delete, {
            openLabel: '<i class="fas fa-trash"></i> Delete Team',
            closeLabel: '<i class="fas fa-times"></i> Cancel Delete'
        });

        loadTeams(state, helpers);
        handleCreateForm(state, helpers);
        handleDeleteForm(state, helpers);
    });
})();
