(function () {
    const utils = window.vmaUtils || {};
    const router = window.vmaRouter || {};
    const auth = window.vmaAuth || {};

    const {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle
    } = utils;

    const { registerRoute, setActiveRoute } = router;

    if (!createElementWithAttrs || !clearElement || !fetchJSON || !apiUrl || !registerRoute) {
        console.warn('Teams initialisation skipped: utilities not available.');
        return;
    }

    const ensureRoot = () => Boolean(auth.isRoot?.());

    function createMessageHelper(element) {
        return {
            show(message, type = 'info') {
                if (!element) {
                    return;
                }
                element.textContent = message;
                element.className = `inline-message inline-message--${type}`;
                element.hidden = false;
            },
            hide() {
                if (!element) {
                    return;
                }
                element.hidden = true;
                element.textContent = '';
            }
        };
    }

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

        const toolbar = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        toolbar.appendChild(createElementWithAttrs('h2', 'Teams'));
        const toolbarActions = createElementWithAttrs('div', '', { class: 'toolbar-actions' });

        const createToggle = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn primary',
            'data-team-create-toggle': ''
        });
        createToggle.innerHTML = '<i class="fas fa-plus"></i> Create Team';

        const deleteToggle = createElementWithAttrs('button', '', {
            type: 'button',
            class: 'btn danger',
            'data-team-delete-toggle': ''
        });
        deleteToggle.innerHTML = '<i class="fas fa-trash"></i> Delete Team';

        toolbarActions.appendChild(createToggle);
        toolbarActions.appendChild(deleteToggle);
        toolbar.appendChild(toolbarActions);

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

        const listCard = createElementWithAttrs('div', '', { class: 'table-card page-section' });
        listCard.innerHTML = `
            <div class="table-header">
                <h2>Existing Teams</h2>
                <span class="badge" data-team-count>0</span>
            </div>
            <div class="inline-message" data-team-list-feedback hidden></div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody data-team-rows>
                    <tr><td colspan="2" class="empty">Loading…</td></tr>
                </tbody>
            </table>
        `;

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
            listFeedback: listCard.querySelector('[data-team-list-feedback]'),
            rowsBody: listCard.querySelector('[data-team-rows]'),
            counter: listCard.querySelector('[data-team-count]'),
            teams: []
        };
    }

    function renderRows(state) {
        if (!state.rowsBody || !state.counter) {
            return;
        }
        const data = Array.isArray(state.teams) ? state.teams : [];
        if (!data.length) {
            state.rowsBody.innerHTML = '<tr><td colspan="2" class="empty">No teams yet.</td></tr>';
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
        const data = Array.isArray(state.teams) ? state.teams : [];
        const previous = state.deleteSelect.value;
        state.deleteSelect.innerHTML = '<option value="">Select a team…</option>';
        data.forEach(team => {
            const value = team.name ?? team.id ?? team[0];
            if (!value) {
                return;
            }
            state.deleteSelect.appendChild(createElementWithAttrs('option', value, { value }));
        });
        state.deleteSelect.disabled = !data.length;
        if (data.some(team => (team.name ?? team.id ?? team[0]) === previous)) {
            state.deleteSelect.value = previous;
        } else {
            state.deleteSelect.value = '';
        }
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
            state.teams = Array.isArray(payload?.result) ? payload.result : payload || [];
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
        if (!button || !card) {
            return () => {};
        }
        const form = card.querySelector('form');
        const firstField = form?.querySelector('input, textarea, select');
        const { openLabel, closeLabel } = options;

        const updateButton = visible => {
            button.innerHTML = visible ? closeLabel : openLabel;
            button.setAttribute('aria-expanded', String(visible));
        };

        const setVisible = visible => {
            card.classList.toggle('show', visible);
            updateButton(visible);
            if (visible) {
                helpers.hide();
                firstField?.focus();
            } else {
                form?.reset();
            }
        };

        button.addEventListener('click', () => {
            const next = !card.classList.contains('show');
            setVisible(next);
        });

        updateButton(false);
        return setVisible;
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
