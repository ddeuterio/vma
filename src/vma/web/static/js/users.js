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
    formatDate,
    copyToClipboard,
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
    console.warn('Users initialisation skipped: utilities not available.');
    return;
  }

  const ensureRoot = () => Boolean(auth.isRoot?.());


  function renderRestricted() {
    const root = document.getElementById('vmaContent');
    if (!root) {
      return;
    }
    setActiveRoute?.(null);
    setPageTitle?.('Users');
    clearElement(root);
    root.appendChild(
      createElementWithAttrs(
        'div',
        'You need root privileges to manage users.',
        { class: 'inline-message inline-message--error' }
      )
    );
  }

  function renderUsersView() {
    const root = document.getElementById('vmaContent');
    if (!root) {
      return null;
    }

    setActiveRoute?.('users');
    setPageTitle?.('Users');
    clearElement(root);

    const wrapper = createElementWithAttrs('section', '', { class: 'users-page' });

    const toolbar = createToolbar({
      title: 'Users',
      buttons: [
        {
          label: 'Create User',
          icon: 'fas fa-user-plus',
          className: 'btn primary',
          attributes: { 'data-user-create-toggle': '' }
        },
        {
          label: 'Delete User',
          icon: 'fas fa-user-minus',
          className: 'btn danger',
          attributes: { 'data-user-delete-toggle': '' }
        }
      ]
    });
    const [createToggle, deleteToggle] = toolbar.buttons;

    const createCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
    createCard.innerHTML = `
            <h3>Create User</h3>
            <form data-user-form>
                <div class="form-group">
                    <label for="user-email">Email</label>
                    <input type="email" id="user-email" name="email" placeholder="user@example.com" required>
                </div>
                <div class="form-group">
                    <label for="user-name">Name</label>
                    <input type="text" id="user-name" name="name" placeholder="Display name">
                </div>
                <div class="form-group">
                    <label for="user-password">Password</label>
                    <input type="password" id="user-password" name="password" placeholder="Strong password" required>
                </div>
                <div class="form-group checkbox-group">
                    <label class="checkbox-field">
                        <input type="checkbox" data-user-root-toggle>
                        <span>Grant super-user (root) access</span>
                    </label>
                    <p class="field-hint">Root users can manage all teams and application settings.</p>
                </div>
                <div class="form-group">
                    <label>Team permissions</label>
                    <div class="team-scope-list" data-user-scope-list>
                        <p class="field-hint">Loading teams…</p>
                    </div>
                    <p class="field-hint">Choose read or write access per team. Leave as “No access” to skip.</p>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Save User
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-user-form-feedback hidden></div>
        `;

    const deleteCard = createElementWithAttrs('div', '', { class: 'form-card page-section hidden-form' });
    deleteCard.innerHTML = `
            <h3>Delete User</h3>
            <form data-user-delete-form>
                <div class="form-group">
                    <label for="user-delete-select">User</label>
                    <select id="user-delete-select" name="email" required disabled>
                        <option value="">Select a user…</option>
                    </select>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn danger">
                        <i class="fas fa-trash"></i>
                        Delete User
                    </button>
                    <button type="reset" class="btn secondary">Reset</button>
                </div>
            </form>
            <div class="inline-message" data-user-delete-feedback hidden></div>
        `;

    const { element: listCard, tbody: rowsBody, counter, feedback: listFeedback } = createTableCard({
      title: 'Existing Users',
      columns: ['Email', 'Name', ''],
      dataAttribute: 'data-user-rows',
      countAttribute: 'data-user-count',
      feedbackAttribute: 'data-user-list-feedback'
    });

    // Edit view (separate full-page view)
    const editView = createElementWithAttrs('div', '', { class: 'edit-view', 'data-edit-view': '', hidden: true });
    const editViewHeader = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
    editViewHeader.innerHTML = `
            <h2>Edit User</h2>
            <div class="toolbar-actions">
                <button type="button" class="btn secondary" data-back-to-list>
                    <i class="fas fa-arrow-left"></i> Back to Users
                </button>
            </div>
        `;

    const editCard = createElementWithAttrs('div', '', { class: 'form-card page-section' });
    editCard.innerHTML = `
            <form data-user-edit-form>
                <div class="form-group">
                    <label for="user-edit-email">Email</label>
                    <input type="email" id="user-edit-email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="user-edit-password">New Password</label>
                    <input type="password" id="user-edit-password" name="password" placeholder="Leave blank to keep current password">
                    <p class="field-hint">Set only if you need to rotate the user password.</p>
                </div>
                <div class="form-group">
                    <label for="user-edit-name">Name</label>
                    <input type="text" id="user-edit-name" name="name">
                </div>
                <div class="form-group checkbox-group">
                    <label class="checkbox-field">
                        <input type="checkbox" data-user-edit-root>
                        <span>Grant super-user (root) access</span>
                    </label>
                    <p class="field-hint">Root users can manage all teams and application settings.</p>
                </div>
                <div class="form-group">
                    <label>Team permissions</label>
                    <div class="team-scope-list" data-user-edit-scope-list>
                        <p class="field-hint">Select a user to edit their team access.</p>
                    </div>
                    <p class="field-hint">Choose read or write access per team. Leave as "No access" to remove access.</p>
                </div>
                <div class="form-actions">
                    <button type="submit" class="btn primary">
                        <i class="fas fa-save"></i>
                        Save Changes
                    </button>
                    <button type="button" class="btn secondary" data-user-edit-cancel>Cancel</button>
                </div>
            </form>
            <div class="inline-message" data-user-edit-feedback hidden></div>
        `;

    // API Tokens Section - Separate visual container
    const tokensSection = createElementWithAttrs('div', '', {
      class: 'form-card page-section',
      style: 'margin-top: 2rem; border-top: 3px solid var(--border-color);'
    });
    tokensSection.innerHTML = `
            <h3><i class="fas fa-key"></i> API Tokens</h3>
            <div data-user-tokens-section>
                <div class="inline-message inline-message--info" style="margin-bottom: 1rem;">
                    <p>API tokens allow CLI and CI/CD authentication. Tokens inherit all user permissions.</p>
                </div>
                <button type="button" class="btn secondary" data-create-user-token-toggle style="margin-bottom: 1rem;">
                    <i class="fas fa-plus"></i> Create Token for User
                </button>

                <!-- Token creation form (hidden by default) -->
                <div class="form-card hidden-form" data-token-create-form-card style="margin-bottom: 1rem;">
                    <h4>Create API Token</h4>
                    <form data-token-create-form>
                            <div class="form-group">
                                <label for="token-description">Description (optional)</label>
                                <input type="text" id="token-description" name="description" placeholder="e.g., CI/CD pipeline, local development">
                            </div>
                            <div class="form-group">
                                <label for="token-expires">Expiration</label>
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <input type="number" id="token-expires-days" name="expires_days" value="365" min="1" max="3650" style="flex: 1;">
                                    <span>days</span>
                                </div>
                                <label style="margin-top: 0.5rem;">
                                    <input type="checkbox" id="token-no-expiry" name="no_expiry">
                                    Never expires
                                </label>
                            </div>
                            <div class="form-actions">
                                <button type="submit" class="btn primary">
                                    <i class="fas fa-save"></i> Create Token
                                </button>
                                <button type="button" class="btn secondary" data-token-create-cancel>Cancel</button>
                            </div>
                        </form>
                        <div class="inline-message" data-token-create-feedback hidden></div>
                    </div>

                    <!-- Token display area (hidden by default) -->
                    <div class="form-card hidden-form" data-token-display-card style="margin-bottom: 1rem;">
                        <h4>Token Created Successfully</h4>
                        <div class="inline-message inline-message--warning">
                            <p><strong>Important:</strong> Copy this token now. You won't be able to see it again!</p>
                        </div>
                        <div style="margin: 1rem 0;">
                            <code data-token-value style="word-break: break-all; display: block; padding: 1rem; background: var(--bg-secondary); border-radius: 4px;"></code>
                            <button type="button" class="btn secondary" data-copy-token style="margin-top: 1rem;">
                                <i class="fas fa-copy"></i> Copy to Clipboard
                            </button>
                        </div>
                        <div data-token-details></div>
                        <div class="form-actions">
                            <button type="button" class="btn primary" data-token-display-close>Done</button>
                        </div>
                    </div>

                    <div data-user-tokens-list>
                        <p class="field-hint">Select a user to view their tokens.</p>
                    </div>
                </div>
            </div>
        `;

    // List view (contains toolbar, create/delete forms, and table)
    const listView = createElementWithAttrs('div', '', { class: 'list-view', 'data-list-view': '' });
    listView.appendChild(toolbar);
    listView.appendChild(createCard);
    listView.appendChild(deleteCard);
    listView.appendChild(listCard);

    // Edit view assembly
    editView.appendChild(editViewHeader);
    editView.appendChild(editCard);
    editView.appendChild(tokensSection);

    wrapper.appendChild(listView);
    wrapper.appendChild(editView);
    root.appendChild(wrapper);

    return {
      listView,
      editView,
      backToListBtn: editViewHeader.querySelector('[data-back-to-list]'),
      createToggle,
      deleteToggle,
      editCard,
      createCard,
      deleteCard,
      tokensSection,
      createForm: createCard.querySelector('[data-user-form]'),
      deleteForm: deleteCard.querySelector('[data-user-delete-form]'),
      createFeedback: createCard.querySelector('[data-user-form-feedback]'),
      deleteFeedback: deleteCard.querySelector('[data-user-delete-feedback]'),
      deleteSelect: deleteCard.querySelector('#user-delete-select'),
      listFeedback,
      rowsBody,
      counter,
      scopeList: createCard.querySelector('[data-user-scope-list]'),
      rootToggle: createCard.querySelector('[data-user-root-toggle]'),
      editForm: editCard.querySelector('[data-user-edit-form]'),
      editFeedback: editCard.querySelector('[data-user-edit-feedback]'),
      editScopeList: editCard.querySelector('[data-user-edit-scope-list]'),
      editRootToggle: editCard.querySelector('[data-user-edit-root]'),
      editCancel: editCard.querySelector('[data-user-edit-cancel]'),
      editEmailInput: editCard.querySelector('#user-edit-email'),
      editNameInput: editCard.querySelector('#user-edit-name'),
      userTokensList: tokensSection.querySelector('[data-user-tokens-list]'),
      createUserTokenToggle: tokensSection.querySelector('[data-create-user-token-toggle]'),
      tokenCreateFormCard: tokensSection.querySelector('[data-token-create-form-card]'),
      tokenCreateForm: tokensSection.querySelector('[data-token-create-form]'),
      tokenCreateFeedback: tokensSection.querySelector('[data-token-create-feedback]'),
      tokenCreateCancel: tokensSection.querySelector('[data-token-create-cancel]'),
      tokenDisplayCard: tokensSection.querySelector('[data-token-display-card]'),
      tokenValueDisplay: tokensSection.querySelector('[data-token-value]'),
      tokenDetailsDisplay: tokensSection.querySelector('[data-token-details]'),
      tokenCopyBtn: tokensSection.querySelector('[data-copy-token]'),
      tokenDisplayClose: tokensSection.querySelector('[data-token-display-close]'),
      editingUserEmail: null,
      teamOptions: [],
      users: []
    };
  }

  function renderRows(state) {
    if (!state.rowsBody || !state.counter) {
      return;
    }
    const data = Array.isArray(state.users) ? state.users : [];
    if (!data.length) {
      state.rowsBody.innerHTML = createEmptyState({
        message: 'No users yet.',
        colspan: 3,
        context: 'table'
      });
      state.counter.textContent = '0';
      return;
    }
    state.rowsBody.innerHTML = '';
    data.forEach(user => {
      const email = user.email ?? user[0] ?? '—';
      const name = user.name ?? user[2] ?? '—';
      const row = document.createElement('tr');
      row.appendChild(createElementWithAttrs('td', email));
      row.appendChild(createElementWithAttrs('td', name || '—'));
      const actionCell = document.createElement('td');
      const editButton = createElementWithAttrs('button', 'Edit', {
        type: 'button',
        class: 'btn link',
        'data-user-action': 'edit',
        'data-user-email': email
      });
      actionCell.appendChild(editButton);
      row.appendChild(actionCell);
      state.rowsBody.appendChild(row);
    });
    state.counter.textContent = String(data.length);
  }

  function updateDeleteOptions(state) {
    if (!state.deleteSelect) {
      return;
    }
    selectHelpers.populate(state.deleteSelect, state.users, {
      valueKey: item => item.email ?? item[0],
      labelKey: item => item.email ?? item[0],
      placeholder: 'Select a user…',
      preserveValue: true
    });
  }

  function clearScopeSelections(container) {
    container?.querySelectorAll('[data-team-select]').forEach(select => {
      select.value = '';
    });
  }

  function resetScopeSelections(state) {
    if (state.rootToggle) {
      state.rootToggle.checked = false;
    }
    clearScopeSelections(state.scopeList);
  }

  function resetEditScopeSelections(state) {
    if (state.editRootToggle) {
      state.editRootToggle.checked = false;
    }
    clearScopeSelections(state.editScopeList);
  }

  function renderScopeOptions(state, container, selected = {}) {
    if (!container) {
      return;
    }
    const teams = Array.isArray(state.teamOptions) ? state.teamOptions : [];
    if (!teams.length) {
      container.innerHTML =
        '<p class="field-hint">No teams available. Create teams before assigning user access.</p>';
      return;
    }
    container.innerHTML = '';
    teams.forEach(team => {
      const name = team.name ?? team.id ?? team[0];
      if (!name) {
        return;
      }
      const row = createElementWithAttrs('div', '', { class: 'team-scope-row' });
      row.appendChild(createElementWithAttrs('span', name, { class: 'team-scope-name' }));
      const select = createElementWithAttrs('select', '', {
        'data-team-select': '',
        'data-team-name': name
      });
      select.innerHTML = `
                <option value="">No access</option>
                <option value="read">Read</option>
                <option value="write">Write</option>
                <option value="admin">Admin</option>
            `;
      const current = String(selected[name] || '').toLowerCase();
      if (current) {
        select.value = current;
      }
      row.appendChild(select);
      container.appendChild(row);
    });
  }

  async function loadTeamOptions(state, helpers) {
    if (state.scopeList) {
      state.scopeList.innerHTML = '<p class="field-hint">Loading teams…</p>';
    }
    if (state.editScopeList) {
      state.editScopeList.innerHTML = '<p class="field-hint">Loading teams…</p>';
    }
    try {
      const payload = await fetchJSON(apiUrl('/teams'));
      state.teamOptions = normalizeApiResponse(payload);
      renderScopeOptions(state, state.scopeList);
      renderScopeOptions(state, state.editScopeList);
    } catch (error) {
      state.teamOptions = [];
      if (state.scopeList) {
        state.scopeList.innerHTML =
          '<p class="inline-message inline-message--error">Unable to load teams for scopes.</p>';
      }
      if (state.editScopeList) {
        state.editScopeList.innerHTML =
          '<p class="inline-message inline-message--error">Unable to load teams for scopes.</p>';
      }
      helpers.create.show(error.message || 'Unable to load teams for scopes.', 'error');
      throw error;
    }
  }

  function collectScopeEntries(container) {
    const entries = [];
    container?.querySelectorAll('[data-team-select]').forEach(select => {
      const team = select.getAttribute('data-team-name');
      const permission = select.value;
      if (team && permission) {
        entries.push(`${team}:${permission}`);
      }
    });
    return entries;
  }

  function normaliseScopeResponse(raw) {
    if (!raw) {
      return {};
    }
    if (typeof raw === 'object' && !Array.isArray(raw)) {
      return raw;
    }
    const result = {};
    if (typeof raw === 'string') {
      raw.split(',').forEach(entry => {
        const [team, perm] = entry.split(':');
        if (team && perm) {
          result[team.trim()] = perm.trim();
        }
      });
      return result;
    }
    if (Array.isArray(raw)) {
      raw.forEach(item => {
        if (item && typeof item === 'object' && item.team) {
          result[item.team] = item.scope ?? item.permission ?? '';
        }
      });
    }
    return result;
  }

  function showListView(state) {
    if (state.listView) {
      state.listView.hidden = false;
    }
    if (state.editView) {
      state.editView.hidden = true;
    }
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
    state.editingUserEmail = null;
    state.editingUserOriginalData = null;
    state.editForm?.reset();
    resetEditScopeSelections(state);
  }

  function populateEditForm(state, data, helpers) {
    if (!state.editCard) {
      return;
    }
    state.editingUserEmail = data.originalEmail || data.email;

    // Store original values for comparison during PATCH
    state.editingUserOriginalData = {
      email: data.email || '',
      name: data.name || '',
      scopes: data.scopes || {},
      isRoot: data.isRoot || false
    };

    if (state.editEmailInput) {
      state.editEmailInput.value = data.email || '';
    }
    if (state.editNameInput) {
      state.editNameInput.value = data.name || '';
    }
    if (state.editRootToggle) {
      state.editRootToggle.checked = data.isRoot || false;
    }
    renderScopeOptions(state, state.editScopeList, data.scopes || {});

    // Load user tokens
    if (helpers) {
      loadUserTokens(state, state.editingUserEmail, helpers);
    }

    // Switch to edit view
    showEditView(state);
    state.editEmailInput?.focus();
  }

  async function fetchUserDetails(state, email) {
    const payload = await fetchJSON(apiUrl(`/user/${encodeURIComponent(email)}`));
    const resultPayload =
      Array.isArray(payload?.result) && payload.result.length
        ? payload.result[0]
        : Array.isArray(payload)
          ? payload[0]
          : payload?.result || payload;
    if (!resultPayload) {
      throw new Error('Unable to load user details.');
    }

    const scopeRaw =
      resultPayload.scopes
      || resultPayload.scope
      || resultPayload.permissions
      || resultPayload.scopes_raw;
    const scopes = normaliseScopeResponse(scopeRaw);
    const isRoot = Boolean(
      resultPayload.is_root ?? resultPayload.root ?? resultPayload.admin
    );

    return {
      originalEmail: email,
      email: resultPayload.email ?? email,
      name: resultPayload.name ?? '',
      scopes,
      isRoot
    };
  }

  async function loadUsers(state, helpers) {
    if (!state.rowsBody) {
      return;
    }
    state.rowsBody.innerHTML = '<tr><td colspan="3" class="empty">Loading…</td></tr>';
    helpers.list.hide();
    helpers.create.hide();
    helpers.delete.hide();
    try {
      const payload = await fetchJSON(apiUrl('/users'));
      state.users = normalizeApiResponse(payload);
      renderRows(state);
      updateDeleteOptions(state);
    } catch (error) {
      state.rowsBody.innerHTML = '<tr><td colspan="3" class="empty">Unable to load users.</td></tr>';
      state.counter.textContent = '0';
      helpers.list.show(error.message || 'Failed to fetch users.', 'error');
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
      const email = formData.get('email')?.trim();
      const name = formData.get('name')?.trim() || '';
      const password = formData.get('password')?.trim();

      if (!email || !password) {
        helpers.create.show('Email and password are required.', 'error');
        return;
      }

      const scopeEntries = collectScopeEntries(state.scopeList);
      const isRoot = Boolean(state.rootToggle?.checked);
      if (!scopeEntries.length && !isRoot) {
        helpers.create.show('Grant root access or select at least one team permission.', 'error');
        return;
      }

      // Build request body matching User model: email, password, name, scopes, root
      const request = {
        email: email,
        password: password,
        name: name,
        scopes: scopeEntries.join(','),
        root: isRoot
      };
      try {
        await fetchJSON(apiUrl('/user'), {
          method: 'POST',
          body: JSON.stringify(request)
        });
        helpers.create.show(`User "${email}" created successfully.`, 'success');
        state.createForm.reset();
        resetScopeSelections(state);
        await loadUsers(state, helpers);
      } catch (error) {
        helpers.create.show(error.message || 'Failed to create user.', 'error');
      }
    });
    state.createForm.addEventListener('reset', () => {
      helpers.create.hide();
      resetScopeSelections(state);
    });
  }

  function handleDeleteForm(state, helpers) {
    if (!state.deleteForm) {
      return;
    }
    state.deleteForm.addEventListener('submit', async event => {
      event.preventDefault();
      helpers.delete.hide();
      const email = state.deleteSelect?.value?.trim();
      if (!email) {
        helpers.delete.show('Select a user to delete.', 'error');
        return;
      }
      if (!window.confirm(`Delete user "${email}"? This action cannot be undone.`)) {
        return;
      }
      try {
        await fetchJSON(apiUrl(`/user/${encodeURIComponent(email)}`), {
          method: 'DELETE'
        });
        helpers.delete.show(`User "${email}" deleted successfully.`, 'success');
        state.deleteForm.reset();
        await loadUsers(state, helpers);
      } catch (error) {
        helpers.delete.show(error.message || 'Failed to delete user.', 'error');
      }
    });
    state.deleteForm.addEventListener('reset', () => {
      helpers.delete.hide();
    });
  }

  function attachUserRowInteractions(state, helpers) {
    if (!state.rowsBody) {
      return;
    }
    state.rowsBody.addEventListener('click', async event => {
      const button = event.target.closest('[data-user-action="edit"]');
      if (!button) {
        return;
      }
      const email = button.getAttribute('data-user-email');
      if (!email) {
        return;
      }
      helpers.edit.hide();
      try {
        if (!Array.isArray(state.teamOptions) || !state.teamOptions.length) {
          await loadTeamOptions(state, helpers);
        }
        const details = await fetchUserDetails(state, email);
        populateEditForm(state, details, helpers);
      } catch (error) {
        hideEditForm(state);
        helpers.list.show(error.message || 'Unable to load user details.', 'error');
      }
    });
  }

  function handleEditForm(state, helpers) {
    if (!state.editForm) {
      return;
    }
    state.editForm.addEventListener('submit', async event => {
      event.preventDefault();
      helpers.edit.hide();
      if (!state.editingUserEmail || !state.editingUserOriginalData) {
        helpers.edit.show('Select a user to edit.', 'error');
        return;
      }

      const formData = new FormData(state.editForm);
      const email = formData.get('email')?.trim();
      const name = formData.get('name')?.trim() || '';
      const password = formData.get('password')?.trim() || '';

      if (!email) {
        helpers.edit.show('Email is required.', 'error');
        return;
      }

      const scopeEntries = collectScopeEntries(state.editScopeList);
      const isRoot = Boolean(state.editRootToggle?.checked);
      if (!scopeEntries.length && !isRoot) {
        helpers.edit.show('Grant root access or select at least one team permission.', 'error');
        return;
      }

      // Build current scopes object for comparison
      const currentScopes = {};
      scopeEntries.forEach(entry => {
        const [team, perm] = entry.split(':');
        if (team && perm) {
          currentScopes[team.trim()] = perm.trim();
        }
      });

      // Compare scopes: check if they're different
      const originalScopes = state.editingUserOriginalData.scopes || {};
      const scopesChanged = JSON.stringify(originalScopes) !== JSON.stringify(currentScopes);

      // Build request body with ONLY changed fields (PATCH semantics)
      // Always include email to identify the user
      const requestBody = { email: email };

      // Only include fields that have changed
      if (password) {
        // Password field is filled, user wants to change it
        requestBody.password = password;
      }

      if (name !== state.editingUserOriginalData.name) {
        requestBody.name = name || null;
      }

      if (scopesChanged) {
        requestBody.scopes = scopeEntries.length > 0 ? scopeEntries.join(',') : null;
      }

      if (isRoot !== state.editingUserOriginalData.isRoot) {
        requestBody.root = isRoot;
      }

      // Check if anything actually changed
      if (Object.keys(requestBody).length === 1) {
        helpers.edit.show('No changes detected.', 'info');
        return;
      }

      try {
        await fetchJSON(apiUrl('/user'), {
          method: 'PATCH',
          body: JSON.stringify(requestBody)
        });

        // Update the local user object with new values
        const userIndex = state.users.findIndex(u =>
          (u.email ?? u[0]) === state.editingUserEmail
        );
        if (userIndex !== -1) {
          const user = state.users[userIndex];
          // Update fields that changed
          if (requestBody.email) user.email = email;
          if (requestBody.name !== undefined) user.name = name;
        }

        await loadUsers(state, helpers);
        hideEditForm(state);
        helpers.list.show(`User "${email}" updated successfully.`, 'success');
      } catch (error) {
        helpers.edit.show(error.message || 'Failed to update user.', 'error');
      }
    });

    state.editCancel?.addEventListener('click', () => {
      helpers.edit.hide();
      hideEditForm(state);
    });
  }

  function setupBackButton(state, helpers) {
    if (!state.backToListBtn) {
      return;
    }
    state.backToListBtn.addEventListener('click', () => {
      helpers.edit.hide();
      hideEditForm(state);
    });
  }

  function setupToggle(button, card, helper, labels, options = {}) {
    const { onHide } = options;
    const toggle = createFormToggle({
      button: button,
      container: card,
      form: card?.querySelector('form'),
      labels: labels,
      onShow: () => helper.hide(),
      onHide: onHide
    });

    return toggle.setVisible;
  }

  // Token management functions

  async function loadUserTokens(state, userEmail, helpers) {
    if (!state.userTokensList || !userEmail) {
      return;
    }

    clearElement(state.userTokensList);
    state.userTokensList.innerHTML = '<div class="loading">Loading tokens...</div>';

    try {
      // Get all tokens (root users see all tokens)
      const response = await fetchJSON(apiUrl(`/tokens/${encodeURIComponent(userEmail)}`));
      const tokens = normalizeApiResponse(response);

      clearElement(state.userTokensList);

      if (!tokens || tokens.length === 0) {
        state.userTokensList.innerHTML = `
                    <div class="empty-state" style="padding: 1rem; text-align: center; color: var(--text-muted);">
                        <i class="fas fa-key" style="font-size: 2rem; margin-bottom: 0.5rem;"></i>
                        <p>No API tokens yet.</p>
                    </div>
                `;
        return;
      }

      const table = createElementWithAttrs('table', '', { class: 'data-table' });
      table.innerHTML = `
                <thead>
                    <tr>
                        <th>Prefix</th>
                        <th>Description</th>
                        <th>Created</th>
                        <th>Last Used</th>
                        <th>Expires</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody></tbody>
            `;

      const tbody = table.querySelector('tbody');
      tokens.forEach(token => {
        const row = createElementWithAttrs('tr');
        row.innerHTML = `
                    <td><code>${token.prefix}</code></td>
                    <td>${token.description || '<em>No description</em>'}</td>
                    <td>${formatDate(token.created_at)}</td>
                    <td>${formatDate(token.last_used_at)}</td>
                    <td>${token.expires_at ? formatDate(token.expires_at) : 'Never'}</td>
                    <td>
                        <button class="btn btn-sm danger" data-revoke-user-token="${token.id}">
                            <i class="fas fa-trash"></i> Revoke
                        </button>
                    </td>
                `;
        tbody.appendChild(row);
      });

      state.userTokensList.appendChild(table);

      // Add revoke event listeners
      state.userTokensList.querySelectorAll('[data-revoke-user-token]').forEach(btn => {
        btn.addEventListener('click', async () => {
          const tokenId = btn.getAttribute('data-revoke-user-token');
          await revokeUserToken(state, userEmail, tokenId, helpers);
        });
      });

    } catch (error) {
      console.error('Error loading tokens:', error);
      clearElement(state.userTokensList);
      state.userTokensList.innerHTML = `
                <p class="inline-message inline-message--error">Error loading tokens: ${error.message}</p>
            `;
    }
  }

  async function revokeUserToken(state, userEmail, tokenId, helpers) {
    if (!window.confirm('Revoke this token? This action cannot be undone.')) {
      return;
    }

    try {
      await fetchJSON(apiUrl(`/tokens/${tokenId}`), {
        method: 'DELETE'
      });

      if (state.tokenHelper) {
        state.tokenHelper.show('Token revoked successfully', 'success');
      }
      loadUserTokens(state, userEmail, helpers);

    } catch (error) {
      console.error('Error revoking token:', error);
      if (state.tokenHelper) {
        state.tokenHelper.show(`Error revoking token: ${error.message}`, 'error');
      }
    }
  }

  function setupTokenCreation(state, helpers) {
    if (!state.createUserTokenToggle || !state.tokenCreateFormCard || !state.tokenCreateForm) {
      return;
    }

    // Create token message helper and add to state for use by all token functions
    state.tokenHelper = createMessageHelper(state.tokenCreateFeedback);

    // Toggle form visibility
    state.createUserTokenToggle.addEventListener('click', () => {
      const isVisible = state.tokenCreateFormCard.classList.contains('show');
      if (isVisible) {
        state.tokenCreateFormCard.classList.remove('show');
        state.createUserTokenToggle.innerHTML = '<i class="fas fa-key"></i> Create Token for User';
      } else {
        state.tokenCreateFormCard.classList.add('show');
        if (state.tokenDisplayCard) {
          state.tokenDisplayCard.classList.remove('show');
        }
        state.createUserTokenToggle.innerHTML = '<i class="fas fa-times"></i> Cancel';
        state.tokenCreateForm.reset();
        state.tokenHelper.hide();
      }
    });

    // Cancel button
    if (state.tokenCreateCancel) {
      state.tokenCreateCancel.addEventListener('click', () => {
        state.tokenCreateFormCard.classList.remove('show');
        state.createUserTokenToggle.innerHTML = '<i class="fas fa-key"></i> Create Token for User';
        state.tokenHelper.hide();
      });
    }

    // Toggle expiry checkbox
    const expiresInput = state.tokenCreateForm.querySelector('#token-expires-days');
    const noExpiryCheckbox = state.tokenCreateForm.querySelector('#token-no-expiry');
    if (expiresInput && noExpiryCheckbox) {
      noExpiryCheckbox.addEventListener('change', (e) => {
        expiresInput.disabled = e.target.checked;
      });
    }

    // Form submission
    state.tokenCreateForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!state.editingUserEmail) {
        state.tokenHelper.show('No user selected', 'error');
        return;
      }

      state.tokenHelper.hide();
      const formData = new FormData(state.tokenCreateForm);
      const description = formData.get('description') || null;
      const noExpiry = formData.get('no_expiry') === 'on';
      const expiresDays = noExpiry ? null : parseInt(formData.get('expires_days') || '365');

      const submitBtn = state.tokenCreateForm.querySelector('button[type="submit"]');
      submitBtn.disabled = true;
      submitBtn.textContent = 'Creating...';

      try {
        const response = await fetchJSON(apiUrl('/apitoken'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: state.editingUserEmail,
            description: description,
            expires_days: expiresDays
          })
        });

        const tokenData = response.result || response;

        // Hide create form
        state.tokenCreateFormCard.classList.remove('show');
        state.createUserTokenToggle.innerHTML = '<i class="fas fa-key"></i> Create Token for User';

        // Show token display
        showTokenDisplay(state, tokenData);

        // Reload token list
        loadUserTokens(state, state.editingUserEmail, helpers);

      } catch (error) {
        console.error('Error creating token:', error);
        state.tokenHelper.show(`Error creating token: ${error.message}`, 'error');
      } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Create Token';
      }
    });

    // Close token display
    if (state.tokenDisplayClose) {
      state.tokenDisplayClose.addEventListener('click', () => {
        state.tokenDisplayCard.classList.remove('show');
      });
    }

    // Copy token button
    if (state.tokenCopyBtn) {
      state.tokenCopyBtn.addEventListener('click', () => {
        const token = state.tokenValueDisplay.textContent;
        copyToClipboard(token, state.tokenCopyBtn, { successText: '<i class="fas fa-check"></i> Copied!' });
      });
    }
  }

  function showTokenDisplay(state, tokenData) {
    if (!state.tokenValueDisplay || !state.tokenDetailsDisplay || !state.tokenDisplayCard) {
      return;
    }

    state.tokenValueDisplay.textContent = tokenData.token;

    state.tokenDetailsDisplay.innerHTML = `
            <h4>Token Details</h4>
            <table class="details-table">
                <tr>
                    <td><strong>ID:</strong></td>
                    <td>${tokenData.id}</td>
                </tr>
                <tr>
                    <td><strong>Prefix:</strong></td>
                    <td><code>${tokenData.prefix}</code></td>
                </tr>
                <tr>
                    <td><strong>Description:</strong></td>
                    <td>${tokenData.description || 'N/A'}</td>
                </tr>
                <tr>
                    <td><strong>Expires:</strong></td>
                    <td>${tokenData.expires_at ? formatDate(tokenData.expires_at) : 'Never'}</td>
                </tr>
            </table>
            <h4>Usage Example</h4>
            <pre style="background: var(--bg-secondary); padding: 1rem; border-radius: 4px; overflow-x: auto;"><code>vma import \\
  --type grype \\
  --file scan.json \\
  --product my-product \\
  --token ${tokenData.token} \\
  --host ${window.location.hostname}</code></pre>
        `;

    state.tokenDisplayCard.classList.add('show');
  }

  registerRoute('users', () => {
    if (!ensureRoot()) {
      renderRestricted();
      return;
    }
    const state = renderUsersView();
    if (!state) {
      return;
    }
    const helpers = {
      list: createMessageHelper(state.listFeedback),
      create: createMessageHelper(state.createFeedback),
      delete: createMessageHelper(state.deleteFeedback),
      edit: createMessageHelper(state.editFeedback)
    };

    // Setup token creation
    setupTokenCreation(state, helpers);

    state.setCreateVisible = setupToggle(
      state.createToggle,
      state.createCard,
      helpers.create,
      {
        open: '<i class="fas fa-user-plus"></i> Create User',
        close: '<i class="fas fa-times"></i> Cancel'
      },
      { onHide: () => resetScopeSelections(state) }
    );
    state.setDeleteVisible = setupToggle(state.deleteToggle, state.deleteCard, helpers.delete, {
      open: '<i class="fas fa-user-minus"></i> Delete User',
      close: '<i class="fas fa-times"></i> Cancel Delete'
    });

    loadTeamOptions(state, helpers);
    (async () => {
      try {
        await loadTeamOptions(state, helpers);
      } catch (error) {
        // Already surfaced via helper
      }
      await loadUsers(state, helpers);
    })();
    handleCreateForm(state, helpers);
    handleDeleteForm(state, helpers);
    handleEditForm(state, helpers);
    attachUserRowInteractions(state, helpers);
    setupBackButton(state, helpers);
  });
})();
