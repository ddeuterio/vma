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
        console.warn('Profile initialisation skipped: utilities not available.');
        return;
    }

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

    function formatDate(dateString) {
        if (!dateString) return 'Never';
        const date = new Date(dateString);
        return date.toLocaleString();
    }

    function renderProfileView() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return null;
        }

        setActiveRoute?.('profile');
        setPageTitle?.('Profile');
        clearElement(root);

        const wrapper = createElementWithAttrs('section', '', { class: 'profile-page' });

        // Page header
        const header = createElementWithAttrs('div', '', { class: 'page-section' });
        header.innerHTML = '<h2>User Profile</h2>';

        // Tabs navigation
        const tabs = createElementWithAttrs('div', '', { class: 'tabs page-section' });
        tabs.innerHTML = `
            <button class="tab-btn active" data-tab="info">
                <i class="fas fa-user"></i> Profile Info
            </button>
            <button class="tab-btn" data-tab="teams">
                <i class="fas fa-users"></i> Teams
            </button>
            <button class="tab-btn" data-tab="tokens">
                <i class="fas fa-key"></i> API Tokens
            </button>
        `;

        // Tab content containers
        const tabContent = createElementWithAttrs('div', '', { class: 'tab-content' });

        // Profile Info Tab
        const infoTab = createElementWithAttrs('div', '', {
            class: 'tab-pane active',
            'data-tab-pane': 'info'
        });
        infoTab.innerHTML = '<div data-profile-info class="page-section">Loading...</div>';

        // Teams Tab
        const teamsTab = createElementWithAttrs('div', '', {
            class: 'tab-pane',
            'data-tab-pane': 'teams'
        });
        teamsTab.innerHTML = '<div data-profile-teams class="page-section">Loading...</div>';

        // Tokens Tab
        const tokensTab = createElementWithAttrs('div', '', {
            class: 'tab-pane',
            'data-tab-pane': 'tokens'
        });

        const tokensToolbar = createElementWithAttrs('div', '', { class: 'toolbar page-section' });
        tokensToolbar.innerHTML = `
            <h3>API Tokens</h3>
            <div class="toolbar-actions">
                <button type="button" class="btn primary" data-token-create>
                    <i class="fas fa-plus"></i> Create Token
                </button>
            </div>
        `;

        const tokensInfo = createElementWithAttrs('div', '', { class: 'page-section' });
        tokensInfo.innerHTML = `
            <div class="inline-message inline-message--info">
                <p><strong>API Tokens</strong> allow you to authenticate with the VMA CLI and CI/CD pipelines.</p>
                <p>Tokens inherit all your user permissions and can access all teams you belong to.</p>
                <p><strong>Warning:</strong> Treat tokens like passwords. They are only shown once upon creation.</p>
            </div>
        `;

        const tokensContainer = createElementWithAttrs('div', '', { class: 'page-section' });
        const tokensMessage = createElementWithAttrs('div', '', { class: 'inline-message', hidden: true });
        const tokensList = createElementWithAttrs('div', '', { 'data-tokens-list': '' });
        tokensContainer.appendChild(tokensMessage);
        tokensContainer.appendChild(tokensList);

        tokensTab.appendChild(tokensToolbar);
        tokensTab.appendChild(tokensInfo);
        tokensTab.appendChild(tokensContainer);

        tabContent.appendChild(infoTab);
        tabContent.appendChild(teamsTab);
        tabContent.appendChild(tokensTab);

        // Modals
        const createModal = createTokenModal();
        const displayModal = createTokenDisplayModal();

        wrapper.appendChild(header);
        wrapper.appendChild(tabs);
        wrapper.appendChild(tabContent);
        wrapper.appendChild(createModal);
        wrapper.appendChild(displayModal);

        root.appendChild(wrapper);

        // Load user data
        loadProfileInfo(infoTab.querySelector('[data-profile-info]'));
        loadUserTeams(teamsTab.querySelector('[data-profile-teams]'));

        const tokensMsg = createMessageHelper(tokensMessage);
        loadTokens(tokensList, tokensMsg);

        // Tab switching
        tabs.querySelectorAll('.tab-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const tabName = btn.getAttribute('data-tab');
                switchTab(tabName, tabs, tabContent);
            });
        });

        // Token creation
        tokensToolbar.querySelector('[data-token-create]').addEventListener('click', () => {
            showCreateModal(createModal, displayModal, tokensList, tokensMsg);
        });

        return { tokensList, tokensMsg };
    }

    function switchTab(tabName, tabsContainer, contentContainer) {
        // Update tab buttons
        tabsContainer.querySelectorAll('.tab-btn').forEach(btn => {
            if (btn.getAttribute('data-tab') === tabName) {
                btn.classList.add('active');
            } else {
                btn.classList.remove('active');
            }
        });

        // Update tab panes
        contentContainer.querySelectorAll('.tab-pane').forEach(pane => {
            if (pane.getAttribute('data-tab-pane') === tabName) {
                pane.classList.add('active');
            } else {
                pane.classList.remove('active');
            }
        });
    }

    async function loadProfileInfo(container) {
        try {
            const claims = auth.getUserClaims?.();

            if (!claims) {
                container.innerHTML = '<p class="error">Unable to load user information.</p>';
                return;
            }

            container.innerHTML = `
                <div class="profile-info-card">
                    <div class="profile-avatar">
                        <i class="fas fa-user-circle fa-5x"></i>
                    </div>
                    <div class="profile-details">
                        <h3>${claims.username || 'User'}</h3>
                        <p class="text-muted">
                            <i class="fas fa-envelope"></i> ${claims.username}
                        </p>
                        ${claims.root ? '<p class="badge badge-admin"><i class="fas fa-shield-halved"></i> Root User</p>' : ''}
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error loading profile info:', error);
            container.innerHTML = '<p class="error">Error loading profile information.</p>';
        }
    }

    async function loadUserTeams(container) {
        try {
            const claims = auth.getUserClaims?.();
            const scope = claims?.scope || {};

            if (Object.keys(scope).length === 0) {
                container.innerHTML = '<p class="text-muted">You are not a member of any teams.</p>';
                return;
            }

            const table = createElementWithAttrs('table', '', { class: 'data-table' });
            table.innerHTML = `
                <thead>
                    <tr>
                        <th>Team Name</th>
                        <th>Your Role</th>
                    </tr>
                </thead>
                <tbody>
                    ${Object.entries(scope).map(([team, role]) => `
                        <tr>
                            <td>${team}</td>
                            <td><span class="badge badge-${getRoleBadgeClass(role)}">${role.toUpperCase()}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            `;

            clearElement(container);
            container.appendChild(table);
        } catch (error) {
            console.error('Error loading teams:', error);
            container.innerHTML = '<p class="error">Error loading team information.</p>';
        }
    }

    function getRoleBadgeClass(role) {
        const roleMap = {
            'admin': 'danger',
            'write': 'warning',
            'read': 'info',
            'read_only': 'info'
        };
        return roleMap[role.toLowerCase()] || 'secondary';
    }

    function createTokenModal() {
        const modal = createElementWithAttrs('div', '', { class: 'modal', 'data-create-modal': '' });
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Create API Token</h3>
                    <button class="modal-close" data-modal-close>&times;</button>
                </div>
                <div class="modal-body">
                    <form data-token-form>
                        <div class="form-group">
                            <label for="token-description">Description (optional)</label>
                            <input type="text" id="token-description" name="description"
                                   placeholder="e.g., CI/CD pipeline, local development">
                        </div>
                        <div class="form-group">
                            <label for="token-expires">Expiration</label>
                            <div class="form-row">
                                <input type="number" id="token-expires-days" name="expires_days"
                                       value="365" min="1" max="3650" style="flex: 1;">
                                <span style="padding: 0.5rem;">days</span>
                            </div>
                            <div class="form-check">
                                <input type="checkbox" id="token-no-expiry" name="no_expiry">
                                <label for="token-no-expiry">Never expires</label>
                            </div>
                        </div>
                        <div class="form-actions">
                            <button type="button" class="btn secondary" data-modal-close>Cancel</button>
                            <button type="submit" class="btn primary">Create Token</button>
                        </div>
                    </form>
                </div>
            </div>
        `;
        return modal;
    }

    function createTokenDisplayModal() {
        const modal = createElementWithAttrs('div', '', { class: 'modal', 'data-display-modal': '' });
        modal.innerHTML = `
            <div class="modal-content">
                <div class="modal-header">
                    <h3>Token Created Successfully</h3>
                </div>
                <div class="modal-body">
                    <div class="inline-message inline-message--warning">
                        <p><strong>Important:</strong> Copy this token now. You won't be able to see it again!</p>
                    </div>
                    <div class="token-display">
                        <code data-token-value style="word-break: break-all; display: block; padding: 1rem; background: var(--bg-secondary); border-radius: 4px; margin: 1rem 0;"></code>
                        <button type="button" class="btn secondary" data-copy-token>
                            <i class="fas fa-copy"></i> Copy to Clipboard
                        </button>
                    </div>
                    <div class="token-details" data-token-details style="margin-top: 1.5rem;"></div>
                    <div class="form-actions">
                        <button type="button" class="btn primary" data-modal-close>Done</button>
                    </div>
                </div>
            </div>
        `;
        return modal;
    }

    function showCreateModal(modal, displayModal, listContainer, message) {
        modal.style.display = 'flex';

        const form = modal.querySelector('[data-token-form]');
        const descInput = modal.querySelector('#token-description');
        const expiresInput = modal.querySelector('#token-expires-days');
        const noExpiryCheckbox = modal.querySelector('#token-no-expiry');

        // Reset form
        descInput.value = '';
        expiresInput.value = '365';
        noExpiryCheckbox.checked = false;
        expiresInput.disabled = false;

        // Toggle expiry input
        noExpiryCheckbox.addEventListener('change', (e) => {
            expiresInput.disabled = e.target.checked;
        });

        // Close buttons
        modal.querySelectorAll('[data-modal-close]').forEach(btn => {
            btn.onclick = () => modal.style.display = 'none';
        });

        // Form submit
        form.onsubmit = async (e) => {
            e.preventDefault();
            await createToken(form, modal, displayModal, listContainer, message);
        };
    }

    async function createToken(form, createModal, displayModal, listContainer, message) {
        const formData = new FormData(form);
        const description = formData.get('description') || null;
        const noExpiry = formData.get('no_expiry') === 'on';
        const expiresDays = noExpiry ? null : parseInt(formData.get('expires_days') || '365');

        const submitBtn = form.querySelector('button[type="submit"]');
        submitBtn.disabled = true;
        submitBtn.textContent = 'Creating...';

        try {
            const response = await fetchJSON(apiUrl('/tokens'), {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    description: description,
                    expires_days: expiresDays
                })
            });

            createModal.style.display = 'none';
            showTokenDisplay(response, displayModal);
            loadTokens(listContainer, message);

        } catch (error) {
            console.error('Error creating token:', error);
            message.show(`Error creating token: ${error.message}`, 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.textContent = 'Create Token';
        }
    }

    function showTokenDisplay(tokenData, modal) {
        const tokenValueEl = modal.querySelector('[data-token-value]');
        const detailsEl = modal.querySelector('[data-token-details]');
        const copyBtn = modal.querySelector('[data-copy-token]');

        tokenValueEl.textContent = tokenData.token;

        detailsEl.innerHTML = `
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

        copyBtn.onclick = () => copyToClipboard(tokenData.token, copyBtn);

        modal.style.display = 'flex';

        modal.querySelector('[data-modal-close]').onclick = () => {
            modal.style.display = 'none';
        };
    }

    function copyToClipboard(text, button) {
        navigator.clipboard.writeText(text).then(() => {
            const originalHTML = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i> Copied!';
            button.classList.add('btn-success');
            setTimeout(() => {
                button.innerHTML = originalHTML;
                button.classList.remove('btn-success');
            }, 2000);
        }).catch(err => {
            console.error('Failed to copy:', err);
            alert('Failed to copy token to clipboard');
        });
    }

    async function loadTokens(container, message) {
        clearElement(container);
        container.innerHTML = '<div class="loading">Loading tokens...</div>';
        message.hide();

        try {
            const tokens = await fetchJSON(apiUrl('/tokens'));

            clearElement(container);

            if (!tokens || tokens.length === 0) {
                container.innerHTML = `
                    <div class="empty-state">
                        <i class="fas fa-key fa-3x" style="color: var(--text-muted); margin-bottom: 1rem;"></i>
                        <p>No API tokens yet.</p>
                        <p>Create a token to use with the CLI or CI/CD pipelines.</p>
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
                        <button class="btn btn-sm danger" data-revoke-token="${token.id}">
                            <i class="fas fa-trash"></i> Revoke
                        </button>
                    </td>
                `;
                tbody.appendChild(row);
            });

            container.appendChild(table);

            // Add revoke event listeners
            container.querySelectorAll('[data-revoke-token]').forEach(btn => {
                btn.addEventListener('click', async () => {
                    const tokenId = btn.getAttribute('data-revoke-token');
                    await revokeToken(tokenId, container, message);
                });
            });

        } catch (error) {
            console.error('Error loading tokens:', error);
            clearElement(container);
            message.show(`Error loading tokens: ${error.message}`, 'error');
        }
    }

    async function revokeToken(tokenId, container, message) {
        if (!confirm('Are you sure you want to revoke this token? This action cannot be undone.')) {
            return;
        }

        try {
            await fetchJSON(apiUrl(`/tokens/${tokenId}`), {
                method: 'DELETE'
            });

            message.show('Token revoked successfully', 'success');
            loadTokens(container, message);

        } catch (error) {
            console.error('Error revoking token:', error);
            message.show(`Error revoking token: ${error.message}`, 'error');
        }
    }

    // Register route
    registerRoute?.('profile', renderProfileView);

})();
