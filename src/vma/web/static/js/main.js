(function () {
    const API_BASE = '/api/v1';
    const ROUTE_PATHS = {
        dashboard: '/',
        products: '/products',
        images: '/images',
        cve: '/cve',
        code: '/code'
    };
    const authState = {
        accessToken: null,
        refreshPromise: null,
        claims: null
    };
    const logoutState = {
        pending: false
    };

    const routeHandlers = new Map();
    let navigationInitialised = false;
    let currentRoute = null;
    const THEME_STORAGE_KEY = 'vma.theme';
    const THEME_LIGHT = 'light';
    const THEME_DARK = 'dark';
    let storedThemePreference = null;
    let currentTheme = THEME_LIGHT;
    let themeMediaQuery = null;

    function createElementWithAttrs(tag, text = '', attrs = {}) {
        const el = document.createElement(tag);
        Object.entries(attrs || {}).forEach(([key, value]) => {
            if (value !== undefined && value !== null) {
                if (key === 'hidden') {
                    el.hidden = Boolean(value);
                } else {
                    el.setAttribute(key, value);
                }
            }
        });
        if (text !== undefined && text !== null && text !== '') {
            el.textContent = text;
        }
        return el;
    }

    function clearElement(target) {
        if (!target) {
            return;
        }
        while (target.firstChild) {
            target.removeChild(target.firstChild);
        }
    }

    function decodeJwtPayload(token) {
        if (typeof token !== 'string' || !token.includes('.')) {
            return null;
        }
        const segments = token.split('.');
        if (segments.length < 2) {
            return null;
        }
        try {
            const normalized = segments[1].replace(/-/g, '+').replace(/_/g, '/');
            const padded = normalized.padEnd(normalized.length + (4 - (normalized.length % 4)) % 4, '=');
            const decoded = atob(padded);
            return JSON.parse(decoded);
        } catch (error) {
            console.warn('Unable to decode access token payload.', error);
            return null;
        }
    }

    function setAccessToken(token) {
        if (typeof token === 'string' && token.trim()) {
            authState.accessToken = token.trim();
            authState.claims = decodeJwtPayload(authState.accessToken);
        } else {
            authState.accessToken = null;
            authState.claims = null;
        }
    }

    function getAccessToken() {
        return authState.accessToken;
    }

    function clearAccessToken() {
        authState.accessToken = null;
        authState.claims = null;
    }

    function handleSessionExpired(message = 'Session expired. Please sign in again.', options = {}) {
        const { throwError = true } = options;
        clearAccessToken();
        window.location.replace('/');
        if (throwError) {
            throw new Error(message);
        }
    }

    function hydrateAccessTokenFromDom() {
        const body = document.body;
        if (!body || !body.dataset) {
            return;
        }
        const token = body.dataset.accessToken || '';
        if (token) {
            setAccessToken(token);
        }
        delete body.dataset.accessToken;
        body.removeAttribute('data-access-token');
    }

    function getUserClaims() {
        return authState.claims || null;
    }

    function getUserScope() {
        const claims = getUserClaims();
        if (!claims || typeof claims.scope !== 'object' || claims.scope === null) {
            return {};
        }
        return claims.scope;
    }

    function isRootUser() {
        return Boolean(getUserClaims()?.root);
    }

    function hasTeamPermission(team, permissions = []) {
        if (isRootUser()) {
            return true;
        }
        if (!team) {
            return false;
        }
        const scope = getUserScope();
        const value = String(scope?.[team] || '').toLowerCase();
        if (!value) {
            return false;
        }
        if (!Array.isArray(permissions) || !permissions.length) {
            return Boolean(value);
        }
        return permissions
            .map(permission => String(permission || '').toLowerCase())
            .includes(value);
    }

    function getTeamsByPermission(permissions = []) {
        const scope = getUserScope();
        const entries = Object.entries(scope);
        if (!entries.length) {
            return [];
        }
        return entries
            .filter(([team]) => hasTeamPermission(team, permissions))
            .map(([team, permission]) => ({
                name: team,
                permission,
            }));
    }

    function getWritableTeams() {
        return getTeamsByPermission(['write', 'admin']);
    }

    function applyRootVisibility() {
        const isRoot = isRootUser();
        document.querySelectorAll('[data-admin-only]').forEach(element => {
            element.hidden = !isRoot;
        });
    }

    function buildAuthHeaders(customHeaders = {}) {
        const headers = {
            Accept: 'application/json',
            'Content-Type': 'application/json',
            ...(customHeaders || {})
        };
        const token = getAccessToken();
        if (token) {
            headers.Authorization = `Bearer ${token}`;
        } else {
            delete headers.Authorization;
        }
        return headers;
    }

    async function authFetch(url, options = {}) {
        const requestOptions = {
            ...options,
            headers: buildAuthHeaders(options.headers)
        };

        let response = await fetch(url, requestOptions);
        return response;
    }

    async function fetchJSON(url, options = {}) {
        let response = await authFetch(url, options);

        // Handle 401 Unauthorized - try to refresh token
        if (response.status === 401) {
            try {
                // Attempt to refresh the access token
                await refreshAccessToken();

                // Retry the original request with the new token
                response = await authFetch(url, options);
            } catch (refreshError) {
                // Refresh failed - handleSessionExpired will redirect to login
                throw refreshError;
            }
        }

        if (!response.ok) {
            let message = `Request failed (${response.status})`;
            try {
                const payload = await response.json();
                if (payload && (payload.detail || payload.message)) {
                    message = payload.detail || payload.message;
                }
            } catch (error) {
                // ignore JSON parse errors
            }
            throw new Error(message);
        }

        if (response.status === 204) {
            return null;
        }

        return response.json();
    }

    function apiUrl(path = '') {
        if (!path || typeof path !== 'string') {
            return API_BASE;
        }
        if (/^https?:\/\//i.test(path)) {
            return path;
        }
        if (!path.startsWith('/')) {
            return `${API_BASE}/${path}`;
        }
        return `${API_BASE}${path}`;
    }

    async function refreshAccessToken() {
        if (authState.refreshPromise) {
            return authState.refreshPromise;
        }

        authState.refreshPromise = (async () => {
            const response = await fetch(apiUrl('/refresh_token'), {
                headers: { Accept: 'application/json' },
                credentials: 'same-origin'
            });

            if (!response.ok) {
                throw new Error('Unable to refresh session.');
            }

            const payload = await response.json();
            if (!payload || !payload.access_token) {
                throw new Error('Unable to refresh session.');
            }

            setAccessToken(payload.access_token);
            return payload.access_token;
        })();

        try {
            return await authState.refreshPromise;
        } catch (error) {
            handleSessionExpired('Session expired. Please sign in again.');
            throw error;
        } finally {
            authState.refreshPromise = null;
        }
    }

    async function logout() {
        if (logoutState.pending) {
            return;
        }
        logoutState.pending = true;

        const logoutButton = document.querySelector('[data-logout]');
        if (logoutButton) {
            logoutButton.disabled = true;
            logoutButton.setAttribute('aria-busy', 'true');
        }

        try {
            const response = await fetch(apiUrl('/logout'), {
                method: 'GET',
                headers: { Accept: 'application/json' },
                credentials: 'same-origin',
                cache: 'no-store'
            });
            if (!response.ok && response.status !== 404) {
                console.warn(`Logout request failed with status ${response.status}`);
            }
        } catch (error) {
            console.warn('Logout request failed', error);
        } finally {
            logoutState.pending = false;
            if (logoutButton) {
                logoutButton.disabled = false;
                logoutButton.removeAttribute('aria-busy');
            }
        }

        handleSessionExpired('You have been signed out.', { throwError: false });
    }

    function setPageTitle(text) {
        const pageTitle = document.getElementById('pageTitle');
        if (pageTitle && typeof text === 'string') {
            pageTitle.textContent = text;
        }
    }

    function routeToPath(route) {
        return ROUTE_PATHS[route] || '/';
    }

    function normalisePath(pathname) {
        if (!pathname) {
            return '/';
        }
        let path = pathname.trim();
        if (!path.startsWith('/')) {
            path = `/${path}`;
        }
        if (path.length > 1 && path.endsWith('/')) {
            path = path.slice(0, -1);
        }
        return path || '/';
    }

    function pathToRoute(pathname) {
        const normalised = normalisePath(pathname);
        const entry = Object.entries(ROUTE_PATHS).find(([, path]) => path === normalised);
        return entry ? entry[0] : 'dashboard';
    }

    function setActiveRoute(route) {
        document.querySelectorAll('[data-route]').forEach(element => {
            element.classList.toggle('active', element.dataset.route === route);
        });
    }

    function dispatchRoute(route, meta = {}) {
        console.log(`dispatch to route ${route}`)
        currentRoute = routeHandlers.has(route) ? route : 'dashboard';
        setActiveRoute(currentRoute);
        const handler = routeHandlers.get(currentRoute);
        if (typeof handler === 'function') {
            handler({ route: currentRoute, ...meta });
        }
    }

    function navigate(route, { replace = false } = {}) {
        console.log(`navigate to ${route}`)
        const targetRoute = routeHandlers.has(route) ? route : 'dashboard';
        const targetPath = routeToPath(targetRoute);
        const state = { route: targetRoute };

        if (replace) {
            window.history.replaceState(state, '', targetPath);
        } else {
            window.history.pushState(state, '', targetPath);
        }

        dispatchRoute(targetRoute, { source: replace ? 'replace' : 'navigation' });
    }

    function registerRoute(route, handler) {
        console.log(`register route ${route}`)
        if (!route || typeof handler !== 'function') {
            return;
        }
        routeHandlers.set(route, handler);

        if (navigationInitialised && currentRoute === route) {
            handler({ route, source: 'register' });
        }
    }

    function getCurrentRoute() {
        return currentRoute;
    }

    function initNavigation() {
        if (navigationInitialised) {
            return;
        }
        navigationInitialised = true;

        document.querySelectorAll('[data-route]').forEach(element => {
            element.addEventListener('click', event => {
                const route = element.dataset.route;
                if (!route || !routeHandlers.has(route)) {
                    return;
                }
                event.preventDefault();
                if (currentRoute === route) {
                    dispatchRoute(route, { source: 'repeat' });
                    return;
                }
                navigate(route);
            });
        });

        window.addEventListener('popstate', event => {
            const route = event.state?.route ?? pathToRoute(window.location.pathname);
            dispatchRoute(route, { source: 'popstate' });
        });

        const initialRoute = pathToRoute(window.location.pathname);
        const initialPath = routeToPath(initialRoute);
        window.history.replaceState({ route: initialRoute }, '', initialPath);
        dispatchRoute(initialRoute, { source: 'initial', replace: true });
    }

    function updateThemeToggle() {
        const toggle = document.querySelector('[data-theme-toggle]');
        if (!toggle) {
            return;
        }

        const icon = toggle.querySelector('.theme-toggle__icon');
        const label = toggle.querySelector('.theme-toggle__label');
        const nextTheme = currentTheme === THEME_DARK ? THEME_LIGHT : THEME_DARK;

        toggle.setAttribute('aria-pressed', currentTheme === THEME_DARK ? 'true' : 'false');
        toggle.setAttribute('data-theme-state', currentTheme);
        toggle.setAttribute('title', `Switch to ${nextTheme} mode`);

        if (icon) {
            icon.className = `fas ${currentTheme === THEME_DARK ? 'fa-sun' : 'fa-moon'} theme-toggle__icon`;
        }
        if (label) {
            label.textContent = currentTheme === THEME_DARK ? 'Light mode' : 'Dark mode';
        }
    }

    function applyTheme(theme, { persist = true } = {}) {
        const normalized = theme === THEME_DARK ? THEME_DARK : THEME_LIGHT;
        document.documentElement.setAttribute('data-theme', normalized);
        currentTheme = normalized;

        if (persist) {
            try {
                localStorage.setItem(THEME_STORAGE_KEY, normalized);
                storedThemePreference = normalized;
            } catch (error) {
                // localStorage unavailable; ignore
            }
        }

        updateThemeToggle();
    }

    function initTheme() {
        try {
            storedThemePreference = localStorage.getItem(THEME_STORAGE_KEY) || null;
        } catch (error) {
            storedThemePreference = null;
        }

        if (typeof window.matchMedia === 'function') {
            themeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
        }

        const initialTheme = storedThemePreference
            || (themeMediaQuery && themeMediaQuery.matches ? THEME_DARK : THEME_LIGHT);

        applyTheme(initialTheme, { persist: Boolean(storedThemePreference) });

        if (!storedThemePreference && themeMediaQuery) {
            const handleSchemeChange = event => {
                if (storedThemePreference) {
                    return;
                }
                applyTheme(event.matches ? THEME_DARK : THEME_LIGHT, { persist: false });
            };

            if (typeof themeMediaQuery.addEventListener === 'function') {
                themeMediaQuery.addEventListener('change', handleSchemeChange);
            } else if (typeof themeMediaQuery.addListener === 'function') {
                themeMediaQuery.addListener(handleSchemeChange);
            }
        }
    }

    function initThemeControls() {
        const toggle = document.querySelector('[data-theme-toggle]');
        if (!toggle) {
            return;
        }

        toggle.addEventListener('click', () => {
            const nextTheme = currentTheme === THEME_DARK ? THEME_LIGHT : THEME_DARK;
            applyTheme(nextTheme);
        });
    }

    function initSessionControls() {
        const logoutTrigger = document.querySelector('[data-logout]');
        if (!logoutTrigger) {
            return;
        }
        logoutTrigger.addEventListener('click', event => {
            event.preventDefault();
            logout();
        });
    }

    // ===== Shared Utilities (Phase 1 Refactoring) =====

    /**
     * Creates a message helper for displaying inline feedback messages
     * @param {HTMLElement} element - The container element for messages
     * @param {Object} options - Configuration options
     * @param {boolean} options.closeButton - Whether to include a close button (default: true)
     * @returns {Object} Helper object with show() and hide() methods
     */
    function createMessageHelper(element, options = {}) {
        const { closeButton = true } = options;

        return {
            show(message, type = 'info') {
                if (!element) {
                    return;
                }
                // Clear existing content
                element.innerHTML = '';
                element.className = `inline-message inline-message--${type}`;

                // Create message text
                const messageText = document.createElement('span');
                messageText.textContent = message;
                element.appendChild(messageText);

                // Create close button if enabled
                if (closeButton) {
                    const closeBtn = document.createElement('button');
                    closeBtn.type = 'button';
                    closeBtn.className = 'inline-message-close';
                    closeBtn.innerHTML = '<i class="fas fa-times"></i>';
                    closeBtn.setAttribute('aria-label', 'Close message');
                    closeBtn.addEventListener('click', () => {
                        this.hide();
                    });
                    element.appendChild(closeBtn);
                }

                element.hidden = false;
            },
            hide() {
                if (!element) {
                    return;
                }
                element.hidden = true;
                element.innerHTML = '';
            }
        };
    }

    /**
     * Formats a date string for display
     * @param {string|Date} dateString - The date to format
     * @param {string} format - Format type: 'full' (default), 'short', 'relative'
     * @returns {string} Formatted date string
     */
    function formatDate(dateString, format = 'full') {
        if (!dateString) {
            return 'Never';
        }

        const date = new Date(dateString);
        if (isNaN(date.getTime())) {
            return String(dateString);
        }

        if (format === 'short') {
            return date.toLocaleDateString(undefined, {
                year: 'numeric',
                month: 'short',
                day: 'numeric'
            });
        }

        if (format === 'relative') {
            const now = new Date();
            const diff = now - date;
            const seconds = Math.floor(diff / 1000);
            const minutes = Math.floor(seconds / 60);
            const hours = Math.floor(minutes / 60);
            const days = Math.floor(hours / 24);

            if (days > 30) {
                return date.toLocaleDateString();
            }
            if (days > 0) {
                return `${days} day${days === 1 ? '' : 's'} ago`;
            }
            if (hours > 0) {
                return `${hours} hour${hours === 1 ? '' : 's'} ago`;
            }
            if (minutes > 0) {
                return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
            }
            return 'Just now';
        }

        // Default: full format
        return date.toLocaleString();
    }

    /**
     * Normalizes API responses to a consistent array format
     * @param {*} payload - The API response payload
     * @param {Object} options - Configuration options
     * @param {boolean} options.expectArray - Whether to expect an array response (default: true)
     * @param {string} options.resultKey - Key name for result data (default: 'result')
     * @returns {Array} Normalized array of items
     */
    function normalizeApiResponse(payload, options = {}) {
        const { expectArray = true, resultKey = 'result' } = options;

        if (!payload || typeof payload !== 'object') {
            return expectArray ? [] : null;
        }

        // Already an array
        if (Array.isArray(payload)) {
            return payload;
        }

        // Check for result key
        if (resultKey in payload) {
            const result = payload[resultKey];
            if (Array.isArray(result)) {
                return result;
            }
            if (expectArray) {
                return result ? [result] : [];
            }
            return result;
        }

        // Single object response
        if (expectArray) {
            return [payload];
        }
        return payload;
    }

    /**
     * Copies text to clipboard with visual feedback
     * @param {string} text - Text to copy
     * @param {HTMLElement} button - Button element to provide visual feedback
     * @returns {Promise<void>}
     */
    function copyToClipboard(text, button) {
        return navigator.clipboard.writeText(text).then(() => {
            if (button) {
                const originalHTML = button.innerHTML;
                button.innerHTML = '<i class="fas fa-check"></i> Copied!';
                button.classList.add('btn-success');
                setTimeout(() => {
                    button.innerHTML = originalHTML;
                    button.classList.remove('btn-success');
                }, 2000);
            }
        }).catch(err => {
            console.error('Failed to copy to clipboard:', err);
            alert('Failed to copy to clipboard');
        });
    }

    // ===== Phase 2: Form and UI Helpers =====

    /**
     * Creates a reusable form toggle controller
     * @param {Object} config - Configuration object
     * @param {HTMLElement} config.button - Toggle button element
     * @param {HTMLElement} config.container - Container to show/hide
     * @param {HTMLFormElement} config.form - Form element (optional)
     * @param {Object} config.labels - Button labels { open, close }
     * @param {Function} config.onShow - Callback when showing (optional)
     * @param {Function} config.onHide - Callback when hiding (optional)
     * @returns {Object} Controller with setVisible() method
     */
    function createFormToggle(config) {
        const {
            button,
            container,
            form,
            labels = { open: 'Show', close: 'Hide' },
            onShow,
            onHide
        } = config;

        if (!button || !container) {
            console.warn('createFormToggle: button and container required');
            return { setVisible: () => {} };
        }

        const firstField = form?.querySelector('input, textarea, select');

        const updateButtonLabel = (visible) => {
            button.innerHTML = visible ? labels.close : labels.open;
            button.setAttribute('aria-expanded', String(visible));
        };

        const setVisible = (visible) => {
            container.classList.toggle('show', visible);
            updateButtonLabel(visible);

            if (visible) {
                if (typeof onShow === 'function') {
                    onShow();
                }
                firstField?.focus();
            } else {
                if (typeof onHide === 'function') {
                    onHide();
                }
                form?.reset();
            }
        };

        button.addEventListener('click', () => {
            const shouldShow = !container.classList.contains('show');
            setVisible(shouldShow);
        });

        updateButtonLabel(false);

        return { setVisible };
    }

    /**
     * Select dropdown helper utilities
     */
    const selectHelpers = {
        /**
         * Resets select to default state with placeholder
         * @param {HTMLSelectElement} select - Select element
         * @param {string} placeholder - Placeholder text
         */
        reset(select, placeholder = 'Select an option…') {
            if (!select) return;
            select.innerHTML = '';
            const option = document.createElement('option');
            option.value = '';
            option.textContent = placeholder;
            option.disabled = true;
            option.selected = true;
            select.appendChild(option);
            select.disabled = false;
        },

        /**
         * Populates select with options
         * @param {HTMLSelectElement} select - Select element
         * @param {Array} items - Array of items
         * @param {Object} config - Configuration
         * @param {string|Function} config.valueKey - Key or function to get value
         * @param {string|Function} config.labelKey - Key or function to get label
         * @param {string} config.placeholder - Placeholder text
         * @param {boolean} config.preserveValue - Keep current selection if valid
         */
        populate(select, items, config = {}) {
            if (!select) return;

            const {
                valueKey = 'value',
                labelKey = 'label',
                placeholder = 'Select an option…',
                preserveValue = true
            } = config;

            const previousValue = select.value;
            const options = Array.isArray(items) ? items : [];

            select.innerHTML = '';

            if (!options.length) {
                select.innerHTML = `<option value="">No options available</option>`;
                select.disabled = true;
                return;
            }

            // Add placeholder
            const placeholderOption = document.createElement('option');
            placeholderOption.value = '';
            placeholderOption.textContent = placeholder;
            placeholderOption.disabled = true;
            placeholderOption.selected = true;
            select.appendChild(placeholderOption);

            // Add options
            options.forEach(item => {
                const getValue = typeof valueKey === 'function' ? valueKey : (obj) => obj[valueKey];
                const getLabel = typeof labelKey === 'function' ? labelKey : (obj) => obj[labelKey];

                const value = getValue(item);
                const label = getLabel(item) || value;

                if (!value && value !== 0) return;

                const option = document.createElement('option');
                option.value = String(value);
                option.textContent = String(label);
                select.appendChild(option);
            });

            // Restore previous value if still valid
            if (preserveValue && previousValue) {
                const hasValue = Array.from(select.options).some(opt => opt.value === previousValue);
                if (hasValue) {
                    select.value = previousValue;
                } else {
                    select.value = '';
                }
            }

            select.disabled = false;
        },

        /**
         * Filters select options based on a predicate
         * @param {HTMLSelectElement} select - Select element
         * @param {Array} items - Full array of items
         * @param {Function} predicate - Filter function (item) => boolean
         * @param {Object} config - Same as populate config
         */
        filter(select, items, predicate, config = {}) {
            if (!select || typeof predicate !== 'function') return;
            const filtered = Array.isArray(items) ? items.filter(predicate) : [];
            this.populate(select, filtered, config);
        }
    };

    // ===== Phase 3: UI Component Factories =====

    /**
     * Component factory collection for building common UI elements
     */
    const components = {
        /**
         * Creates a toolbar with title and action buttons
         * @param {Object} config - Configuration object
         * @param {string} config.title - Toolbar title
         * @param {Array} config.buttons - Array of button configs { label, icon, className, attributes }
         * @param {string} config.subtitle - Optional subtitle
         * @param {string} config.className - Container class (default: 'toolbar page-section')
         * @returns {HTMLElement} Toolbar element with buttons array attached
         */
        createToolbar({ title, buttons = [], subtitle = null, className = 'toolbar page-section' }) {
            const toolbar = createElementWithAttrs('div', '', { class: className });
            const toolbarTitle = createElementWithAttrs('h2', title);
            toolbar.appendChild(toolbarTitle);

            if (subtitle) {
                const subtitleEl = createElementWithAttrs('p', subtitle, { class: 'toolbar-subtitle' });
                toolbar.appendChild(subtitleEl);
            }

            if (buttons.length > 0) {
                const toolbarActions = createElementWithAttrs('div', '', { class: 'toolbar-actions' });
                const buttonElements = [];

                buttons.forEach(btnConfig => {
                    const { label, icon, className: btnClass = 'btn primary', attributes = {} } = btnConfig;
                    const button = createElementWithAttrs('button', '', {
                        type: 'button',
                        class: btnClass,
                        ...attributes
                    });
                    button.innerHTML = icon ? `<i class="${icon}"></i> ${label}` : label;
                    toolbarActions.appendChild(button);
                    buttonElements.push(button);
                });

                toolbar.appendChild(toolbarActions);
                toolbar.buttons = buttonElements; // Attach for easy reference
            }

            return toolbar;
        },

        /**
         * Creates a table card with header, counter badge, and feedback message
         * @param {Object} config - Configuration object
         * @param {string} config.title - Table title
         * @param {Array<string>} config.columns - Column header names
         * @param {string} config.loadingMessage - Initial loading message
         * @param {string} config.dataAttribute - Data attribute for tbody
         * @param {string} config.countAttribute - Data attribute for counter badge
         * @param {string} config.feedbackAttribute - Data attribute for feedback message
         * @param {string} config.className - Container class (default: 'table-card page-section')
         * @returns {Object} Card element with refs object { element, tbody, counter, feedback }
         */
        createTableCard({
            title,
            columns,
            loadingMessage = 'Loading…',
            dataAttribute,
            countAttribute,
            feedbackAttribute,
            className = 'table-card page-section'
        }) {
            const card = createElementWithAttrs('div', '', { class: className });
            const colspan = columns.length;

            card.innerHTML = `
                <div class="table-header">
                    <h2>${title}</h2>
                    <span class="badge" ${countAttribute}>0</span>
                </div>
                <div class="inline-message" ${feedbackAttribute} hidden></div>
                <table class="data-table">
                    <thead>
                        <tr>
                            ${columns.map(col => `<th>${col}</th>`).join('')}
                        </tr>
                    </thead>
                    <tbody ${dataAttribute}>
                        <tr><td colspan="${colspan}" class="empty">${loadingMessage}</td></tr>
                    </tbody>
                </table>
            `;

            return {
                element: card,
                tbody: card.querySelector(`[${dataAttribute}]`),
                counter: card.querySelector(`[${countAttribute}]`),
                feedback: card.querySelector(`[${feedbackAttribute}]`)
            };
        },

        /**
         * Creates a form card with title and feedback message
         * @param {Object} config - Configuration object
         * @param {string} config.title - Form card title
         * @param {string} config.formHTML - Inner form HTML content
         * @param {string} config.formAttribute - Data attribute for form
         * @param {string} config.feedbackAttribute - Data attribute for feedback message
         * @param {string} config.className - Container class (default: 'form-card page-section hidden-form')
         * @returns {Object} Card element with refs { element, form, feedback }
         */
        createFormCard({
            title,
            formHTML,
            formAttribute,
            feedbackAttribute,
            className = 'form-card page-section hidden-form'
        }) {
            const card = createElementWithAttrs('div', '', { class: className });

            card.innerHTML = `
                <h3>${title}</h3>
                <form ${formAttribute}>
                    ${formHTML}
                </form>
                <div class="inline-message" ${feedbackAttribute} hidden></div>
            `;

            return {
                element: card,
                form: card.querySelector(`[${formAttribute}]`),
                feedback: card.querySelector(`[${feedbackAttribute}]`)
            };
        },

        /**
         * Creates a badge element
         * @param {Object} config - Configuration object
         * @param {string} config.text - Badge text
         * @param {string} config.variant - Badge variant (primary, danger, warning, success, info, severity-*)
         * @param {string} config.className - Additional classes
         * @param {Object} config.attributes - Additional attributes
         * @returns {HTMLElement} Badge span element
         */
        createBadge({
            text,
            variant = 'primary',
            className = '',
            attributes = {}
        }) {
            const variantClass = variant.startsWith('severity-')
                ? `severity-badge ${variant}`
                : `badge badge-${variant}`;

            return createElementWithAttrs('span', text, {
                class: `${variantClass} ${className}`.trim(),
                ...attributes
            });
        },

        /**
         * Creates an empty state component
         * @param {Object} config - Configuration object
         * @param {string} config.message - Primary message
         * @param {number} config.colspan - Column span for table context
         * @param {string} config.icon - FontAwesome icon class
         * @param {string} config.secondaryMessage - Optional secondary message
         * @param {string} config.context - 'table' or 'standalone'
         * @returns {HTMLElement|string} Empty state element or HTML string for table context
         */
        createEmptyState({
            message,
            colspan,
            icon = 'fas fa-inbox',
            secondaryMessage = null,
            context = 'table'
        }) {
            if (context === 'table') {
                const secondaryHTML = secondaryMessage
                    ? `<br><small>${secondaryMessage}</small>`
                    : '';
                return `<tr><td colspan="${colspan}" class="empty">${message}${secondaryHTML}</td></tr>`;
            }

            // Standalone empty state
            const container = createElementWithAttrs('div', '', { class: 'empty-state' });

            if (icon) {
                const iconEl = createElementWithAttrs('i', '', {
                    class: `${icon} fa-3x`,
                    style: 'color: var(--text-muted); margin-bottom: 1rem;'
                });
                container.appendChild(iconEl);
            }

            const primaryMsg = createElementWithAttrs('p', message);
            container.appendChild(primaryMsg);

            if (secondaryMessage) {
                const secondaryMsg = createElementWithAttrs('p', secondaryMessage);
                container.appendChild(secondaryMsg);
            }

            return container;
        }
    };

    // ===== End Shared Utilities =====

    const utils = {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle,
        // Phase 1 additions
        createMessageHelper,
        formatDate,
        normalizeApiResponse,
        copyToClipboard,
        // Phase 2 additions
        createFormToggle,
        selectHelpers,
        // Phase 3 additions
        components
    };

    const router = {
        registerRoute,
        navigate,
        getCurrentRoute,
        setActiveRoute,
        initNavigation
    };

    const auth = {
        getAccessToken,
        setAccessToken,
        clearAccessToken,
        refreshAccessToken,
        handleSessionExpired,
        logout,
        getUserClaims,
        getScope: getUserScope,
        getWritableTeams,
        isRoot: isRootUser,
        hasTeamPermission,
        getTeamsByPermission
    };

    window.vmaUtils = utils;
    window.vmaRouter = router;
    window.vmaAuth = auth;

    async function bootstrapAccessToken() {
        hydrateAccessTokenFromDom();
        if (getAccessToken()) {
            return true;
        }
        try {
            await refreshAccessToken();
            return Boolean(getAccessToken());
        } catch (error) {
            // refreshAccessToken already handles session expiration
            return false;
        }
    }

    async function initApp() {
        const ready = await bootstrapAccessToken();
        if (!ready) {
            return;
        }
        applyRootVisibility();
        initTheme();
        initThemeControls();
        initSessionControls();
        initNavigation();
    }

    function scheduleInit() {
        initApp().catch(error => {
            console.error('Failed to initialise VMA SPA', error);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', scheduleInit, { once: true });
    } else {
        scheduleInit();
    }
})();
