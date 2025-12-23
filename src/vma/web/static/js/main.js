(function () {
    const API_BASE = '/api/v1';
    const ROUTE_PATHS = {
        dashboard: '/',
        products: '/products',
        images: '/images',
        cve: '/cve'
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
        const response = await authFetch(url, options);

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
        currentRoute = routeHandlers.has(route) ? route : 'dashboard';
        setActiveRoute(currentRoute);
        const handler = routeHandlers.get(currentRoute);
        if (typeof handler === 'function') {
            handler({ route: currentRoute, ...meta });
        }
    }

    function navigate(route, { replace = false } = {}) {
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

    const utils = {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle
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
