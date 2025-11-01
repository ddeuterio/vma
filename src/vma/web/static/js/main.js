(function () {
    const API_BASE = '/api/v1';
    const ROUTE_PATHS = {
        dashboard: '/',
        products: '/products',
        images: '/images',
        cve: '/cve'
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

    async function fetchJSON(url, options = {}) {
        const response = await fetch(url, {
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
                ...(options.headers || {})
            },
            ...options
        });

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

    window.vmaUtils = utils;
    window.vmaRouter = router;

    function initApp() {
        initTheme();
        initThemeControls();
        initNavigation();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initApp);
    } else {
        initApp();
    }
})();
