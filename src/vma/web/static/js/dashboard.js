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
        console.warn('Dashboard initialisation skipped: utilities not available.');
        return;
    }

    function formatLabel(key) {
        return key
            .replace(/_/g, ' ')
            .replace(/\b\w/g, character => character.toUpperCase());
    }

    function formatValue(value) {
        if (value === null || value === undefined) {
            return '—';
        }
        if (typeof value === 'number' && Number.isFinite(value)) {
            return value.toLocaleString();
        }
        return String(value);
    }

    const iconByKey = {
        products: 'fas fa-cube card-icon',
        images: 'fas fa-layer-group card-icon',
        critical_cves: 'fas fa-exclamation-triangle card-icon',
        total_cves: 'fas fa-shield-alt card-icon'
    };

    function renderDashboard(stats) {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return;
        }

        clearElement(root);

        const section = createElementWithAttrs('section', '', { class: 'dashboard-cards' });
        const entries = Object.entries(stats || {});

        if (!entries.length) {
            section.appendChild(createElementWithAttrs('p', 'No statistics available.', { class: 'empty' }));
        } else {
            entries.forEach(([key, value]) => {
                const card = createElementWithAttrs('div', '', { class: 'card' });
                const iconClass = iconByKey[key] || 'fas fa-chart-line card-icon';

                card.appendChild(createElementWithAttrs('i', '', { class: iconClass }));
                card.appendChild(createElementWithAttrs('h3', formatLabel(key)));
                card.appendChild(createElementWithAttrs('p', formatValue(value), { class: 'card-value' }));

                section.appendChild(card);
            });
        }

        root.appendChild(section);
    }

    async function loadDashboard() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return;
        }

        setActiveRoute?.('dashboard');
        setPageTitle?.('Dashboard');

        clearElement(root);
        root.appendChild(createElementWithAttrs('p', 'Loading statistics…', { class: 'empty' }));

        try {
            const stats = await fetchJSON(apiUrl('/stats'));
            renderDashboard(stats || {});
        } catch (error) {
            clearElement(root);
            root.appendChild(
                createElementWithAttrs('p', error.message || 'Unable to load statistics.', { class: 'empty' })
            );
        }
    }

    registerRoute('dashboard', () => {
        loadDashboard();
    });
})();
