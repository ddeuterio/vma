(function () {
    const STORAGE_KEY = 'vma.sidebar.collapsed';

    const readStoredCollapsed = () => {
        try {
            return localStorage.getItem(STORAGE_KEY) === 'true';
        } catch (error) {
            console.debug('Sidebar preference read failed:', error);
            return false;
        }
    };

    const setStoredCollapsed = value => {
        try {
            localStorage.setItem(STORAGE_KEY, value ? 'true' : 'false');
        } catch (error) {
            console.debug('Sidebar preference write failed:', error);
        }
    };

    function setupSidebar() {
        const sidebar = document.getElementById('sidebar');
        const desktopToggle = document.getElementById('sidebarToggle');
        const mainContent = document.getElementById('mainContent');
        if (!sidebar || !desktopToggle || !mainContent) {
            return;
        }

        const isMobile = () => window.innerWidth <= 768;

        let mobileToggle = document.getElementById('sidebarToggleMobile');
        if (!mobileToggle) {
            mobileToggle = document.createElement('button');
            mobileToggle.type = 'button';
            mobileToggle.id = 'sidebarToggleMobile';
            mobileToggle.className = 'sidebar-toggle sidebar-toggle--floating';
            mobileToggle.setAttribute('aria-label', 'Expand navigation');
            mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
            document.body.appendChild(mobileToggle);
        }

        const toggles = [desktopToggle, mobileToggle];

        const updateToggleVisibility = () => {
            const mobileView = isMobile();
            desktopToggle.hidden = mobileView;
            mobileToggle.hidden = !mobileView;
        };

        const setSidebarState = ({ visible, expanded }) => {
            const mobileView = isMobile();
            sidebar.setAttribute('aria-hidden', (!visible).toString());
            toggles.forEach(btn => {
                if (!btn) {
                    return;
                }
                btn.setAttribute('aria-controls', 'sidebar');
                btn.setAttribute('aria-expanded', expanded.toString());
                btn.setAttribute('aria-label', expanded ? 'Collapse navigation' : 'Expand navigation');
            });

            if (mobileView) {
                sidebar.classList.toggle('open', expanded);
            }
        };

        const applyCollapsedState = collapsed => {
            sidebar.classList.toggle('collapsed', collapsed);
            mainContent.classList.toggle('collapsed', collapsed);
            setSidebarState({ visible: true, expanded: !collapsed });
        };

        const syncState = () => {
            updateToggleVisibility();
            if (isMobile()) {
                sidebar.classList.remove('collapsed');
                mainContent.classList.remove('collapsed');
                const expanded = sidebar.classList.contains('open');
                setSidebarState({ visible: expanded, expanded });
            } else {
                sidebar.classList.remove('open');
                applyCollapsedState(readStoredCollapsed());
            }
        };

        const handleToggleClick = event => {
            event.preventDefault();
            if (isMobile()) {
                const expanded = !sidebar.classList.contains('open');
                setSidebarState({ visible: expanded, expanded });
            } else {
                const nextCollapsed = !sidebar.classList.contains('collapsed');
                applyCollapsedState(nextCollapsed);
                setStoredCollapsed(nextCollapsed);
            }
        };

        toggles.forEach(btn => {
            if (!btn) {
                return;
            }
            btn.addEventListener('click', handleToggleClick);
        });

        window.addEventListener('resize', syncState);
        document.addEventListener('click', event => {
            if (!isMobile() || !sidebar.classList.contains('open')) {
                return;
            }
            if (!sidebar.contains(event.target) && !toggles.some(btn => btn && btn.contains(event.target))) {
                setSidebarState({ visible: false, expanded: false });
            }
        });
        document.addEventListener('keydown', event => {
            if (event.key === 'Escape' && sidebar.classList.contains('open')) {
                setSidebarState({ visible: false, expanded: false });
            }
        });

        syncState();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', setupSidebar);
    } else {
        setupSidebar();
    }
})();
