/* eslint-disable max-depth */
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
        console.warn('CVE search initialisation skipped: utilities not available.');
        return;
    }

    function safeParseJSON(value) {
        if (typeof value !== 'string') {
            return value;
        }
        const trimmed = value.trim();
        if (!trimmed) {
            return value;
        }
        try {
            return JSON.parse(trimmed);
        } catch {
            return value;
        }
    }

    function formatDate(value) {
        if (!value) {
            return '';
        }
        const timestamp = Date.parse(value);
        if (Number.isNaN(timestamp)) {
            return value;
        }
        return new Date(timestamp).toLocaleDateString(undefined, {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        });
    }

    function extractDescription(value) {
        const parsed = safeParseJSON(value);
        if (Array.isArray(parsed)) {
            const english = parsed.find(
                entry => entry && typeof entry === 'object' && /en/i.test(entry.lang || '')
            );
            const chosen = english || parsed[0];
            if (chosen && typeof chosen === 'object') {
                return chosen.value || '';
            }
            return typeof chosen === 'string' ? chosen : '';
        }
        if (parsed && typeof parsed === 'object') {
            if (Array.isArray(parsed.description)) {
                return parsed.description.map(item => item.value || item).join('\n');
            }
            if ('value' in parsed) {
                return parsed.value;
            }
        }
        if (typeof parsed === 'string') {
            return parsed;
        }
        return '';
    }

    function extractWeakness(value) {
        const parsed = safeParseJSON(value);
        const results = [];

        const addWeakness = entry => {
            if (!entry) {
                return;
            }
            if (typeof entry === 'string') {
                const cleaned = entry.trim();
                if (cleaned) {
                    results.push(cleaned);
                }
                return;
            }
            if (typeof entry === 'object') {
                const descriptions = [];
                if (Array.isArray(entry.description)) {
                    entry.description.forEach(item => {
                        if (typeof item === 'string') {
                            descriptions.push(item.trim());
                        } else if (item && typeof item === 'object' && item.value) {
                            descriptions.push(String(item.value).trim());
                        }
                    });
                } else if (entry.description) {
                    descriptions.push(String(entry.description).trim());
                }

                const name = entry.name || entry.weakness; // fallbacks
                if (descriptions.length) {
                    results.push(descriptions.filter(Boolean).join(' — '));
                } else if (name) {
                    results.push(String(name).trim());
                } else if (entry.value) {
                    results.push(String(entry.value).trim());
                }
            }
        };

        if (Array.isArray(parsed)) {
            parsed.forEach(addWeakness);
        } else if (parsed && typeof parsed === 'object') {
            if (Array.isArray(parsed.weaknesses)) {
                parsed.weaknesses.forEach(addWeakness);
            } else if (Array.isArray(parsed.description)) {
                parsed.description.forEach(addWeakness);
            } else {
                addWeakness(parsed);
            }
        } else {
            addWeakness(parsed);
        }

        return results.filter(Boolean);
    }

    function extractReferenceUrls(value) {
        const parsed = safeParseJSON(value);
        const urls = [];
        const seen = new Set();

        const pushUrl = rawUrl => {
            if (typeof rawUrl !== 'string') {
                return;
            }

            rawUrl
                .split(',')
                .map(segment => segment.trim())
                .filter(Boolean)
                .forEach(segment => {
                    if (!seen.has(segment)) {
                        seen.add(segment);
                        urls.push(segment);
                    }
                });
        };

        const collect = item => {
            if (!item) {
                return;
            }
            if (Array.isArray(item)) {
                item.forEach(collect);
                return;
            }
            if (item && typeof item === 'object') {
                pushUrl(item.url || item.href || item.uri);
                Object.values(item).forEach(collect);
                return;
            }
            pushUrl(item);
        };

        collect(parsed);
        return urls.slice(0, 10);
    }

    function severityClass(severity) {
        if (!severity || typeof severity !== 'string') {
            return '';
        }
        const level = severity.toLowerCase();
        if (level === 'critical') {
            return 'severity-critical';
        }
        if (level === 'high') {
            return 'severity-high';
        }
        if (level === 'medium') {
            return 'severity-medium';
        }
        if (level === 'low') {
            return 'severity-low';
        }
        return '';
    }

    function createMessageHelper(element) {
        const showMessage = (message, type = 'info') => {
            if (!element) {
                return;
            }
            element.textContent = message;
            element.className = `inline-message inline-message--${type}`;
            element.hidden = false;
        };

        const hideMessage = () => {
            if (!element) {
                return;
            }
            element.hidden = true;
            element.textContent = '';
        };

        return { showMessage, hideMessage };
    }

    function createField(label, iconClass, content) {
        const field = createElementWithAttrs('div', '', { class: 'cve-field' });
        const labelEl = createElementWithAttrs('span', '', { class: 'field-label' });
        if (iconClass) {
            labelEl.appendChild(createElementWithAttrs('i', '', { class: `fas ${iconClass}` }));
        }
        labelEl.appendChild(document.createTextNode(label));
        field.appendChild(labelEl);

        const appendValue = value => {
            const valueEl = createElementWithAttrs('div', '', { class: 'field-value' });
            if (value instanceof HTMLElement) {
                valueEl.appendChild(value);
            } else if (value !== undefined && value !== null && value !== '') {
                valueEl.textContent = String(value);
            } else {
                valueEl.textContent = '—';
            }
            field.appendChild(valueEl);
        };

        if (Array.isArray(content)) {
            if (!content.length) {
                appendValue('—');
            } else {
                content.forEach(item => appendValue(item));
            }
        } else {
            appendValue(content);
        }

        return field;
    }

    function renderCvssEntries(cvssData) {
        const container = document.createElement('div');
        let hasEntries = false;

        if (cvssData && typeof cvssData === 'object') {
            Object.entries(cvssData).forEach(([version, entries]) => {
                if (!Array.isArray(entries)) {
                    return;
                }

                entries.forEach(entry => {
                    hasEntries = true;
                    const row = createElementWithAttrs('div', '', { class: 'cvss-entry' });

                const severity = entry.base_severity || entry.severity;
                if (severity) {
                    row.appendChild(
                        createElementWithAttrs('span', severity, {
                            class: `severity-badge ${severityClass(severity)}`.trim()
                        })
                    );
                }

                if (entry.base_score !== undefined && entry.base_score !== null) {
                    const classes = ['severity-badge'];
                    const severityClassName = severityClass(severity);
                    if (severityClassName) {
                        classes.push(severityClassName);
                    }
                    row.appendChild(
                        createElementWithAttrs('span', `Score: ${entry.base_score}`, {
                            class: classes.filter(Boolean).join(' ')
                        })
                    );
                }

                row.appendChild(
                    createElementWithAttrs('span', `v${version}`, { class: 'badge cvss-version' })
                );

                if (entry.vector_string) {
                    row.appendChild(createElementWithAttrs('span', entry.vector_string));
                }

                    if (entry.source) {
                        row.appendChild(createElementWithAttrs('span', `Source: ${entry.source}`));
                    }

                    container.appendChild(row);
                });
            });
        }

        if (!hasEntries) {
            container.appendChild(createElementWithAttrs('span', 'No CVSS data available.'));
        }

    return container;
}

function extractConfigurationGroups(config) {
    const groups = [];

    const visitNode = node => {
        if (!node || typeof node !== 'object') {
            return;
        }

        const matches = node.cpe_match || node.cpeMatch;
        if (Array.isArray(matches) && matches.length) {
            groups.push(matches);
        }

        const nested = [];
        if (Array.isArray(node.children)) {
            nested.push(...node.children);
        }
        if (Array.isArray(node.childrenNodes)) {
            nested.push(...node.childrenNodes);
        }
        if (Array.isArray(node.nodes)) {
            nested.push(...node.nodes);
        }
        nested.forEach(visitNode);
    };

    if (!config) {
        return groups;
    }

    if (Array.isArray(config)) {
        config.forEach(visitNode);
    } else if (typeof config === 'object') {
        if (Array.isArray(config.nodes)) {
            config.nodes.forEach(visitNode);
        }
        if (Array.isArray(config.configurations)) {
            config.configurations.forEach(visitNode);
        }
    }

    return groups;
}

function renderConfigurationGroups(groups) {
    const container = createElementWithAttrs('div', '', { class: 'config-list' });

    groups.forEach((matches, groupIndex) => {
        const entry = createElementWithAttrs('div', '', { class: 'config-entry' });
        entry.appendChild(
            createElementWithAttrs('div', `Configuration ${groupIndex + 1}`, { class: 'config-entry__title' })
        );

        const matchesContainer = createElementWithAttrs('div', '', { class: 'config-entry__matches' });

        matches.forEach((match, matchIndex) => {
            const row = createElementWithAttrs('div', '', { class: 'config-match' });
            const cpeRaw = match.criteria || match.cpe23Uri || match.cpe_name;

            row.appendChild(
                createElementWithAttrs('div', cpeRaw || `CPE entry ${matchIndex + 1}`, {
                    class: 'config-match__cpe'
                })
            );

            const meta = createElementWithAttrs('div', '', { class: 'config-match__meta' });

            const vulnerable = match.vulnerable !== false;
            meta.appendChild(
                createElementWithAttrs(
                    'span',
                    vulnerable ? 'Vulnerable' : 'Not vulnerable',
                    { class: `config-chip ${vulnerable ? 'config-chip--risk' : 'config-chip--safe'}` }
                )
            );

            const versionFragments = [];
            if (match.versionStartIncluding) {
                versionFragments.push(`>= ${match.versionStartIncluding}`);
            } else if (match.versionStartExcluding) {
                versionFragments.push(`> ${match.versionStartExcluding}`);
            }

            if (match.versionEndIncluding) {
                versionFragments.push(`<= ${match.versionEndIncluding}`);
            } else if (match.versionEndExcluding) {
                versionFragments.push(`< ${match.versionEndExcluding}`);
            }

            if (!versionFragments.length) {
                versionFragments.push('All versions');
            }

            meta.appendChild(
                createElementWithAttrs('span', versionFragments.join(' · '), {
                    class: 'config-chip config-chip--muted'
                })
            );

            row.appendChild(meta);
            matchesContainer.appendChild(row);
        });

        entry.appendChild(matchesContainer);
        container.appendChild(entry);
    });

    return container;
}

    function formatConfigurations(configs) {
        if (!configs) {
            return '—';
        }

        const parsed = safeParseJSON(configs);
        const normalized = parsed ?? configs;

    const groups = extractConfigurationGroups(normalized);
    if (!groups.length && typeof normalized === 'string') {
        return normalized;
    }

    if (!groups.length) {
        const block = createElementWithAttrs('pre', '', { class: 'config-block' });
        block.textContent = JSON.stringify(normalized, null, 2);
        return block;
    }

    return renderConfigurationGroups(groups);
}

    function appendMeta(metaContainer, icon, text) {
        if (!text) {
            return;
        }
        const span = document.createElement('span');
        span.appendChild(createElementWithAttrs('i', '', { class: `fas ${icon}` }));
        span.appendChild(document.createTextNode(` ${text}`));
        metaContainer.appendChild(span);
    }

    function renderCveCard(cveId, details) {
        const card = createElementWithAttrs('article', '', { class: 'cve-card' });
        const header = createElementWithAttrs('div', '', { class: 'cve-header' });
        header.appendChild(createElementWithAttrs('div', cveId, { class: 'cve-id' }));

        const meta = createElementWithAttrs('div', '', { class: 'cve-meta' });
        appendMeta(meta, 'fa-calendar-alt', `Published ${formatDate(details.published_date)}`);
        appendMeta(meta, 'fa-clock', `Updated ${formatDate(details.last_modified)}`);
        appendMeta(meta, 'fa-building', details.source ? `Source ${details.source}` : '');
        appendMeta(meta, 'fa-clipboard-check', details.status);
        header.appendChild(meta);

        const body = createElementWithAttrs('div', '', { class: 'cve-body' });
        const description = extractDescription(details.descriptions) || 'No description available.';
        const weaknessEntries = extractWeakness(details.weakness);
        const references = extractReferenceUrls(details.references).map(url =>
            createElementWithAttrs('a', url, {
                href: url,
                target: '_blank',
                rel: 'noopener noreferrer',
                class: 'link-chip'
            })
        );

        body.appendChild(createField('CVSS Metrics', 'fa-shield-alt', renderCvssEntries(details.cvss)));
        body.appendChild(createField('Description', 'fa-align-left', description));
        body.appendChild(createField('Configurations', 'fa-diagram-project', formatConfigurations(details.configurations)));

        if (weaknessEntries && weaknessEntries.length) {
            body.appendChild(
                createField('Weakness', 'fa-bolt', weaknessEntries.map(entry => entry || '—'))
            );
        }

        body.appendChild(
            createField(
                'References',
                'fa-link',
                references.length ? references : ['No reference links available.']
            )
        );

        card.appendChild(header);
        card.appendChild(body);
        return card;
    }

    function renderSearchPage() {
        const root = document.getElementById('vmaContent');
        if (!root) {
            return null;
        }

        setActiveRoute?.('cve');
        setPageTitle?.('CVE Search');
        clearElement(root);

        const wrapper = createElementWithAttrs('section', '', { class: 'search-page' });

        const hero = createElementWithAttrs('div', '', { class: 'search-hero' });
        const heroCopy = document.createElement('div');
        heroCopy.appendChild(createElementWithAttrs('h2', 'Common Vulnerabilities and Exposures'));
        heroCopy.appendChild(
            createElementWithAttrs(
                'p',
                'Search CVE by identifier.'
            )
        );
        hero.appendChild(heroCopy);

        const searchBar = createElementWithAttrs('div', '', { class: 'search-bar' });
        const input = createElementWithAttrs('input', '', {
            type: 'text',
            id: 'searchInput',
            class: 'search-input',
            placeholder: 'Search CVEs by ID (e.g. CVE-2024-1234)',
            autocomplete: 'off'
        });
        const button = document.createElement('button');
        button.type = 'button';
        button.id = 'searchBtn';
        button.className = 'btn primary';
        button.appendChild(createElementWithAttrs('i', '', { class: 'fas fa-search' }));
        button.appendChild(document.createTextNode(' Search'));

        searchBar.appendChild(input);
        searchBar.appendChild(button);
        hero.appendChild(searchBar);

        const feedback = createElementWithAttrs('div', '', {
            class: 'inline-message',
            hidden: true,
            'data-search-feedback': ''
        });
        hero.appendChild(feedback);

        const resultsCard = createElementWithAttrs('section', '', { class: 'results-card' });
        const loadingIndicator = createElementWithAttrs('p', 'Searching…', {
            class: 'empty',
            hidden: true
        });
        const paginationControls = createElementWithAttrs('div', '', {
            id: 'paginationControls',
            class: 'pagination-controls',
            hidden: true
        });
        const noResults = createElementWithAttrs('div', '', {
            class: 'no-results',
            hidden: true
        });
        noResults.appendChild(createElementWithAttrs('i', '', { class: 'fas fa-search' }));
        noResults.appendChild(createElementWithAttrs('h3', 'No CVEs Found'));
        noResults.appendChild(
            createElementWithAttrs('p', 'Try a different identifier or adjust your search terms.')
        );
        const resultsList = createElementWithAttrs('div', '', { class: 'results-list' });

        resultsCard.appendChild(loadingIndicator);
        resultsCard.appendChild(paginationControls);
        resultsCard.appendChild(noResults);
        resultsCard.appendChild(resultsList);

        wrapper.appendChild(hero);
        wrapper.appendChild(resultsCard);
        root.appendChild(wrapper);

        return {
            input,
            button,
            feedback,
            loadingIndicator,
            noResults,
            resultsList,
            wrapper
        };
    }

    function normaliseResult(payload) {
        if (!payload || typeof payload !== 'object') {
            return [];
        }

        if (Array.isArray(payload)) {
            return payload;
        }

        if ('result' in payload && payload.result && typeof payload.result === 'object') {
            return Object.entries(payload.result).map(([cveId, details]) => ({
                id: cveId,
                ...details
            }));
        }

        return [];
    }

    function renderResults(state, items) {
        const list = state.resultsList;
        if (!list) {
            return;
        }

        list.innerHTML = '';

        if (!Array.isArray(items) || !items.length) {
            state.noResults.hidden = false;
            return;
        }

        state.noResults.hidden = true;
        items.forEach(item => {
            list.appendChild(renderCveCard(item.id, item));
        });
    }

    async function performSearch(state, helpers, rawTerm) {
        const term = rawTerm?.trim();
        if (!term) {
            helpers.feedback.showMessage('Enter a CVE identifier to search.', 'error');
            state.input?.focus();
            return;
        }

        helpers.feedback.hideMessage();
        state.loadingIndicator.hidden = false;
        state.noResults.hidden = true;
        state.resultsList.innerHTML = '';
        state.button.disabled = true;
        state.input.disabled = true;

        try {
            const payload = await fetchJSON(apiUrl(`/cve/${encodeURIComponent(term)}`));
            const items = normaliseResult(payload);
            renderResults(state, items);
            if (!items.length) {
                state.noResults.hidden = false;
            }
        } catch (error) {
            helpers.feedback.showMessage(error.message || 'Search failed.', 'error');
        } finally {
            state.loadingIndicator.hidden = true;
            state.button.disabled = false;
            state.input.disabled = false;
        }
    }

    registerRoute('cve', () => {
        const state = renderSearchPage();
        if (!state) {
            return;
        }

        const helpers = {
            feedback: createMessageHelper(state.feedback)
        };

        const triggerSearch = () => performSearch(state, helpers, state.input.value);

        state.button.addEventListener('click', triggerSearch);
        state.input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();
                triggerSearch();
            }
        });

        const initialQuery = new URL(window.location.href).searchParams.get('q');
        if (initialQuery) {
            state.input.value = initialQuery;
            performSearch(state, helpers, initialQuery);
        } else {
            state.input.focus();
            state.resultsList.innerHTML = '';
            state.noResults.hidden = true;
        }
    });
})();
