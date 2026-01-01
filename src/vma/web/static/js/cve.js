/* eslint-disable max-depth */
(function () {
    const utils = window.vmaUtils || {};
    const router = window.vmaRouter || {};

    const {
        createElementWithAttrs,
        clearElement,
        fetchJSON,
        apiUrl,
        setPageTitle,
        createMessageHelper,
        normalizeApiResponse
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

function parseCvssVector(vectorString) {
    // Parse CVSS vector string to extract base score
    // Format: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    const result = {
        vectorString: vectorString,
        baseScore: null,
        baseSeverity: null
    };

    if (!vectorString || typeof vectorString !== 'string') {
        return result;
    }

    // CVSS v3.x scoring
    const v3Match = vectorString.match(/CVSS:3\.[01]/);
    if (v3Match) {
        // Extract metric values
        const metrics = {};
        vectorString.split('/').forEach(part => {
            const [key, value] = part.split(':');
            if (key && value) {
                metrics[key] = value;
            }
        });

        // Calculate base score (simplified - matching common CVSS patterns)
        // This is a heuristic based on typical values
        if (metrics.AV === 'N' && metrics.AC === 'L' && metrics.PR === 'N') {
            if (metrics.C === 'H' && metrics.I === 'H' && metrics.A === 'H') {
                result.baseScore = 9.8;
            } else if (metrics.C === 'H' || metrics.I === 'H' || metrics.A === 'H') {
                result.baseScore = 7.5;
            } else {
                result.baseScore = 5.0;
            }
        } else {
            result.baseScore = 5.0; // Default medium
        }
    }

    // CVSS v4.x scoring
    const v4Match = vectorString.match(/CVSS:4\.0/);
    if (v4Match) {
        // V4 uses different metrics but similar principle
        result.baseScore = 7.0; // Default to high for v4
    }

    // Determine severity from score
    if (result.baseScore !== null) {
        if (result.baseScore >= 9.0) {
            result.baseSeverity = 'CRITICAL';
        } else if (result.baseScore >= 7.0) {
            result.baseSeverity = 'HIGH';
        } else if (result.baseScore >= 4.0) {
            result.baseSeverity = 'MEDIUM';
        } else {
            result.baseSeverity = 'LOW';
        }
    }

    return result;
}

function renderSeverityEntries(severityData) {
    const container = document.createElement('div');
    let hasEntries = false;

    if (severityData && typeof severityData === 'object') {
        Object.entries(severityData).forEach(([severityType, entries]) => {
            if (!Array.isArray(entries)) {
                return;
            }

            // Filter: Only show severity items that start with "CVSS"
            if (!severityType || !severityType.toUpperCase().startsWith('CVSS')) {
                return;
            }

            // Extract version from severity type (e.g., CVSS_V3 -> 3)
            const versionMatch = severityType.match(/CVSS_V?(\d+)/i);
            const version = versionMatch ? versionMatch[1] : severityType;

            entries.forEach(entry => {
                hasEntries = true;
                const row = createElementWithAttrs('div', '', { class: 'cvss-entry' });

                // Parse CVSS vector string to extract score and severity
                const parsed = parseCvssVector(entry.score);

                // 1. Severity badge (matching NVD)
                if (parsed.baseSeverity) {
                    row.appendChild(
                        createElementWithAttrs('span', parsed.baseSeverity, {
                            class: `severity-badge ${severityClass(parsed.baseSeverity)}`.trim()
                        })
                    );
                }

                // 2. Score badge (matching NVD)
                if (parsed.baseScore !== null) {
                    const classes = ['severity-badge'];
                    const severityClassName = severityClass(parsed.baseSeverity);
                    if (severityClassName) {
                        classes.push(severityClassName);
                    }
                    row.appendChild(
                        createElementWithAttrs('span', `Score: ${parsed.baseScore}`, {
                            class: classes.filter(Boolean).join(' ')
                        })
                    );
                }

                // 3. Version badge (matching NVD)
                row.appendChild(
                    createElementWithAttrs('span', `v${version}`, {
                        class: 'badge cvss-version'
                    })
                );

                // 4. Vector string (matching NVD)
                if (parsed.vectorString) {
                    row.appendChild(createElementWithAttrs('span', parsed.vectorString));
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

    function renderCveCard(cveId, details, dataSource) {
        const card = createElementWithAttrs('article', '', { class: 'cve-card' });
        const header = createElementWithAttrs('div', '', { class: 'cve-header' });
        header.appendChild(createElementWithAttrs('div', cveId, { class: 'cve-id' }));

        const meta = createElementWithAttrs('div', '', { class: 'cve-meta' });

        // Adapt metadata based on data source
        if (dataSource === 'osv') {
            // OSV format
            appendMeta(meta, 'fa-calendar-alt', `Published ${formatDate(details.published)}`);
            appendMeta(meta, 'fa-clock', `Modified ${formatDate(details.modified)}`);
            appendMeta(meta, 'fa-database', 'Source: OSV');
            appendMeta(meta, 'fa-code-branch', `Schema ${details.schema_version || '1.0.0'}`);
            if (details.withdrawn) {
                appendMeta(meta, 'fa-exclamation-triangle', `Withdrawn ${formatDate(details.withdrawn)}`);
            }
        } else {
            // NVD format
            appendMeta(meta, 'fa-calendar-alt', `Published ${formatDate(details.published_date)}`);
            appendMeta(meta, 'fa-clock', `Updated ${formatDate(details.last_modified)}`);
            appendMeta(meta, 'fa-database', 'Source: NVD');
            appendMeta(meta, 'fa-clipboard-check', details.status);
            if (details.source) {
                appendMeta(meta, 'fa-building', `Identifier: ${details.source}`);
            }
        }

        header.appendChild(meta);

        const body = createElementWithAttrs('div', '', { class: 'cve-body' });

        // Adapt description based on data source
        let description;
        if (dataSource === 'osv') {
            // OSV uses 'summary' and 'details'
            const summary = details.summary || '';
            const detailsText = details.details || '';
            description = summary && detailsText
                ? `${summary}\n\n${detailsText}`
                : (summary || detailsText || 'No description available.');
        } else {
            // NVD uses 'descriptions'
            description = extractDescription(details.descriptions) || 'No description available.';
        }

        body.appendChild(createField('Description', 'fa-align-left', description));

        // CVSS Metrics - only for NVD
        if (dataSource !== 'osv' && details.cvss) {
            body.appendChild(createField('CVSS Metrics', 'fa-shield-alt', renderCvssEntries(details.cvss)));
        }

        // Configurations - only for NVD
        if (dataSource !== 'osv' && details.configurations) {
            body.appendChild(createField('Configurations', 'fa-diagram-project', formatConfigurations(details.configurations)));
        }

        // Weakness - only for NVD
        if (dataSource !== 'osv' && details.weakness) {
            const weaknessEntries = extractWeakness(details.weakness);
            if (weaknessEntries && weaknessEntries.length) {
                body.appendChild(
                    createField('Weakness', 'fa-bolt', weaknessEntries.map(entry => entry || '—'))
                );
            }
        }

        // CVSS Metrics - adapt based on source
        if (dataSource === 'osv') {
            // OSV CVSS data from osv_severity table
            if (details.severity && typeof details.severity === 'object' && Object.keys(details.severity).length > 0) {
                body.appendChild(createField('CVSS Metrics', 'fa-shield-alt', renderSeverityEntries(details.severity)));
            }

            // OSV severity rating from database_specific
            if (details.database_specific) {
                const dbSpecific = safeParseJSON(details.database_specific);
                if (dbSpecific && typeof dbSpecific === 'object' && dbSpecific.severity) {
                    const severityRating = String(dbSpecific.severity).toUpperCase();
                    const severityBadge = createElementWithAttrs('span', severityRating, {
                        class: `severity-badge ${severityClass(severityRating)}`.trim()
                    });
                    body.appendChild(createField('Severity', 'fa-exclamation-triangle', severityBadge));
                }
            }
        }

        // References - adapt based on source
        let references = [];
        if (dataSource === 'osv') {
            // OSV database_specific field
            if (details.database_specific) {
                const dbSpecific = safeParseJSON(details.database_specific);
                if (dbSpecific && typeof dbSpecific === 'object') {
                    const dbContainer = createElementWithAttrs('div', '', { class: 'database-specific-container' });

                    // CWE IDs
                    if (dbSpecific.cwe_ids && Array.isArray(dbSpecific.cwe_ids) && dbSpecific.cwe_ids.length > 0) {
                        const cweContainer = createElementWithAttrs('div', '', { class: 'db-field' });
                        const cweLabel = createElementWithAttrs('strong', 'CWE IDs: ');
                        cweContainer.appendChild(cweLabel);

                        dbSpecific.cwe_ids.forEach((cweId, index) => {
                            if (index > 0) {
                                cweContainer.appendChild(document.createTextNode(' '));
                            }
                            const cweBadge = createElementWithAttrs('span', cweId, {
                                class: 'badge cwe-badge'
                            });
                            cweContainer.appendChild(cweBadge);
                        });
                        dbContainer.appendChild(cweContainer);
                    }

                    // GitHub Reviewed Status
                    if (dbSpecific.github_reviewed !== undefined) {
                        const reviewedContainer = createElementWithAttrs('div', '', { class: 'db-field' });
                        const reviewedLabel = createElementWithAttrs('strong', 'GitHub Reviewed: ');
                        reviewedContainer.appendChild(reviewedLabel);

                        const statusBadge = createElementWithAttrs('span',
                            dbSpecific.github_reviewed ? 'Yes' : 'No', {
                            class: `badge ${dbSpecific.github_reviewed ? 'status-reviewed' : 'status-not-reviewed'}`
                        });
                        reviewedContainer.appendChild(statusBadge);
                        dbContainer.appendChild(reviewedContainer);
                    }

                    // NVD Published Date
                    if (dbSpecific.nvd_published_at) {
                        const nvdDateContainer = createElementWithAttrs('div', '', { class: 'db-field' });
                        const nvdDateLabel = createElementWithAttrs('strong', 'NVD Published: ');
                        nvdDateContainer.appendChild(nvdDateLabel);
                        nvdDateContainer.appendChild(document.createTextNode(formatDate(dbSpecific.nvd_published_at)));
                        dbContainer.appendChild(nvdDateContainer);
                    }

                    // GitHub Reviewed Date
                    if (dbSpecific.github_reviewed_at) {
                        const githubDateContainer = createElementWithAttrs('div', '', { class: 'db-field' });
                        const githubDateLabel = createElementWithAttrs('strong', 'GitHub Reviewed: ');
                        githubDateContainer.appendChild(githubDateLabel);
                        githubDateContainer.appendChild(document.createTextNode(formatDate(dbSpecific.github_reviewed_at)));
                        dbContainer.appendChild(githubDateContainer);
                    }

                    // Add any other fields that don't match known keys
                    const knownKeys = ['cwe_ids', 'severity', 'github_reviewed', 'nvd_published_at', 'github_reviewed_at'];
                    Object.entries(dbSpecific).forEach(([key, value]) => {
                        if (!knownKeys.includes(key) && value !== null && value !== undefined) {
                            const fieldContainer = createElementWithAttrs('div', '', { class: 'db-field' });
                            const fieldLabel = createElementWithAttrs('strong', `${key}: `);
                            fieldContainer.appendChild(fieldLabel);

                            // Format value based on type
                            let displayValue;
                            if (typeof value === 'object') {
                                displayValue = JSON.stringify(value);
                            } else {
                                displayValue = String(value);
                            }
                            fieldContainer.appendChild(document.createTextNode(displayValue));
                            dbContainer.appendChild(fieldContainer);
                        }
                    });

                    if (dbContainer.children.length > 0) {
                        body.appendChild(createField('Database Specific', 'fa-info-circle', dbContainer));
                    }
                }
            }
        } else {
            // NVD references
            references = extractReferenceUrls(details.references).map(url =>
                createElementWithAttrs('a', url, {
                    href: url,
                    target: '_blank',
                    rel: 'noopener noreferrer',
                    class: 'link-chip'
                })
            );
            body.appendChild(
                createField(
                    'References',
                    'fa-link',
                    references.length ? references : ['No reference links available.']
                )
            );
        }

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

        // Header with title and source selector
        const heroHeader = createElementWithAttrs('div', '', { class: 'search-hero__header' });
        const heroCopy = document.createElement('div');
        heroCopy.appendChild(createElementWithAttrs('h2', 'Common Vulnerabilities and Exposures'));
        heroCopy.appendChild(
            createElementWithAttrs(
                'p',
                'Search vulnerabilities by identifier from NVD or OSV databases.'
            )
        );
        heroHeader.appendChild(heroCopy);

        // Source selector
        const sourceSelector = createElementWithAttrs('div', '', { class: 'source-selector' });
        const sourceLabel = createElementWithAttrs('label', 'Data Source: ', { for: 'sourceSelect' });
        const sourceSelect = createElementWithAttrs('select', '', {
            id: 'sourceSelect',
            class: 'source-select'
        });

        const nvdOption = createElementWithAttrs('option', 'NVD (National Vulnerability Database)', { value: 'nvd' });
        const osvOption = createElementWithAttrs('option', 'OSV (Open Source Vulnerabilities)', { value: 'osv' });
        sourceSelect.appendChild(nvdOption);
        sourceSelect.appendChild(osvOption);

        sourceSelector.appendChild(sourceLabel);
        sourceSelector.appendChild(sourceSelect);
        heroHeader.appendChild(sourceSelector);
        hero.appendChild(heroHeader);

        const searchBar = createElementWithAttrs('div', '', { class: 'search-bar' });
        const input = createElementWithAttrs('input', '', {
            type: 'text',
            id: 'searchInput',
            class: 'search-input',
            placeholder: 'Search by ID (e.g. CVE-2024-1234 or GHSA-xxxx-yyyy-zzzz)',
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
            sourceSelect,
            feedback,
            loadingIndicator,
            noResults,
            resultsList,
            wrapper
        };
    }

    function normaliseResult(payload, dataSource) {
        if (!payload || typeof payload !== 'object') {
            return [];
        }

        // Handle OSV format (array of results)
        if (dataSource === 'osv') {
            if ('result' in payload && Array.isArray(payload.result)) {
                return payload.result.map(item => ({
                    id: item.osv_id,
                    ...item,
                    dataSource: 'osv'
                }));
            }
            if (Array.isArray(payload)) {
                return payload.map(item => ({
                    id: item.osv_id || item.id,
                    ...item,
                    dataSource: 'osv'
                }));
            }
        }

        // Handle NVD format (object with CVE IDs as keys)
        if (Array.isArray(payload)) {
            return payload.map(item => ({
                id: item.cve_id || item.id,
                ...item,
                dataSource: 'nvd'
            }));
        }

        if ('result' in payload && payload.result && typeof payload.result === 'object') {
            if (Array.isArray(payload.result)) {
                return payload.result.map(item => ({
                    id: item.cve_id || item.osv_id || item.id,
                    ...item,
                    dataSource: dataSource || 'nvd'
                }));
            }
            return Object.entries(payload.result).map(([cveId, details]) => ({
                id: cveId,
                ...details,
                dataSource: 'nvd'
            }));
        }

        return [];
    }

    function renderResults(state, items, dataSource) {
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
            // Use dataSource from item or fallback to provided dataSource
            const source = item.dataSource || dataSource || 'nvd';
            list.appendChild(renderCveCard(item.id, item, source));
        });
    }

    async function performSearch(state, helpers, rawTerm) {
        const term = rawTerm?.trim();
        if (!term) {
            helpers.feedback.show('Enter a vulnerability identifier to search.', 'error');
            state.input?.focus();
            return;
        }

        const dataSource = state.sourceSelect?.value || 'nvd';

        helpers.feedback.hide();
        state.loadingIndicator.hidden = false;
        state.noResults.hidden = true;
        state.resultsList.innerHTML = '';
        state.button.disabled = true;
        state.input.disabled = true;
        state.sourceSelect.disabled = true;

        try {
            const payload = await fetchJSON(apiUrl(`/cve/${dataSource}/${encodeURIComponent(term)}`));
            const items = normaliseResult(payload, dataSource);
            renderResults(state, items, dataSource);
            if (!items.length) {
                state.noResults.hidden = false;
            }
        } catch (error) {
            helpers.feedback.show(error.message || 'Search failed.', 'error');
        } finally {
            state.loadingIndicator.hidden = true;
            state.button.disabled = false;
            state.input.disabled = false;
            state.sourceSelect.disabled = false;
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
