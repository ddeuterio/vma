// Application state
let currentQuery = '';
let currentFilters = {};

// DOM elements
const searchInput = document.getElementById('searchInput');
const searchBtn = document.getElementById('searchBtn');
const resultsContainer = document.getElementById('resultsContainer');
const noResults = document.getElementById('noResults');

// Event listeners
searchBtn.addEventListener('click', () => performSearch(1));
searchInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') performSearch(1);
});

function isEmptyObject(obj) {
  return obj && Object.keys(obj).length === 0 && obj.constructor === Object;
}

function performSearch() {
    const query = searchInput.value.trim();
    if (!query) return;

    const params = {
        q: query
    };

    const queryString = new URLSearchParams(params).toString();
    const url = `http://localhost:5000/search?${queryString}`

    setTimeout(() => {
        fetch(url)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Request failed');
                }
                return response.json();
            })
            .then(data => {
                if (!isEmptyObject(data)) {
                    console.log('data received')
                    displayResults(data);
                } else {
                    console.log('nothing to print')
                    showNoResults();
                }
                
            })
            .catch(error => {
                console.error('Error:', error);
                showNoResults();
            });
    }, 800);
}

function displayResults(results) {
    resultsContainer.innerHTML = '';
    
    noResults.style.display = 'none';
    
    Object.entries(results).forEach(([key, value]) => {
        const cveCard = createCVECard(value, key);
        // cveCard.style.animationDelay = `${index * 0.1}s`;
        resultsContainer.appendChild(cveCard);
    });
}

function createCVECard(cve, idx) {
    const card = document.createElement('div');
    card.className = 'cve-card animate-in';
    
    card.innerHTML = `
        <div class="cve-header">
            <div class="d-flex justify-content-between align-items-start">
                <div>
                    <div class="cve-id">${idx}</div>
                </div>
                <div class="text-muted">
                    <small><i class="fas fa-calendar me-1"></i>Published: ${cve.published_date.split(" ")[0]}</small>
                </div>
                <div class="text-muted">
                    <small><i class="fas fa-calendar me-1"></i>Last Modified: ${cve.last_modified.split(" ")[0]}</small>
                </div>
                <div class="text-muted">
                    <small><i class="fas fa-calendar me-1"></i>Status: ${cve.status}</small>
                </div>
            </div>
        </div>
        <div class="cve-body">
            <div class="cve-field">
                <div class="field-label">Metrics</div>
                ${Object.entries(cve.cvss).map(([key, value]) => {
                    let data = ``
                    value.map((value, index) => {
                        let severityClass = `severity-${value.base_severity.toLowerCase()}`;
                        const cvssColor = getCVSSColor(value.base_score);
                        data += `
                            <div class="cvss-entry">
                                <span class="severity-badge cvss">CVSS v${key}</span>
                                <span class="severity-badge ${severityClass}">${value.base_severity}</span>
                                <span class="cvss-score" style="background: ${cvssColor};">${value.base_score}</span>
                                <span class="cvss-score" style="background: ${cvssColor};">${value.vector_string}</span>
                                <span class="severity-badge cvss">Souce ${value.source}</span>
                            </div>
                        `
                    })
                    return data
                }).join('')}
            </div>
            <div class="cve-field">
                <div class="field-label">
                    <i class="fas fa-info-circle me-2"></i>Description
                </div>
                ${(cve.descriptions).map(item => {
                    if (item.lang === 'en') {
                        return `<div class="field-value">${item.value}</div>`
                    } else {
                        return ''
                    }
                }).join('')}
            </div>
            
            <div class="cve-field">
                <div class="field-label">
                    <i class="fas fa-building me-2"></i>Vendor
                </div>
                <div class="field-value">${cve.source}</div>
            </div>

            <div class="cve-field">
                <div class="field-label">
                    <i class="fas fa-cube me-2"></i>Product
                </div>
                <div class="field-value">
                ${(cve.configurations).map(node => {
                    return node.nodes.map(item => {
                        const negate = item.negate
                        const operator = item.operator
                        let res = `Product `
                        if (negate) {
                            res += `is NOT and `
                        }

                        if (operator === "OR") {
                            res += `complies with ANY of the CPE match: <br>`
                        } else {
                            res += `complies with ALL of the CPE match: <br>`
                        }
                        
                        item.cpeMatch.map(cpe => {
                            res += `${cpe.criteria} FROM (including) ${cpe.versionStartIncluding} TO (excluding) ${cpe.versionEndExcluding} <br>`
                        })
                        return res
                    })
                }).join('')}
                </div>
            </div>

            <div class="cve-field">
                <div class="field-label">
                    <i class="fas fa-link me-2"></i>References
                </div>
                <div class="field-value">
                ${(cve.references.split(", ")).map(item =>
                    `<div class="field-value">
                        <a href="${item}" class="btn btn-outline-primary btn-sm me-2 mb-1">
                            <span>${item}</span>
                            <i class="fas fa-external-link-alt me-1"></i>
                        </a>
                    </div>`
                ).join('')}
                </div>
            </div>
        </div>
    `;
    
    return card;
}

function getCVSSColor(score) {
    if (score >= 9.0) return '#dc3545';
    if (score >= 7.0) return '#fd7e14';
    if (score >= 4.0) return '#ffc107';
    return '#28a745';
}

function showNoResults() {
    noResults.style.display = 'block';
    statsSection.style.display = 'none';
    resultsContainer.style.display = 'none';
}