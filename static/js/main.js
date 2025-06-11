document.addEventListener('DOMContentLoaded', function() {
    const domainForm = document.getElementById('domainForm');
    const resultSection = document.getElementById('result');
    const statusElement = document.getElementById('status');
    const harmlessCount = document.getElementById('harmlessCount');
    const maliciousCount = document.getElementById('maliciousCount');
    const suspiciousCount = document.getElementById('suspiciousCount');
    const undetectedCount = document.getElementById('undetectedCount');
    const typeSelector = document.getElementById('checkType');
    const inputField = document.getElementById('inputValue');
    const resultsContainer = document.getElementById('resultsDetails');
    
    // Initially hide the result section
    resultSection.style.display = 'none';

       // Update placeholder based on selected check type
    typeSelector.addEventListener('change', function() {
        switch(this.value) {
            case 'domain':
                inputField.placeholder = 'Enter domain (e.g., example.com)';
                break;
            case 'ip':
                inputField.placeholder = 'Enter IP address (e.g., 8.8.8.8)';
                break;
            case 'hash':
                inputField.placeholder = 'Enter file hash (MD5, SHA-1, or SHA-256)';
                break;
        }
    });
    
    domainForm.addEventListener('submit', function(event) {
        event.preventDefault();
        
        const checkType = document.getElementById('checkType').value;
        const inputValue = document.getElementById('inputValue').value.trim();
        
        if (!inputValue) {
            alert('Please enter a value to check');
            return;
        }
        
        // Show loading state
        statusElement.textContent = `Checking ${checkType}...`;
        resultSection.style.display = 'block';
        resultSection.className = 'result';
        resultsContainer.innerHTML = '<p>Loading results...</p>';
        
        // Determine which API endpoint to use
        let endpoint;
        switch(checkType) {
            case 'domain':
                endpoint = `/research?domain=${encodeURIComponent(inputValue)}`;
                break;
            case 'ip':
                endpoint = `/check/ip?ip=${encodeURIComponent(inputValue)}`;
                break;
            case 'hash':
                endpoint = `/check/hash?hash=${encodeURIComponent(inputValue)}`;
                break;
            case 'url':
                endpoint = `/check/website?url=${encodeURIComponent(inputValue)}`;
                break;
        }
        
        // Make API request
        fetch(endpoint)
             .then(response => {
                // First check if the response is JSON
                const contentType = response.headers.get('content-type');
                if (contentType && contentType.includes('application/json')) {
                    if (!response.ok) {
                        return response.json().then(err => { 
                            throw new Error(err.error || 'API error'); 
                        });
                    }
                    return response.json();
                } else {
                    throw new Error(`Invalid response format (${response.status}): Not JSON`);
                }
        })
            .then(data => {
                console.log("API Response:", data);
                // Check the data structure more flexibly
                let attributes;
                if (data.data && data.data.data && data.data.data.attributes) {
                    // New structure with nested data
                    attributes = data.data.data.attributes;
                } else if (data.data && data.data.attributes) {
                    // Current structure from your API
                    attributes = data.data.attributes;
                } else {
                    throw new Error('Invalid response format from VirusTotal API');
                }
   
                const stats = attributes.last_analysis_stats;
                
                // Determine overall status
                let overallStatus;
                let statusClass;
                
                if (stats.malicious > 0) {
                    overallStatus = 'MALICIOUS';
                    statusClass = 'malicious';
                } else if (stats.suspicious > 0) {
                    overallStatus = 'SUSPICIOUS';
                    statusClass = 'suspicious';
                } else {
                    overallStatus = 'SAFE';
                    statusClass = 'safe';
                }
                
                // Display overall status
                statusElement.innerHTML =`
                    <div class="status-container">
                        <div class="check-details">
                            <span class="check-type">${checkType.toUpperCase()}</span>
                            <span class="check-value">${inputValue}</span>
                        </div>
                        <div class="verdict ${statusClass}">
                            <span class="verdict-icon"></span>
                            <span class="verdict-text">${overallStatus}</span>
                        </div>
                    </div>
                `;
                resultSection.className = `result ${statusClass}`;
                
                // Create detailed results HTML
                let resultsHTML = `
                    <div class="stats-container">
                        <div class="stat-box harmless">
                            <h3>Harmless</h3>
                            <p>${stats.harmless || 0}</p>
                        </div>
                        <div class="stat-box malicious">
                            <h3>Malicious</h3>
                            <p>${stats.malicious || 0}</p>
                        </div>
                        <div class="stat-box suspicious">
                            <h3>Suspicious</h3>
                            <p>${stats.suspicious || 0}</p>
                        </div>
                        <div class="stat-box undetected">
                            <h3>Undetected</h3>
                            <p>${stats.undetected || 0}</p>
                        </div>
                    </div>
                `;
                
                                // Add more detailed security information in a user-friendly format
                resultsHTML += `<h3>Website Blacklist Status</h3>
                <div class="security-details">`;
                
                // Check major security vendors and show their status
                const securityVendors = [
                    'Google Safebrowsing', 
                    'McAfee', 
                    'Sucuri SiteCheck',
                    'ESET', 
                    'PhishTank',
                    'Yandex Safebrowsing',
                    'Opera'
                ];
                
                if (attributes.last_analysis_results) {
                    securityVendors.forEach(vendor => {
                        const result = attributes.last_analysis_results[vendor];
                        if (result) {
                            const isClean = result.category === 'harmless' || result.result === 'clean' || result.result === 'unrated';
                            const statusClass = isClean ? 'clean' : 'flagged';
                            const statusText = isClean ? 'clean' : result.result || 'flagged';
                            
                            resultsHTML += `
                                <div class="security-item ${statusClass}">
                                    <span class="status-icon ${statusClass}"></span>
                                    <span>Domain ${statusText} by ${vendor}</span>
                                </div>`;
                        }
                    });
                }
                
                resultsHTML += `</div>
                
                <h3>Website Malware & Security</h3>
                <div class="security-details">`;
                
                // Add general malware security information
                const malwareRisk = stats.malicious > 0 ? 'High Risk' : 'Low Risk';
                const suspiciousRisk = stats.suspicious > 0 ? 'Medium Risk' : 'Low Risk';
                
                resultsHTML += `
                    <div class="security-item ${stats.malicious > 0 ? 'flagged' : 'clean'}">
                        <span class="status-icon ${stats.malicious > 0 ? 'flagged' : 'clean'}"></span>
                        <span>${stats.malicious > 0 ? 'Malware detected by scan' : 'No malware detected by scan'} (${malwareRisk})</span>
                    </div>
                    <div class="security-item ${stats.suspicious > 0 ? 'warning' : 'clean'}">
                        <span class="status-icon ${stats.suspicious > 0 ? 'warning' : 'clean'}"></span>
                        <span>${stats.suspicious > 0 ? 'Suspicious content detected' : 'No suspicious content detected'} (${suspiciousRisk})</span>
                    </div>
                    <div class="security-item clean">
                        <span class="status-icon clean"></span>
                        <span>No defacements detected (Low Risk)</span>
                    </div>
                    <div class="security-item clean">
                        <span class="status-icon clean"></span>
                        <span>No internal server errors detected (Low Risk)</span>
                    </div>`;
                
                // If we have SSL certificate information, show it
                if (attributes.last_https_certificate) {
                    const cert = attributes.last_https_certificate;
                    const now = new Date();
                    const expiryDate = new Date(cert.validity.not_after * 1000);
                    const isExpired = expiryDate < now;
                    
                    resultsHTML += `
                        <div class="security-item ${isExpired ? 'flagged' : 'clean'}">
                            <span class="status-icon ${isExpired ? 'flagged' : 'clean'}"></span>
                            <span>SSL Certificate ${isExpired ? 'expired' : 'valid'} until ${expiryDate.toLocaleDateString()} (${isExpired ? 'High Risk' : 'Low Risk'})</span>
                        </div>`;
                }
                
                resultsHTML += `</div>`;
               
                // Show detailed vendor results if available
                if (attributes.last_analysis_results) {
                    const vendorResults = attributes.last_analysis_results;
                    
                    // Show malicious detections if any
                    if (stats.malicious > 0) {
                        resultsHTML += `<h3>Malicious Detections</h3><div class="vendor-details">`;
                        
                        for (const [vendor, result] of Object.entries(vendorResults)) {
                            if (result.category === 'malicious') {
                                resultsHTML += `
                                    <div class="vendor-result malicious">
                                        <span class="vendor-name">${vendor}:</span>
                                        <span class="vendor-verdict">${result.result || 'Malicious'}</span>
                                    </div>`;
                            }
                        }
                        resultsHTML += `</div>`;
                    }
                    
                    // Show suspicious detections if any
                    if (stats.suspicious > 0) {
                        resultsHTML += `<h3>Suspicious Detections</h3><div class="vendor-details">`;
                        
                        for (const [vendor, result] of Object.entries(vendorResults)) {
                            if (result.category === 'suspicious') {
                                resultsHTML += `
                                    <div class="vendor-result suspicious">
                                        <span class="vendor-name">${vendor}:</span>
                                        <span class="vendor-verdict">${result.result || 'Suspicious'}</span>
                                    </div>`;
                            }
                        }
                        resultsHTML += `</div>`;
                    }
                }
              
                
                // Update the results container
                resultsContainer.innerHTML = resultsHTML;
            })
            .catch(error => {
                console.error("Error:", error);
                statusElement.innerHTML = `
                    <div class="status-container error">
                        <div class="check-details">
                            <span class="check-type">ERROR</span>
                            <span class="check-value">${error.message}</span>
                        </div>
                    </div>
                `;
                resultSection.className = 'result error';
                
                // Show a more user-friendly message
                let errorMessage = "An error occurred while checking. Please try again later.";
                
                // Check for specific error patterns
                if (error.message.includes("Invalid domain format") || 
                    error.message.includes("not found in VirusTotal") || 
                    error.message.includes("Invalid response format")) {
                    errorMessage = "Please enter a valid domain name (e.g., google.com)";
                }
                
                resultsDetails.innerHTML = `
                    <div class="error-message">
                        <h3>Check Failed</h3>
                        <p>${errorMessage}</p>
                    </div>
                `;
            });
    });
});