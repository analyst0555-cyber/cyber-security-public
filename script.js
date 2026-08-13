/* =========================================
   PASSWORD STRENGTH CHECKER
   ========================================= */

function checkPassword() {

    const input = document.getElementById("password");
    const result = document.getElementById("result");

    if (!input || !result) return;

    const password = input.value;

    if (password === "") {
        result.textContent = "⚠️ Please enter a password.";
        return;
    }

    let score = 0;

    if (password.length >= 8) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    if (score <= 2) {
        result.textContent = "🔴 Weak password";
    }
    else if (score <= 4) {
        result.textContent = "🟡 Medium password";
    }
    else {
        result.textContent = "🟢 Strong password";
    }
}


/* =========================================
   DOMAIN ANALYZER
   ========================================= */

async function analyzeDomain() {

    const input = document.getElementById("domainInput");
    const result = document.getElementById("domainResult");

    if (!input || !result) return;

    let domain = input.value.trim().toLowerCase();

    if (domain === "") {
        result.innerHTML =
            "<p>⚠️ Please enter a domain.</p>";
        return;
    }

    domain = domain.replace(/^https?:\/\//, "");
    domain = domain.split("/")[0];

    const domainPattern =
        /^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$/;

    if (!domainPattern.test(domain)) {
        result.innerHTML =
            "<p>❌ Invalid domain format.</p>";
        return;
    }

    result.innerHTML =
        "<p>🔎 Looking up DNS information...</p>";

    try {

        const recordTypes = [
            "A",
            "AAAA",
            "MX",
            "NS",
            "CNAME"
        ];

        const dnsResults = {};

        for (const type of recordTypes) {

            const response = await fetch(
                `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`
            );

            if (!response.ok) {
                throw new Error("DNS lookup failed");
            }

            const data = await response.json();

            dnsResults[type] = data.Answer || [];
        }

        let html = `
            <h3>🌍 Domain Information</h3>

            <p>
                <strong>Domain:</strong>
                ${domain}
            </p>

            <p>
                <strong>Status:</strong>
                ✅ Valid domain format
            </p>
        `;

        html += "<h3>IPv4 (A) Records</h3>";

        if (dnsResults.A.length) {
            html += "<ul>";

            dnsResults.A.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";
        }
        else {
            html += "<p>No A records found.</p>";
        }

        html += "<h3>IPv6 (AAAA) Records</h3>";

        if (dnsResults.AAAA.length) {
            html += "<ul>";

            dnsResults.AAAA.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";
        }
        else {
            html += "<p>No AAAA records found.</p>";
        }

        html += "<h3>📧 Mail (MX) Records</h3>";

        if (dnsResults.MX.length) {
            html += "<ul>";

            dnsResults.MX.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";
        }
        else {
            html += "<p>No MX records found.</p>";
        }

        html += "<h3>🗄️ Nameservers (NS)</h3>";

        if (dnsResults.NS.length) {
            html += "<ul>";

            dnsResults.NS.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";
        }
        else {
            html += "<p>No NS records found.</p>";
        }

        html += "<h3>🔗 CNAME Records</h3>";

        if (dnsResults.CNAME.length) {
            html += "<ul>";

            dnsResults.CNAME.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";
        }
        else {
            html += "<p>No CNAME records found.</p>";
        }

        html += `
            <p>
                <small>
                    DNS information retrieved using
                    DNS-over-HTTPS.
                </small>
            </p>
        `;

        result.innerHTML = html;

    }
    catch (error) {

        console.error(error);

        result.innerHTML =
            "<p>❌ Unable to retrieve DNS information.</p>";
    }
}


/* =========================================
   EMAIL SECURITY CHECKER
   ========================================= */

async function checkEmailSecurity() {

    const input = document.getElementById("emailInput");
    const result = document.getElementById("emailResult");

    if (!input || !result) return;

    const email = input.value.trim().toLowerCase();

    if (email === "") {
        result.innerHTML =
            "<p>⚠️ Please enter an email address.</p>";
        return;
    }

    const emailPattern =
        /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(email)) {
        result.innerHTML =
            "<p>❌ Invalid email format.</p>";
        return;
    }

    const parts = email.split("@");

    const domain = parts[1];

    result.innerHTML =
        "<p>🔎 Checking mail configuration...</p>";

    try {

        const response = await fetch(
            `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=MX`
        );

        if (!response.ok) {
            throw new Error("DNS request failed");
        }

        const data = await response.json();

        const mxRecords = data.Answer || [];

        let html = `
            <h3>📧 Email Analysis</h3>

            <p>
                <strong>Email:</strong>
                ${email}
            </p>

            <p>
                <strong>Domain:</strong>
                ${domain}
            </p>

            <p>
                <strong>Format:</strong>
                ✅ Valid
            </p>
        `;

        if (mxRecords.length) {

            html += `
                <h3>📬 Mail Servers</h3>

                <p>
                    ✅ This domain publishes MX records.
                </p>

                <ul>
            `;

            mxRecords.forEach(record => {
                html += `<li>${record.data}</li>`;
            });

            html += "</ul>";

        }
        else {

            html += `
                <h3>📬 Mail Servers</h3>

                <p>
                    ⚠️ No MX records were found.
                </p>
            `;
        }

        html += `
            <p>
                <small>
                    This checks public DNS mail configuration.
                    It does not verify whether the mailbox
                    itself exists.
                </small>
            </p>
        `;

        result.innerHTML = html;

    }
    catch (error) {

        console.error(error);

        result.innerHTML =
            "<p>❌ Unable to retrieve mail configuration.</p>";
    }
}


/* =========================================
   URL ANALYZER
   ========================================= */

function analyzeURL() {

    const input =
        document.getElementById("urlAnalyzerInput");

    const result =
        document.getElementById("urlAnalyzerResult");

    if (!input || !result) return;

    let value = input.value.trim();

    if (value === "") {
        result.innerHTML =
            "<p>⚠️ Please enter a URL.</p>";
        return;
    }

    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
        value = "https://" + value;
    }

    let parsedURL;

    try {
        parsedURL = new URL(value);
    }
    catch {
        result.innerHTML =
            "<p>❌ Invalid URL.</p>";
        return;
    }

    const protocol = parsedURL.protocol;
    const hostname = parsedURL.hostname;

    const port =
        parsedURL.port ||
        (
            protocol === "https:"
                ? "443"
                : protocol === "http:"
                    ? "80"
                    : "Default"
        );

    const path =
        parsedURL.pathname || "/";

    const query =
        parsedURL.search || "None";

    const fragment =
        parsedURL.hash || "None";

    const isHTTPS =
        protocol === "https:";

    const hasCredentials =
        parsedURL.username !== "" ||
        parsedURL.password !== "";

    const isIPAddress =
        /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname) ||
        hostname.includes(":");

    const isNonStandardPort =
        parsedURL.port !== "" &&
        !(
            (protocol === "https:" &&
                parsedURL.port === "443") ||
            (protocol === "http:" &&
                parsedURL.port === "80")
        );

    const longURL =
        value.length > 200;

    let observations = "";

    observations += isHTTPS
        ? "<li>✅ HTTPS is being used.</li>"
        : "<li>⚠️ URL uses HTTP instead of HTTPS.</li>";

    observations += hasCredentials
        ? "<li>⚠️ URL contains credentials.</li>"
        : "<li>✅ No URL credentials detected.</li>";

    observations += isIPAddress
        ? "<li>⚠️ Host appears to be an IP address.</li>"
        : "<li>✅ Host uses a domain name.</li>";

    observations += isNonStandardPort
        ? "<li>⚠️ Non-standard port detected.</li>"
        : "<li>✅ No unusual port detected.</li>";

    observations += longURL
        ? "<li>⚠️ URL is unusually long.</li>"
        : "<li>✅ URL length is within a normal range.</li>";

    result.innerHTML = `

        <h3>🔗 URL Analysis</h3>

        <p>
            <strong>Protocol:</strong>
            ${protocol}
        </p>

        <p>
            <strong>Hostname:</strong>
            ${hostname}
        </p>

        <p>
            <strong>Port:</strong>
            ${port}
        </p>

        <p>
            <strong>Path:</strong>
            ${path}
        </p>

        <p>
            <strong>Query:</strong>
            ${query}
        </p>

        <p>
            <strong>Fragment:</strong>
            ${fragment}
        </p>

        <h3>🛡️ Security Observations</h3>

        <ul>
            ${observations}
        </ul>

        <p>
            <small>
                These are structural observations only.
                They do not determine whether a URL is malicious.
            </small>
        </p>
    `;
}


/* =========================================
   HASH IDENTIFIER
   ========================================= */

function identifyHash() {

    const input =
        document.getElementById("hashInput");

    const result =
        document.getElementById("hashResult");

    if (!input || !result) return;

    const hash =
        input.value.trim().toLowerCase();

    if (hash === "") {
        result.innerHTML =
            "<p>⚠️ Please enter a hash.</p>";
        return;
    }

    if (!/^[a-f0-9]+$/.test(hash)) {
        result.innerHTML =
            "<p>❌ This does not appear to be a hexadecimal hash.</p>";
        return;
    }

    const length = hash.length;

    const possibleHashes = [];

    if (length === 32) possibleHashes.push("MD5");
    if (length === 40) possibleHashes.push("SHA-1");
    if (length === 56) possibleHashes.push("SHA-224");
    if (length === 64) possibleHashes.push("SHA-256");
    if (length === 96) possibleHashes.push("SHA-384");
    if (length === 128) possibleHashes.push("SHA-512");

    if (!possibleHashes.length) {

        result.innerHTML = `
            <p>
                ⚠️ No common hash format matches
                this length.
            </p>

            <p>
                Length:
                ${length} hexadecimal characters
            </p>
        `;

        return;
    }

    result.innerHTML = `
        <h3>🔢 Possible Hash Format(s)</h3>

        <p>
            <strong>Length:</strong>
            ${length} hexadecimal characters
        </p>

        <ul>
            ${possibleHashes
                .map(type => `<li>✅ ${type}</li>`)
                .join("")}
        </ul>

        <p>
            <small>
                Identification based on length and character
                pattern cannot guarantee the algorithm.
            </small>
        </p>
    `;
}


/* =========================================
   HASH GENERATOR
   ========================================= */

async function generateHash(algorithm) {

    const input =
        document.getElementById("hashTextInput");

    const result =
        document.getElementById("hashGenerateResult");

    if (!input || !result) return;

    const text = input.value;

    if (text === "") {
        result.innerHTML =
            "<p>⚠️ Enter some text first.</p>";
        return;
    }

    try {

        const encoder =
            new TextEncoder();

        const data =
            encoder.encode(text);

        const hashBuffer =
            await crypto.subtle.digest(
                algorithm,
                data
            );

        const hashArray =
            Array.from(
                new Uint8Array(hashBuffer)
            );

        const hashHex =
            hashArray
                .map(byte =>
                    byte
                        .toString(16)
                        .padStart(2, "0")
                )
                .join("");

        result.innerHTML = `
            <h3>🔐 ${algorithm}</h3>

            <p>
                <strong>Hash:</strong>
            </p>

            <pre>${hashHex}</pre>
        `;

    }
    catch (error) {

        console.error(error);

        result.innerHTML =
            "<p>❌ Unable to generate hash.</p>";
    }
}


/* =========================================
   IP INTELLIGENCE
   IPv4 + IPv6
   ========================================= */

function analyzeIP() {

    const ipInput =
        document.getElementById("ipInput");

    const cidrInput =
        document.getElementById("cidrInput");

    const result =
        document.getElementById("ipResult");

    if (!ipInput || !cidrInput || !result) return;

    const ip =
        ipInput.value.trim();

    const cidrValue =
        cidrInput.value.trim();

    if (ip === "") {
        result.innerHTML =
            "<p>⚠️ Please enter an IP address.</p>";
        return;
    }


    /* IPv6 */

    if (ip.includes(":")) {

        function isValidIPv6(address) {

            if (address.includes(".")) {
                return false;
            }

            if ((address.match(/::/g) || []).length > 1) {
                return false;
            }

            const parts =
                address.split(":");

            if (address.includes("::")) {

                const split =
                    address.split("::");

                const left =
                    split[0] === ""
                        ? []
                        : split[0].split(":");

                const right =
                    split[1] === ""
                        ? []
                        : split[1].split(":");

                if (
                    left.length +
                    right.length >= 8
                ) {
                    return false;
                }

                return left
                    .concat(right)
                    .every(part =>
                        /^[0-9a-fA-F]{1,4}$/.test(part)
                    );

            }

            if (parts.length !== 8) {
                return false;
            }

            return parts.every(part =>
                /^[0-9a-fA-F]{1,4}$/.test(part)
            );
        }


        if (!isValidIPv6(ip)) {

            result.innerHTML =
                "<p>❌ Invalid IPv6 address.</p>";

            return;
        }

        const cidr =
            cidrValue === ""
                ? 128
                : Number(cidrValue);

        if (
            !Number.isInteger(cidr) ||
            cidr < 0 ||
            cidr > 128
        ) {

            result.innerHTML =
                "<p>❌ IPv6 CIDR must be between 0 and 128.</p>";

            return;
        }

        const lowerIP =
            ip.toLowerCase();

        let classification =
            "Global / Public";

        if (lowerIP === "::1") {
            classification = "Loopback";
        }
        else if (
            lowerIP.startsWith("fe8:") ||
            lowerIP.startsWith("fe9:") ||
            lowerIP.startsWith("fea:") ||
            lowerIP.startsWith("feb:")
        ) {
            classification = "Link-local";
        }
        else if (
            lowerIP.startsWith("fc") ||
            lowerIP.startsWith("fd")
        ) {
            classification = "Unique Local Address";
        }
        else if (lowerIP.startsWith("ff")) {
            classification = "Multicast";
        }

        result.innerHTML = `

            <h3>🌐 IPv6 Analysis</h3>

            <p>
                <strong>IP Address:</strong>
                ${ip}
            </p>

            <p>
                <strong>Type:</strong>
                IPv6
            </p>

            <p>
                <strong>Classification:</strong>
                ${classification}
            </p>

            <p>
                <strong>CIDR:</strong>
                /${cidr}
            </p>

            <p>
                <strong>Address Size:</strong>
                128 bits
            </p>

            <p>
                <strong>Address Space:</strong>
                2<sup>128</sup> possible addresses
            </p>

        `;

        return;
    }


    /* IPv4 */

    const octets =
        ip.split(".");

    if (
        octets.length !== 4 ||
        octets.some(octet =>
            !/^\d+$/.test(octet) ||
            Number(octet) < 0 ||
            Number(octet) > 255
        )
    ) {

        result.innerHTML =
            "<p>❌ Invalid IPv4 address.</p>";

        return;
    }

    const numbers =
        octets.map(Number);

    const cidr =
        cidrValue === ""
            ? 32
            : Number(cidrValue);

    if (
        !Number.isInteger(cidr) ||
        cidr < 0 ||
        cidr > 32
    ) {

        result.innerHTML =
            "<p>❌ IPv4 CIDR must be between 0 and 32.</p>";

        return;
    }

    const ipNumber =
        (
            (
                (
                    numbers[0] * 256 +
                    numbers[1]
                ) * 256 +
                numbers[2]
            ) * 256 +
            numbers[3]
        ) >>> 0;

    const mask =
        cidr === 0
            ? 0
            : (0xFFFFFFFF << (32 - cidr)) >>> 0;

    const network =
        (ipNumber & mask) >>> 0;

    const broadcast =
        (network | (~mask >>> 0)) >>> 0;

    function numberToIP(number) {

        return [
            (number >>> 24) & 255,
            (number >>> 16) & 255,
            (number >>> 8) & 255,
            number & 255
        ].join(".");
    }

    const networkIP =
        numberToIP(network);

    const broadcastIP =
        numberToIP(broadcast);

    let classification =
        "Public";

    if (
        numbers[0] === 10 ||
        (
            numbers[0] === 172 &&
            numbers[1] >= 16 &&
            numbers[1] <= 31
        ) ||
        (
            numbers[0] === 192 &&
            numbers[1] === 168
        )
    ) {
        classification = "Private";
    }

    if (numbers[0] === 127) {
        classification = "Loopback";
    }

    if (
        numbers[0] === 169 &&
        numbers[1] === 254
    ) {
        classification = "Link-local";
    }

    let usableHosts;

    if (cidr <= 30) {
        usableHosts =
            Math.pow(2, 32 - cidr) - 2;
    }
    else if (cidr === 31) {
        usableHosts = 2;
    }
    else {
        usableHosts = 1;
    }

    let firstHost = networkIP;
    let lastHost = broadcastIP;

    if (cidr <= 30) {
        firstHost =
            numberToIP(network + 1);

        lastHost =
            numberToIP(broadcast - 1);
    }

    result.innerHTML = `

        <h3>🌐 IPv4 Analysis</h3>

        <p>
            <strong>IP Address:</strong>
            ${ip}
        </p>

        <p>
            <strong>Type:</strong>
            IPv4
        </p>

        <p>
            <strong>Classification:</strong>
            ${classification}
        </p>

        <p>
            <strong>CIDR:</strong>
            /${cidr}
        </p>

        <p>
            <strong>Network Address:</strong>
            ${networkIP}
        </p>

        <p>
            <strong>Broadcast Address:</strong>
            ${broadcastIP}
        </p>

        <p>
            <strong>First Usable Host:</strong>
            ${firstHost}
        </p>

        <p>
            <strong>Last Usable Host:</strong>
            ${lastHost}
        </p>

        <p>
            <strong>Usable Hosts:</strong>
            ${usableHosts}
        </p>

    `;
}


/* =========================================
   SOC LOG FILE LOADER
   ========================================= */

function loadLogFile() {

    const fileInput =
        document.getElementById("logFile");

    const logInput =
        document.getElementById("logInput");

    if (!fileInput || !logInput) return;

    const file =
        fileInput.files[0];

    if (!file) return;

    const fileName =
        file.name.toLowerCase();

    if (
        !fileName.endsWith(".log") &&
        !fileName.endsWith(".txt")
    ) {

        alert(
            "Please select a .log or .txt file."
        );

        fileInput.value = "";

        return;
    }

    const reader =
        new FileReader();

    reader.onload = function(event) {

        logInput.value =
            event.target.result;
    };

    reader.onerror = function() {

        alert(
            "Unable to read the selected file."
        );
    };

    reader.readAsText(file);
}


/* =========================================
   SOC LOG ANALYZER
   ========================================= */

function analyzeLog() {

    const input =
        document.getElementById("logInput");

    const result =
        document.getElementById("logResult");

    if (!input || !result) return;

    const log =
        input.value.trim();

    if (log === "") {

        result.innerHTML =
            "<p>⚠️ Please paste one or more log entries.</p>";

        return;
    }

    const lines =
        log
            .split(/\r?\n/)
            .map(line => line.trim())
            .filter(line => line !== "");

    let failedLogins = 0;
    let successfulLogins = 0;
    let accountLockouts = 0;

    const sourceIPs = {};
    const usernames = {};

    lines.forEach(function(line) {

        const ipMatch =
            line.match(
                /\b(?:\d{1,3}\.){3}\d{1,3}\b/
            );

        if (ipMatch) {

            const ip =
                ipMatch[0];

            sourceIPs[ip] =
                (sourceIPs[ip] || 0) + 1;
        }


        const userMatch =
            line.match(
                /(?:for|user|username)[ =]+([a-zA-Z0-9._-]+)/i
            );

        if (userMatch) {

            const username =
                userMatch[1];

            usernames[username] =
                (usernames[username] || 0) + 1;
        }


        if (
            /failed password/i.test(line) ||
            /authentication failure/i.test(line) ||
            /login failed/i.test(line) ||
            /failed login/i.test(line)
        ) {
            failedLogins++;
        }


        if (
            /accepted password/i.test(line) ||
            /authentication successful/i.test(line) ||
            /login successful/i.test(line)
        ) {
            successfulLogins++;
        }


        if (
            /account locked/i.test(line) ||
            /account lockout/i.test(line)
        ) {
            accountLockouts++;
        }

    });


    let bruteForceDetected = false;
    let suspiciousIP = "";

    for (const ip in sourceIPs) {

        if (sourceIPs[ip] >= 3) {

            bruteForceDetected = true;
            suspiciousIP = ip;

            break;
        }
    }


    let severity = "Low";

    if (accountLockouts > 0) {
        severity = "High";
    }
    else if (bruteForceDetected) {
        severity = "High";
    }
    else if (failedLogins > 0) {
        severity = "Medium";
    }


    let eventType =
        "General Authentication Activity";

    if (bruteForceDetected) {
        eventType =
            "Possible Brute-Force Activity";
    }
    else if (accountLockouts > 0) {
        eventType =
            "Account Lockout Activity";
    }
    else if (failedLogins > 0) {
        eventType =
            "Failed Authentication Activity";
    }
    else if (successfulLogins > 0) {
        eventType =
            "Successful Authentication Activity";
    }


    let ipSummary = "";

    const ipList =
        Object.keys(sourceIPs);

    if (!ipList.length) {

        ipSummary =
            "<li>No source IP addresses detected.</li>";

    }
    else {

        ipSummary =
            ipList
                .map(ip =>
                    `<li><strong>${ip}</strong> → ${sourceIPs[ip]} event(s)</li>`
                )
                .join("");
    }


    let usernameSummary = "";

    const usernameList =
        Object.keys(usernames);

    if (!usernameList.length) {

        usernameSummary =
            "<li>No usernames detected.</li>";

    }
    else {

        usernameSummary =
            usernameList
                .map(username =>
                    `<li><strong>${username}</strong> → ${usernames[username]} event(s)</li>`
                )
                .join("");
    }


    let detection =
        "No obvious repeated authentication pattern detected.";

    if (bruteForceDetected) {

        detection =
            `⚠️ Possible brute-force activity detected from ${suspiciousIP}.`;

    }
    else if (accountLockouts > 0) {

        detection =
            "⚠️ Account lockout activity detected.";

    }
    else if (failedLogins > 0) {

        detection =
            "⚠️ Failed authentication activity detected.";
    }


    result.innerHTML = `

        <h3>📊 SOC Log Analysis</h3>

        <p>
            <strong>Total Events:</strong>
            ${lines.length}
        </p>

        <p>
            <strong>Failed Logins:</strong>
            ${failedLogins}
        </p>

        <p>
            <strong>Successful Logins:</strong>
            ${successfulLogins}
        </p>

        <p>
            <strong>Account Lockouts:</strong>
            ${accountLockouts}
        </p>

        <p>
            <strong>Event Type:</strong>
            ${eventType}
        </p>

        <p>
            <strong>Severity:</strong>
            ${severity}
        </p>

        <h3>🌐 Source IP Summary</h3>

        <ul>
            ${ipSummary}
        </ul>

        <h3>👤 Username Summary</h3>

        <ul>
            ${usernameSummary}
        </ul>

        <h3>🚨 Detection</h3>

        <p>
            ${detection}
        </p>

        <p>
            <small>
                This is an automated triage aid.
                Results should be validated by a
                security analyst.
            </small>
        </p>
    `;
}   

/* =========================================
   CIDR SUBNET CALCULATOR
   ========================================= */

function calculateSubnet() {

    const ipInput = document.getElementById("subnetIP");
    const cidrInput = document.getElementById("subnetCIDR");
    const result = document.getElementById("subnetResult");

    if (!ipInput || !cidrInput || !result) {
        return;
    }

    const ip = ipInput.value.trim();
    const cidr = Number(cidrInput.value.trim());

    const octets = ip.split(".");

    if (
        octets.length !== 4 ||
        octets.some(
            octet =>
                octet === "" ||
                isNaN(octet) ||
                Number(octet) < 0 ||
                Number(octet) > 255
        )
    ) {
        result.innerHTML =
            "<p>❌ Enter a valid IPv4 address.</p>";
        return;
    }

    if (
        !Number.isInteger(cidr) ||
        cidr < 0 ||
        cidr > 32
    ) {
        result.innerHTML =
            "<p>❌ CIDR must be between 0 and 32.</p>";
        return;
    }

    const ipNumbers = octets.map(Number);

    const ipValue =
        ((ipNumbers[0] << 24) >>> 0) |
        (ipNumbers[1] << 16) |
        (ipNumbers[2] << 8) |
        ipNumbers[3];

    const mask =
        cidr === 0
            ? 0
            : (0xFFFFFFFF << (32 - cidr)) >>> 0;

    const network =
        (ipValue & mask) >>> 0;

    const broadcast =
        (network | (~mask >>> 0)) >>> 0;

    const toIP = value =>
        [
            (value >>> 24) & 255,
            (value >>> 16) & 255,
            (value >>> 8) & 255,
            value & 255
        ].join(".");

    const networkIP = toIP(network);
    const broadcastIP = toIP(broadcast);

    const totalAddresses =
        Math.pow(2, 32 - cidr);

    let usableHosts;

    if (cidr === 32) {
        usableHosts = 1;
    } else if (cidr === 31) {
        usableHosts = 2;
    } else {
        usableHosts = Math.max(
            totalAddresses - 2,
            0
        );
    }

    let firstHost = "N/A";
    let lastHost = "N/A";

    if (cidr <= 30) {
        firstHost = toIP(network + 1);
        lastHost = toIP(broadcast - 1);
    } else if (cidr === 31) {
        firstHost = networkIP;
        lastHost = broadcastIP;
    } else if (cidr === 32) {
        firstHost = networkIP;
        lastHost = networkIP;
    }

    result.innerHTML = `
        <h3>🌐 Subnet Information</h3>

        <p>
            <strong>Network:</strong>
            ${networkIP}/${cidr}
        </p>

        <p>
            <strong>Subnet Mask:</strong>
            ${toIP(mask)}
        </p>

        <p>
            <strong>Broadcast:</strong>
            ${broadcastIP}
        </p>

        <p>
            <strong>First Host:</strong>
            ${firstHost}
        </p>

        <p>
            <strong>Last Host:</strong>
            ${lastHost}
        </p>

        <p>
            <strong>Total Addresses:</strong>
            ${totalAddresses.toLocaleString()}
        </p>

        <p>
            <strong>Usable Hosts:</strong>
            ${usableHosts.toLocaleString()}
        </p>
    `;
}