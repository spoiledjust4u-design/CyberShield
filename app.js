// ==================================================
// CYBERSHIELD - DIGITAL DEFENSE APPLICATION
// ==================================================


// ==================================================
// APPLICATION DATA
// ==================================================

const HISTORY_KEY = "cyberShieldScanHistory";
const MAX_HISTORY = 100;

let scanHistory = [];
let latestScanReport = null;
let scanInProgress = false;


// ==================================================
// LOAD SAVED SCAN HISTORY
// ==================================================

function loadScanHistory() {

    try {

        const savedHistory = localStorage.getItem(HISTORY_KEY);

        if (!savedHistory) {
            scanHistory = [];
            return;
        }

        const parsedHistory = JSON.parse(savedHistory);

        if (Array.isArray(parsedHistory)) {

            scanHistory = parsedHistory
                .filter(scan =>
                    scan &&
                    typeof scan.website === "string"
                )
                .slice(0, MAX_HISTORY);

        }

    } catch (error) {

        console.error(
            "Unable to load scan history:",
            error
        );

        scanHistory = [];
    }
}


// ==================================================
// SAVE SCAN HISTORY
// ==================================================

function saveScanHistory(
    website,
    status,
    warnings,
    risk_score,
    risk_level
) {

    const scan = {

        website: website,

        status: status,

        warnings: Array.isArray(warnings)
            ? warnings
            : [],

        risk_score: risk_score,

        risk_level: risk_level,

        date: new Date().toLocaleString()

    };

    scanHistory.unshift(scan);

    scanHistory = scanHistory.slice(0, MAX_HISTORY);

    try {

        localStorage.setItem(
            HISTORY_KEY,
            JSON.stringify(scanHistory)
        );

    } catch (error) {

        console.error(
            "Unable to save scan history:",
            error
        );

        alert(
            "CyberShield could not save scan history in this browser."
        );

    }

    displayScanHistory();
}


// ==================================================
// WEBSITE SCANNER
// ==================================================

async function scanWebsite() {

    const websiteInput =
        document.getElementById("websiteInput");

    const result =
        document.getElementById("websiteResult");

    const scanButton =
        document.querySelector(
            '.tool-card button[onclick="scanWebsite()"]'
        );

    const website = websiteInput.value.trim();

    if (!website) {

        result.textContent =
            "Please enter a website address.";

        return;
    }

    if (scanInProgress) {
        return;
    }

    scanInProgress = true;

    if (scanButton) {
        scanButton.disabled = true;
        scanButton.textContent = "Scanning...";
    }

    result.textContent = "Analyzing website...";

    try {

        const response = await fetch("/scan-website", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                website: website
            })

        });

        const data = await response.json();

        if (!response.ok) {

            throw new Error(
                data.error || "Website scan failed."
            );

        }

        if (
            !Array.isArray(data.warnings) ||
            typeof data.risk_score !== "number" ||
            !["Low", "Moderate", "High"].includes(data.risk_level)
        ) {

            throw new Error(
                "The scanning engine returned an invalid response."
            );

        }

        const recommendations =
            generateRecommendations(data.warnings);

        latestScanReport = {

            website: data.website,

            status: data.status,

            risk_score: data.risk_score,

            risk_level: data.risk_level,

            warnings: data.warnings,

            recommendations: recommendations,

            date: new Date().toLocaleString()

        };

        displayWebsiteResults(data);

        saveScanHistory(
            data.website,
            data.status,
            data.warnings,
            data.risk_score,
            data.risk_level
        );

    } catch (error) {

        result.textContent =
            error.message ||
            "Unable to connect to CyberShield's Python engine.";

    } finally {

        scanInProgress = false;

        if (scanButton) {

            scanButton.disabled = false;

            scanButton.textContent = "Scan Website";

        }

    }
}


// ==================================================
// GENERATE SECURITY RECOMMENDATIONS
// ==================================================

function generateRecommendations(warnings) {

    const recommendations = [];

    const warningText = warnings.join(" ").toLowerCase();

    if (warningText.includes("https")) {

        recommendations.push(
            "Avoid entering passwords or sensitive information on websites that do not use HTTPS."
        );

    }

    if (warningText.includes("suspicious keyword")) {

        recommendations.push(
            "Verify the website's identity and domain name before entering personal information."
        );

    }

    if (warningText.includes("ip address")) {

        recommendations.push(
            "Verify that the IP address belongs to the organization claiming to operate the website."
        );

    }

    if (warningText.includes("embedded")) {

        recommendations.push(
            "Avoid URLs containing embedded usernames or passwords."
        );

    }

    if (warningText.includes("internationalized")) {

        recommendations.push(
            "Check the domain carefully for look-alike characters."
        );

    }

    if (warningText.includes("hyphens")) {

        recommendations.push(
            "Double-check unusually formatted domain names."
        );

    }

    if (warningText.includes("sequence of numbers")) {

        recommendations.push(
            "Verify domains containing unusually long number sequences."
        );

    }

    if (recommendations.length === 0) {

        recommendations.push(
            "Continue practicing safe browsing and avoid sharing sensitive information with unverified websites."
        );

    }

    return recommendations;
}


// ==================================================
// DISPLAY WEBSITE RESULTS SAFELY
// ==================================================

function displayWebsiteResults(data) {

    const result =
        document.getElementById("websiteResult");

    result.replaceChildren();

    const container =
        document.createElement("div");

    container.className = "security-results";

    const heading =
        document.createElement("h3");

    heading.textContent =
        "Website Security Assessment";

    container.appendChild(heading);


    // Status

    const status =
        document.createElement("p");

    status.textContent =
        "Status: " + data.status;

    container.appendChild(status);


    // Risk score

    const score =
        document.createElement("p");

    score.textContent =
        "Risk Score: " + data.risk_score + "/100";

    container.appendChild(score);


    // Risk level

    const level =
        document.createElement("p");

    const levelLabel =
        document.createElement("strong");

    levelLabel.textContent = "Risk Level: ";

    const badge =
        document.createElement("span");

    badge.className =
        "risk-badge " + data.risk_level.toLowerCase();

    badge.textContent = data.risk_level;

    level.appendChild(levelLabel);
    level.appendChild(badge);

    container.appendChild(level);


    // Risk meter

    const meterSection =
        document.createElement("div");

    meterSection.className =
        "risk-meter-section";

    const meterHeading =
        document.createElement("strong");

    meterHeading.textContent =
        "Overall Risk Meter";

    meterSection.appendChild(meterHeading);

    const meter =
        document.createElement("div");

    meter.className = "risk-meter";

    const fill =
        document.createElement("div");

    fill.className =
        "risk-meter-fill " + data.risk_level.toLowerCase();

    fill.style.width =
        Math.max(0, Math.min(100, data.risk_score)) + "%";

    meter.appendChild(fill);

    meterSection.appendChild(meter);

    const meterText =
        document.createElement("small");

    meterText.textContent =
        data.risk_score + "/100 Risk Score";

    meterSection.appendChild(meterText);

    container.appendChild(meterSection);


    // Security warnings

    const warningHeading =
        document.createElement("h4");

    warningHeading.textContent =
        "Security Warnings";

    container.appendChild(warningHeading);

    if (data.warnings.length > 0) {

        const warningList =
            document.createElement("ul");

        data.warnings.forEach(warning => {

            const item =
                document.createElement("li");

            item.textContent = warning;

            warningList.appendChild(item);

        });

        container.appendChild(warningList);

    } else {

        const message =
            document.createElement("p");

        message.textContent =
            "No basic URL warnings detected.";

        container.appendChild(message);

    }


    // Recommendations

    const recommendationHeading =
        document.createElement("h4");

    recommendationHeading.textContent =
        "Security Recommendations";

    container.appendChild(recommendationHeading);

    const recommendationList =
        document.createElement("ul");

    latestScanReport.recommendations.forEach(recommendation => {

        const item =
            document.createElement("li");

        item.textContent = recommendation;

        recommendationList.appendChild(item);

    });

    container.appendChild(recommendationList);


    // TXT report button

    const textButton =
        document.createElement("button");

    textButton.textContent =
        "Download TXT Report";

    textButton.type = "button";

    textButton.addEventListener(
        "click",
        downloadSecurityReport
    );

    container.appendChild(textButton);


    // PDF report button

    const pdfButton =
        document.createElement("button");

    pdfButton.textContent =
        "Download PDF Report";

    pdfButton.type = "button";

    pdfButton.addEventListener(
        "click",
        downloadPDFReport
    );

    container.appendChild(pdfButton);


    // Disclaimer

    const disclaimer =
        document.createElement("small");

    disclaimer.textContent =
        "This basic assessment does not guarantee website safety.";

    container.appendChild(disclaimer);


    result.appendChild(container);

}


// ==================================================
// DISPLAY SCAN HISTORY
// ==================================================

function displayScanHistory() {

    const historyContainer =
        document.getElementById("scanHistory");

    if (!historyContainer) return;

    historyContainer.replaceChildren();

    if (scanHistory.length === 0) {

        const message =
            document.createElement("p");

        message.textContent =
            "No scans recorded yet.";

        historyContainer.appendChild(message);

        return;
    }

    scanHistory.forEach(scan => {

        const item =
            document.createElement("div");

        item.className = "history-item";


        const status =
            document.createElement("strong");

        status.textContent =
            scan.status || "Unknown";

        item.appendChild(status);


        const website =
            document.createElement("p");

        website.textContent =
            "Website: " + scan.website;

        item.appendChild(website);


        const score =
            document.createElement("p");

        score.textContent =
            "Risk Score: " +
            (scan.risk_score ?? "N/A") + "/100";

        item.appendChild(score);


        const level =
            document.createElement("p");

        level.textContent =
            "Risk Level: " +
            (scan.risk_level || "N/A");

        item.appendChild(level);


        const date =
            document.createElement("small");

        date.textContent =
            scan.date || "Date unavailable";

        item.appendChild(date);


        const findings =
            document.createElement("p");

        findings.textContent =
            "Findings: " +
            (
                Array.isArray(scan.warnings) &&
                scan.warnings.length
                    ? scan.warnings.join(" ")
                    : "No basic URL warnings detected."
            );

        item.appendChild(findings);

        historyContainer.appendChild(item);

    });

}


// ==================================================
// CLEAR SCAN HISTORY
// ==================================================

function clearScanHistory() {

    if (scanHistory.length === 0) {

        alert("There is no scan history to clear.");

        return;
    }

    const confirmed = confirm(
        "Are you sure you want to delete all saved scan history?"
    );

    if (!confirmed) return;

    scanHistory = [];

    try {

        localStorage.removeItem(HISTORY_KEY);

    } catch (error) {

        console.error(
            "Unable to clear saved history:",
            error
        );

    }

    displayScanHistory();

}


// ==================================================
// PASSWORD SECURITY CHECKER
// ==================================================

function checkPassword() {

    const passwordInput =
        document.getElementById("passwordInput");

    const result =
        document.getElementById("passwordResult");

    const password = passwordInput.value;

    if (!password) {

        result.textContent =
            "Please enter a test password.";

        return;
    }

    let score = 0;

    if (password.length >= 12) score++;

    if (/[A-Z]/.test(password)) score++;

    if (/[a-z]/.test(password)) score++;

    if (/[0-9]/.test(password)) score++;

    if (/[^A-Za-z0-9]/.test(password)) score++;


    let strength;
    let advice;

    if (password.length < 8 || score <= 2) {

        strength = "Weak";

        advice =
            "Consider using a longer, unique passphrase.";

    } else if (score <= 3) {

        strength = "Moderate";

        advice =
            "Consider increasing password length and uniqueness.";

    } else {

        strength = "Stronger";

        advice =
            "This password meets more of the basic complexity checks. Avoid reusing it.";

    }

    result.textContent =
        "Password assessment: " +
        strength +
        ". Criteria score: " +
        score +
        "/5. " +
        advice +
        " This is a basic local assessment, not a guarantee of password security.";

    // Clear the input after assessment.

    passwordInput.value = "";

}


// ==================================================
// SCAM MESSAGE DETECTOR
// ==================================================

function scanMessage() {

    const messageInput =
        document.getElementById("messageInput");

    const result =
        document.getElementById("messageResult");

    const message =
        messageInput.value.trim();

    if (!message) {

        result.textContent =
            "Please enter a message to analyze.";

        return;
    }

    const suspiciousWords = [

        "urgent",

        "immediately",

        "locked",

        "verify your information",

        "click this link",

        "password",

        "account suspended",

        "send money",

        "gift card",

        "limited time",

        "act now",

        "claim your prize",

        "wire transfer",

        "social security number",

        "payment required"

    ];

    const lowerMessage =
        message.toLowerCase();

    const foundWords =
        suspiciousWords.filter(word =>
            lowerMessage.includes(word)
        );

    if (foundWords.length > 0) {

        result.textContent =
            "Warning: This message contains suspicious wording. " +
            "Possible red flags: " +
            foundWords.join(", ") +
            ". Do not click unexpected links or provide personal information.";

    } else {

        result.textContent =
            "No obvious suspicious wording detected. This does not guarantee the message is safe.";

    }

}


// ==================================================
// SECURITY ALERTS
// ==================================================

function showAlerts() {

    const result =
        document.getElementById("alertResult");

    const alerts = [

        "Avoid clicking suspicious links.",

        "Use unique passwords for different accounts.",

        "Enable multifactor authentication.",

        "Keep operating systems and applications updated.",

        "Never share verification codes with strangers.",

        "Check website addresses carefully.",

        "Be cautious of unexpected payment requests."

    ];

    result.textContent =
        "SECURITY REMINDERS\n\n" +
        alerts.join("\n");

}


// ==================================================
// DOWNLOAD TEXT REPORT
// ==================================================

function downloadSecurityReport() {

    if (!latestScanReport) {
        alert("Please scan a website before downloading a report.");
        return;
    }

    const warnings = Array.isArray(latestScanReport.warnings)
        ? latestScanReport.warnings
        : [];

    const recommendations = Array.isArray(latestScanReport.recommendations)
        ? latestScanReport.recommendations
        : [];

    const report = `
CYBERSHIELD
WEBSITE SECURITY ASSESSMENT REPORT

Website: ${latestScanReport.website}
Date: ${latestScanReport.date}
Status: ${latestScanReport.status}
Risk Score: ${latestScanReport.risk_score}/100
Risk Level: ${latestScanReport.risk_level}

SECURITY WARNINGS

${warnings.length ? warnings.join("\n") : "No basic URL warnings detected."}

SECURITY RECOMMENDATIONS

${recommendations.length ? recommendations.join("\n") : "No additional recommendations."}

DISCLAIMER

This basic assessment does not guarantee website safety.
It is not a substitute for a professional security audit.
`;

    const file = new Blob(
        [report],
        { type: "text/plain;charset=utf-8" }
    );

    const downloadURL = URL.createObjectURL(file);

    const link = document.createElement("a");

    link.href = downloadURL;
    link.download = "CyberShield-Security-Report.txt";
    link.style.display = "none";

    document.body.appendChild(link);
    link.click();

    setTimeout(() => {
        link.remove();
        URL.revokeObjectURL(downloadURL);
    }, 10000);

}


// ==================================================
// DOWNLOAD PDF REPORT
// ==================================================

async function downloadPDFReport() {

    if (!latestScanReport) {

        alert(
            "Please scan a website before downloading a report."
        );

        return;
    }

    try {

        const response = await fetch(
            "/download-report",
            {

                method: "POST",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify(
                    latestScanReport
                )

            }
        );

        if (!response.ok) {

            let errorMessage =
                "Unable to generate PDF report.";

            try {

                const errorData =
                    await response.json();

                if (errorData.error) {
                    errorMessage = errorData.error;
                }

            } catch (error) {
                // Keep the default error message.
            }

            throw new Error(errorMessage);

        }

        const pdfBlob =
            await response.blob();

        const downloadURL =
            URL.createObjectURL(pdfBlob);

        const link =
            document.createElement("a");

        link.href = downloadURL;

        link.download =
            "CyberShield-Security-Report.pdf";

        document.body.appendChild(link);

        link.click();

        document.body.removeChild(link);

        setTimeout(() => {
            URL.revokeObjectURL(downloadURL);
        }, 1000);

    } catch (error) {

        alert(
            "PDF download failed: " + error.message
        );

        console.error(
            "PDF report error:",
            error
        );

    }

}


// ==================================================
// APPLICATION INITIALIZATION
// ==================================================

function initializeCyberShield() {

    loadScanHistory();

    displayScanHistory();

    const securityMessage =
        document.getElementById("securityMessage");

    if (securityMessage) {

        securityMessage.textContent =
            "CyberShield is ready. Your security tools are available.";

    }

}


if (document.readyState === "loading") {

    document.addEventListener(
        "DOMContentLoaded",
        initializeCyberShield
    );

} else {

    initializeCyberShield();

}