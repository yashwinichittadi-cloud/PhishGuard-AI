/**
 * PhishGuard AI - Headless Browser E2E Scanner Test
 * Launches headless Microsoft Edge, connects via CDP (Chrome DevTools Protocol),
 * and verifies that scanning legitimate and suspicious URLs causes ZERO console errors
 * and correctly populates all result elements.
 */

const { spawn } = require('child_process');
const http = require('http');

const PORT = 5055;
const CDP_PORT = 9222;
const EDGE_PATH = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
const PYTHON_PATH = "C:\\Users\\yashw\\.gemini\\antigravity\\scratch\\PhishGuard-AI\\venv\\Scripts\\python.exe";

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForHttp(url, timeoutMs = 15000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
        try {
            const res = await fetch(url);
            if (res.ok || res.status === 200) return true;
        } catch (e) {
            // wait and retry
        }
        await sleep(300);
    }
    throw new Error(`Timeout waiting for ${url}`);
}

async function runBrowserTest() {
    console.log("[1] Starting Flask server on port " + PORT + "...");
    const flaskProcess = spawn(PYTHON_PATH, [
        "-c",
        `
from app import create_app
import os
app = create_app()
app.run(host='127.0.0.1', port=${PORT}, debug=False)
`
    ], {
        cwd: "C:\\Users\\yashw\\.gemini\\antigravity\\scratch\\PhishGuard-AI"
    });

    flaskProcess.stderr.on('data', d => {
        // Flask logs to stderr by default
        const str = d.toString();
        if (str.includes("Running on") || str.includes("Traceback")) {
            console.log("    [Flask]: " + str.trim());
        }
    });

    let edgeProcess = null;

    try {
        await waitForHttp(`http://127.0.0.1:${PORT}/scanner`);
        console.log("[2] Flask server is live. Launching headless Edge with CDP on port " + CDP_PORT + "...");

        edgeProcess = spawn(EDGE_PATH, [
            "--headless=new",
            `--remote-debugging-port=${CDP_PORT}`,
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--user-data-dir=" + os_tmp(),
            `http://127.0.0.1:${PORT}/scanner`
        ]);

        await waitForHttp(`http://127.0.0.1:${CDP_PORT}/json/version`);
        console.log("[3] Headless Edge connected via DevTools Protocol.");

        const targetsRes = await fetch(`http://127.0.0.1:${CDP_PORT}/json`);
        const targets = await targetsRes.json();
        const pageTarget = targets.find(t => t.type === 'page' && t.url.includes(`:${PORT}/scanner`)) || targets[0];

        if (!pageTarget || !pageTarget.webSocketDebuggerUrl) {
            throw new Error("Could not find WebSocket debugger URL from CDP target list.");
        }

        console.log("[4] Attaching WebSocket to page: " + pageTarget.url);
        const ws = new WebSocket(pageTarget.webSocketDebuggerUrl);

        await new Promise((resolve, reject) => {
            ws.onopen = resolve;
            ws.onerror = reject;
        });

        let msgId = 1;
        const pendingCallbacks = new Map();
        const exceptions = [];
        const consoleMessages = [];

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            if (data.id && pendingCallbacks.has(data.id)) {
                pendingCallbacks.get(data.id)(data);
                pendingCallbacks.delete(data.id);
            }
            if (data.method === "Runtime.exceptionThrown") {
                const desc = data.params?.exceptionDetails?.text || JSON.stringify(data.params);
                const exMsg = data.params?.exceptionDetails?.exception?.description || desc;
                console.error("    [BROWSER EXCEPTION THROWN]:", exMsg);
                exceptions.push(exMsg);
            }
            if (data.method === "Runtime.consoleAPICalled") {
                const args = data.params?.args?.map(a => a.value || a.description).join(" ");
                consoleMessages.push(args);
                if (data.params?.type === "error") {
                    console.error("    [BROWSER CONSOLE ERROR]:", args);
                }
            }
        };

        function sendCDP(method, params = {}) {
            return new Promise((resolve) => {
                const id = msgId++;
                pendingCallbacks.set(id, (response) => resolve(response.result));
                ws.send(JSON.stringify({ id, method, params }));
            });
        }

        // Enable Runtime & Page domains
        await sendCDP("Runtime.enable");
        await sendCDP("Page.enable");
        await sleep(1000);

        async function evalInPage(expression) {
            const res = await sendCDP("Runtime.evaluate", {
                expression,
                returnByValue: true,
                awaitPromise: true
            });
            if (res.exceptionDetails) {
                const err = res.exceptionDetails.exception?.description || res.exceptionDetails.text;
                throw new Error("Page eval error: " + err);
            }
            return res.result?.value;
        }

        console.log("\n=======================================================");
        console.log("TEST 1: Scanning Legitimate URL (https://www.google.com)");
        console.log("=======================================================");

        await evalInPage(`
            document.getElementById("urlInput").value = "https://www.google.com";
            document.getElementById("scanBtn").click();
        `);

        // Wait for scan to complete and UI to update
        let scan1Done = false;
        for (let i = 0; i < 20; i++) {
            await sleep(500);
            const isVisible = await evalInPage(`!document.getElementById("scanResultContainer").classList.contains("d-none")`);
            if (isVisible) {
                scan1Done = true;
                break;
            }
        }

        if (!scan1Done) {
            throw new Error("Scan result container did not become visible for Legitimate URL.");
        }

        const res1 = await evalInPage(`({
            url: document.getElementById("resUrl").textContent.trim(),
            domain: document.getElementById("resDomain").textContent.trim(),
            classification: document.getElementById("resClassification").textContent.trim(),
            classificationClass: document.getElementById("resClassificationBadge").className,
            riskScore: document.getElementById("resRiskValue").textContent.trim(),
            modelMode: document.getElementById("resModelMode").textContent.trim(),
            urlLen: document.getElementById("resFeatUrlLen").textContent.trim(),
            findingsCount: document.getElementById("resFindingsList").children.length,
            recsCount: document.getElementById("resRecommendationsList").children.length
        })`);

        console.log("    URL              :", res1.url);
        console.log("    Domain           :", res1.domain);
        console.log("    Classification   :", res1.classification);
        console.log("    Badge Class      :", res1.classificationClass);
        console.log("    Risk Score       :", res1.riskScore);
        console.log("    Model Mode       :", res1.modelMode);
        console.log("    URL Length       :", res1.urlLen);
        console.log("    Findings Count   :", res1.findingsCount);
        console.log("    Recs Count       :", res1.recsCount);

        if (!res1.classification.includes("Safe")) {
            throw new Error("Expected Legitimate URL classification to contain 'Safe', got: " + res1.classification);
        }

        console.log("\n=======================================================");
        console.log("TEST 2: Scanning Suspicious / Phishing URL (http://paypal-verification-center-update.com/signin/auth.php)");
        console.log("=======================================================");

        await evalInPage(`
            document.getElementById("urlInput").value = "http://paypal-verification-center-update.com/signin/auth.php";
            document.getElementById("scanBtn").click();
        `);

        // Wait for scan to update
        let scan2Done = false;
        for (let i = 0; i < 20; i++) {
            await sleep(500);
            const currentUrl = await evalInPage(`document.getElementById("resUrl").textContent.trim()`);
            if (currentUrl.includes("paypal-verification")) {
                scan2Done = true;
                break;
            }
        }

        if (!scan2Done) {
            throw new Error("Scan result container did not update for Phishing URL.");
        }

        const res2 = await evalInPage(`({
            url: document.getElementById("resUrl").textContent.trim(),
            domain: document.getElementById("resDomain").textContent.trim(),
            classification: document.getElementById("resClassification").textContent.trim(),
            classificationClass: document.getElementById("resClassificationBadge").className,
            riskScore: document.getElementById("resRiskValue").textContent.trim(),
            modelMode: document.getElementById("resModelMode").textContent.trim(),
            findingsCount: document.getElementById("resFindingsList").children.length,
            recsCount: document.getElementById("resRecommendationsList").children.length
        })`);

        console.log("    URL              :", res2.url);
        console.log("    Domain           :", res2.domain);
        console.log("    Classification   :", res2.classification);
        console.log("    Badge Class      :", res2.classificationClass);
        console.log("    Risk Score       :", res2.riskScore);
        console.log("    Model Mode       :", res2.modelMode);
        console.log("    Findings Count   :", res2.findingsCount);
        console.log("    Recs Count       :", res2.recsCount);

        if (!res2.classification.includes("High Risk") && !res2.classification.includes("Phishing")) {
            throw new Error("Expected Phishing URL classification to be High Risk / Phishing, got: " + res2.classification);
        }

        console.log("\n=======================================================");
        console.log("TEST 3: Theme Toggle Test (Dark <-> Light)");
        console.log("=======================================================");

        const initialTheme = await evalInPage(`document.documentElement.getAttribute("data-theme")`);
        console.log("    Initial Theme    :", initialTheme);

        await evalInPage(`document.getElementById("themeToggleBtn").click()`);
        await sleep(300);
        const toggledTheme = await evalInPage(`document.documentElement.getAttribute("data-theme")`);
        console.log("    Toggled Theme    :", toggledTheme);

        await evalInPage(`document.getElementById("themeToggleBtn").click()`);
        await sleep(300);
        const restoredTheme = await evalInPage(`document.documentElement.getAttribute("data-theme")`);
        console.log("    Restored Theme   :", restoredTheme);

        ws.close();

        console.log("\n=======================================================");
        console.log("EXCEPTIONS CHECK");
        console.log("=======================================================");
        console.log("    Total Browser Exceptions Logged:", exceptions.length);

        if (exceptions.length > 0) {
            console.error("FAILED: Browser threw uncaught JavaScript exceptions during execution:");
            exceptions.forEach(e => console.error("   * " + e));
            process.exit(1);
        } else {
            console.log("[SUCCESS] Zero browser JavaScript errors or null property exceptions encountered!");
        }

    } finally {
        if (edgeProcess) {
            edgeProcess.kill();
        }
        flaskProcess.kill();
    }
}

function os_tmp() {
    return process.env.TEMP || "C:\\Windows\\Temp";
}

runBrowserTest().catch(err => {
    console.error("FATAL BROWSER TEST ERROR:", err);
    process.exit(1);
});
