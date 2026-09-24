const target = document.getElementById("target");
const auditBtn = document.getElementById("auditBtn");

const loading = document.getElementById("loading");
const errorBox = document.getElementById("error");
const results = document.getElementById("results");

const statusBox = document.getElementById("status");
const httpsBox = document.getElementById("https");
const timeBox = document.getElementById("time");
const countBox = document.getElementById("count");

const headersBox = document.getElementById("headers");
const findingsBox = document.getElementById("findings");

const securityHeaders = [
  {
    name: "strict-transport-security",
    label: "HSTS",
    recommendation:
      "Consider enabling HSTS after confirming HTTPS is correctly configured."
  },
  {
    name: "content-security-policy",
    label: "Content-Security-Policy",
    recommendation:
      "Consider deploying a suitable Content-Security-Policy."
  },
  {
    name: "x-content-type-options",
    label: "X-Content-Type-Options",
    recommendation:
      "Consider setting X-Content-Type-Options to nosniff."
  },
  {
    name: "referrer-policy",
    label: "Referrer-Policy",
    recommendation:
      "Consider configuring an appropriate Referrer-Policy."
  },
  {
    name: "permissions-policy",
    label: "Permissions-Policy",
    recommendation:
      "Consider restricting browser features that the application does not need."
  }
];

auditBtn.addEventListener("click", audit);

async function audit() {

  errorBox.classList.add("hidden");
  results.classList.add("hidden");
  loading.classList.remove("hidden");

  try {

    const url = target.value.trim();

    if (!url) {
      throw new Error("Enter an authorized HTTPS website.");
    }

    const parsed = new URL(url);

    if (!["http:", "https:"].includes(parsed.protocol)) {
      throw new Error("Only HTTP and HTTPS URLs are supported.");
    }

    const start = performance.now();

    const response = await fetch(parsed.href, {
      method: "GET",
      credentials: "omit",
      cache: "no-store"
    });

    const elapsed = Math.round(performance.now() - start);

    const headerMap = {};

    response.headers.forEach((value, key) => {
      headerMap[key.toLowerCase()] = value;
    });

    const findings = [];

    for (const item of securityHeaders) {

      const value = headerMap[item.name];

      if (!value) {

        findings.push({
          severity: item.name === "content-security-policy"
            ? "MEDIUM"
            : "LOW",

          title: `${item.label} missing`,

          description: item.recommendation
        });

      } else {

        findings.push({
          severity: "PASS",
          title: `${item.label} detected`,
          description: value
        });

      }
    }

    render(
      response,
      parsed,
      elapsed,
      headerMap,
      findings
    );

  } catch (err) {

    errorBox.textContent =
      "Browser request failed: " + err.message +
      " — the target may block cross-origin browser requests (CORS).";

    errorBox.classList.remove("hidden");

  } finally {

    loading.classList.add("hidden");

  }
}

function render(response, url, elapsed, headers, findings) {

  results.classList.remove("hidden");

  statusBox.textContent =
    `${response.status} ${response.statusText}`;

  httpsBox.textContent =
    url.protocol === "https:" ? "YES" : "NO";

  timeBox.textContent =
    `${elapsed} ms`;

  const realFindings =
    findings.filter(x => x.severity !== "PASS");

  countBox.textContent =
    realFindings.length;

  headersBox.innerHTML = "";

  Object.entries(headers)
    .sort()
    .forEach(([name, value]) => {

      const row = document.createElement("div");

      row.className = "header-row";

      row.innerHTML = `
        <span class="header-name">
          ${escapeHTML(name)}
        </span>

        <span>
          ${escapeHTML(value)}
        </span>
      `;

      headersBox.appendChild(row);
    });

  findingsBox.innerHTML = "";

  findings.forEach(item => {

    const box = document.createElement("div");

    box.className = "finding";

    box.innerHTML = `
      <div class="severity">
        ${escapeHTML(item.severity)}
      </div>

      <div class="finding-title">
        ${escapeHTML(item.title)}
      </div>

      <div class="finding-description">
        ${escapeHTML(item.description)}
      </div>
    `;

    findingsBox.appendChild(box);

  });
}

function escapeHTML(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

}
