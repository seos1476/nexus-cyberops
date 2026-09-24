// ==========================================
// NEXUS CYBEROPS
// Main application logic
// ==========================================


// ---------- CLOCK ----------

function updateClock() {

    const now = new Date();

    const time = now.toLocaleTimeString();

    document.getElementById("clock").textContent = time;
}

updateClock();

setInterval(updateClock, 1000);


// ---------- PAGE NAVIGATION ----------

const navButtons =
    document.querySelectorAll(".nav-button");

const pages =
    document.querySelectorAll(".page");

const pageTitle =
    document.getElementById("page-title");


function openPage(pageName) {

    pages.forEach(page => {

        page.classList.remove("active");

    });


    const target =
        document.getElementById(pageName);

    if (target) {

        target.classList.add("active");

    }


    navButtons.forEach(button => {

        button.classList.remove("active");

        if (button.dataset.page === pageName) {

            button.classList.add("active");

        }

    });


    const titles = {

        dashboard: "Dashboard",

        hash: "Hash Analyzer",

        jwt: "JWT Inspector",

        labs: "Cyber Labs",

        about: "About"

    };


    pageTitle.textContent =
        titles[pageName] || "NEXUS";

}


navButtons.forEach(button => {

    button.addEventListener("click", () => {

        openPage(button.dataset.page);

    });

});


document
    .querySelectorAll("[data-open]")
    .forEach(button => {

        button.addEventListener("click", () => {

            openPage(button.dataset.open);

        });

    });


// ---------- HASH ANALYZER ----------

const fileInput =
    document.getElementById("file-input");

const chooseFile =
    document.getElementById("choose-file");

const dropZone =
    document.getElementById("drop-zone");

const hashResults =
    document.getElementById("hash-results");


chooseFile.addEventListener("click", () => {

    fileInput.click();

});


fileInput.addEventListener("change", event => {

    const file = event.target.files[0];

    if (file) {

        analyzeFile(file);

    }

});


dropZone.addEventListener("dragover", event => {

    event.preventDefault();

    dropZone.style.borderColor =
        "var(--accent)";

});


dropZone.addEventListener("dragleave", () => {

    dropZone.style.borderColor =
        "#394555";

});


dropZone.addEventListener("drop", event => {

    event.preventDefault();

    dropZone.style.borderColor =
        "#394555";

    const file =
        event.dataTransfer.files[0];

    if (file) {

        analyzeFile(file);

    }

});


async function analyzeFile(file) {

    const buffer =
        await file.arrayBuffer();


    const algorithms = [
        "SHA-256",
        "SHA-384",
        "SHA-512"
    ];


    document.getElementById("file-name")
        .textContent = file.name;


    document.getElementById("file-size")
        .textContent = formatBytes(file.size);


    for (const algorithm of algorithms) {

        const hashBuffer =
            await crypto.subtle.digest(
                algorithm,
                buffer
            );


        const hashHex =
            bufferToHex(hashBuffer);


        const elementId =
            algorithm.toLowerCase()
                .replace("-", "");


        document.getElementById(elementId)
            .textContent = hashHex;

    }


    hashResults.classList.remove("hidden");

}


function bufferToHex(buffer) {

    const bytes =
        new Uint8Array(buffer);

    return [...bytes]
        .map(byte =>
            byte.toString(16).padStart(2, "0")
        )
        .join("");

}


function formatBytes(bytes) {

    if (bytes === 0) return "0 Bytes";

    const units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];

    const index =
        Math.floor(
            Math.log(bytes) / Math.log(1024)
        );

    return (
        parseFloat(
            (bytes / Math.pow(1024, index))
                .toFixed(2)
        )
        + " "
        + units[index]
    );

}


// ---------- JWT INSPECTOR ----------

const decodeButton =
    document.getElementById("decode-jwt");


decodeButton.addEventListener(
    "click",
    decodeJWT
);


function decodeJWT() {

    const input =
        document.getElementById("jwt-input")
            .value
            .trim();


    const headerElement =
        document.getElementById("jwt-header");

    const payloadElement =
        document.getElementById("jwt-payload");


    headerElement.textContent = "{ }";
    payloadElement.textContent = "{ }";


    if (!input) {

        headerElement.textContent =
            "No token supplied.";

        return;

    }


    const parts =
        input.split(".");


    if (parts.length !== 3) {

        headerElement.textContent =
            "Invalid JWT format.";

        return;

    }


    try {

        const header =
            JSON.parse(
                base64UrlDecode(parts[0])
            );


        const payload =
            JSON.parse(
                base64UrlDecode(parts[1])
            );


        headerElement.textContent =
            JSON.stringify(
                header,
                null,
                2
            );


        payloadElement.textContent =
            JSON.stringify(
                payload,
                null,
                2
            );

    }

    catch (error) {

        headerElement.textContent =
            "Unable to decode token.";

        payloadElement.textContent =
            error.message;

    }

}


function base64UrlDecode(value) {

    let base64 =
        value
            .replace(/-/g, "+")
            .replace(/_/g, "/");


    while (base64.length % 4) {

        base64 += "=";

    }


    const binary =
        atob(base64);


    const bytes =
        Uint8Array.from(
            binary,
            char => char.charCodeAt(0)
        );


    return new TextDecoder()
        .decode(bytes);

}
