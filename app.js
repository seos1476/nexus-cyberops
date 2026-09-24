// ==========================================
// NEXUS // CYBEROPS
// Browser-based defensive security toolkit
// ==========================================


// ==========================================
// CLOCK
// ==========================================

function updateClock() {

    const now = new Date();

    const time =
        now.toLocaleTimeString(
            [],
            {
                hour12: false
            }
        );

    document.getElementById("clock")
        .textContent = time;

}

updateClock();

setInterval(updateClock, 1000);


// ==========================================
// PAGE NAVIGATION
// ==========================================

const pages =
    document.querySelectorAll(".page");

const navButtons =
    document.querySelectorAll(".nav-btn");

const currentPage =
    document.getElementById("current-page");


function openPage(pageName) {

    pages.forEach(page => {

        page.classList.remove("active");

    });


    navButtons.forEach(button => {

        button.classList.remove("active");

    });


    const target =
        document.getElementById(pageName);

    const button =
        document.querySelector(
            `[data-page="${pageName}"]`
        );


    if (target) {

        target.classList.add("active");

    }


    if (button) {

        button.classList.add("active");

    }


    currentPage.textContent =
        pageName.toUpperCase();

}


navButtons.forEach(button => {

    button.addEventListener(
        "click",
        () => {

            openPage(
                button.dataset.page
            );

        }
    );

});


document.querySelectorAll(
    "[data-open]"
).forEach(element => {

    element.addEventListener(
        "click",
        () => {

            openPage(
                element.dataset.open
            );

        }
    );

});


// ==========================================
// FILE FORENSICS
// ==========================================

const fileInput =
    document.getElementById("file-input");

const dropZone =
    document.getElementById("drop-zone");

const hashResults =
    document.getElementById("hash-results");


fileInput.addEventListener(
    "change",
    async event => {

        const file =
            event.target.files[0];

        if (file) {

            await analyzeFile(file);

        }

    }
);


// Drag & Drop

dropZone.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        dropZone.classList.add("dragging");

    }
);


dropZone.addEventListener(
    "dragleave",
    () => {

        dropZone.classList.remove(
            "dragging"
        );

    }
);


dropZone.addEventListener(
    "drop",
    async event => {

        event.preventDefault();

        dropZone.classList.remove(
            "dragging"
        );


        const file =
            event.dataTransfer.files[0];

        if (file) {

            await analyzeFile(file);

        }

    }
);


// ==========================================
// FILE ANALYSIS
// ==========================================

async function analyzeFile(file) {

    const buffer =
        await file.arrayBuffer();

    const bytes =
        new Uint8Array(buffer);


    document.getElementById(
        "file-name"
    ).textContent = file.name;


    document.getElementById(
        "file-size"
    ).textContent =
        formatBytes(file.size);


    document.getElementById(
        "mime-type"
    ).textContent =
        file.type || "Unknown";


    document.getElementById(
        "file-type"
    ).textContent =
        detectFileType(bytes);


    document.getElementById(
        "magic-bytes"
    ).textContent =
        getMagicBytes(bytes);


    document.getElementById(
        "entropy"
    ).textContent =
        calculateEntropy(bytes).toFixed(4);


    const algorithms = [
        "SHA-256",
        "SHA-384",
        "SHA-512"
    ];


    for (const algorithm of algorithms) {

        const hashBuffer =
            await crypto.subtle.digest(
                algorithm,
                buffer
            );


        const hashHex =
            bufferToHex(hashBuffer);


        const elementId =
            algorithm
                .toLowerCase()
                .replace("-", "");


        document.getElementById(
            elementId
        ).textContent = hashHex;

    }


    const strings =
        extractStrings(bytes);


    document.getElementById(
        "file-strings"
    ).textContent =
        strings.length > 0
            ? strings.join("\n")
            : "No printable strings found.";


    hashResults.classList.remove(
        "hidden"
    );

}


// ==========================================
// FILE TYPE DETECTION
// ==========================================

function detectFileType(bytes) {

    if (
        bytes[0] === 0x89 &&
        bytes[1] === 0x50 &&
        bytes[2] === 0x4E &&
        bytes[3] === 0x47
    ) {

        return "PNG Image";

    }


    if (
        bytes[0] === 0xFF &&
        bytes[1] === 0xD8 &&
        bytes[2] === 0xFF
    ) {

        return "JPEG Image";

    }


    if (
        bytes[0] === 0x25 &&
        bytes[1] === 0x50 &&
        bytes[2] === 0x44 &&
        bytes[3] === 0x46
    ) {

        return "PDF Document";

    }


    if (
        bytes[0] === 0x50 &&
        bytes[1] === 0x4B &&
        bytes[2] === 0x03 &&
        bytes[3] === 0x04
    ) {

        return "ZIP / Office Archive";

    }


    if (
        bytes[0] === 0x47 &&
        bytes[1] === 0x49 &&
        bytes[2] === 0x46
    ) {

        return "GIF Image";

    }


    if (
        bytes[0] === 0x7F &&
        bytes[1] === 0x45 &&
        bytes[2] === 0x4C &&
        bytes[3] === 0x46
    ) {

        return "ELF Executable";

    }


    if (
        bytes[0] === 0x4D &&
        bytes[1] === 0x5A
    ) {

        return "Windows PE Executable";

    }


    return "Unknown / Binary";

}


// ==========================================
// MAGIC BYTES
// ==========================================

function getMagicBytes(bytes) {

    const length =
        Math.min(
            bytes.length,
            16
        );


    return Array.from(
        bytes.slice(0, length)
    )
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
                    .toUpperCase()
        )
        .join(" ");

}


// ==========================================
// ENTROPY
// ==========================================

function calculateEntropy(bytes) {

    if (bytes.length === 0) {

        return 0;

    }


    const frequencies =
        new Array(256).fill(0);


    for (const byte of bytes) {

        frequencies[byte]++;

    }


    let entropy = 0;


    for (const count of frequencies) {

        if (count === 0) {

            continue;

        }


        const probability =
            count / bytes.length;


        entropy -=
            probability *
            Math.log2(
                probability
            );

    }


    return entropy;

}


// ==========================================
// PRINTABLE STRINGS
// ==========================================

function extractStrings(bytes) {

    const results = [];

    let current = "";


    for (const byte of bytes) {

        const printable =
            byte >= 32 &&
            byte <= 126;


        if (printable) {

            current +=
                String.fromCharCode(byte);

        } else {

            if (current.length >= 4) {

                results.push(current);

            }

            current = "";

        }

    }


    if (current.length >= 4) {

        results.push(current);

    }


    return results.slice(
        0,
        200
    );

}


// ==========================================
// HASH → HEX
// ==========================================

function bufferToHex(buffer) {

    return Array.from(
        new Uint8Array(buffer)
    )
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(2, "0")
        )
        .join("");

}


// ==========================================
// FILE SIZE
// ==========================================

function formatBytes(bytes) {

    if (bytes === 0) {

        return "0 Bytes";

    }


    const units = [
        "Bytes",
        "KB",
        "MB",
        "GB"
    ];


    const index =
        Math.floor(
            Math.log(bytes) /
            Math.log(1024)
        );


    return (
        parseFloat(
            (
                bytes /
                Math.pow(
                    1024,
                    index
                )
            ).toFixed(2)
        ) +
        " " +
        units[index]
    );

}


// ==========================================
// JWT INSPECTOR
// ==========================================

const jwtInput =
    document.getElementById(
        "jwt-input"
    );

const decodeJWTButton =
    document.getElementById(
        "decode-jwt"
    );

const jwtHeader =
    document.getElementById(
        "jwt-header"
    );

const jwtPayload =
    document.getElementById(
        "jwt-payload"
    );

const jwtError =
    document.getElementById(
        "jwt-error"
    );


decodeJWTButton.addEventListener(
    "click",
    decodeJWT
);


function decodeJWT() {

    const token =
        jwtInput.value.trim();


    jwtError.textContent = "";


    if (!token) {

        jwtError.textContent =
            "ERROR: TOKEN IS EMPTY";

        return;

    }


    try {

        const parts =
            token.split(".");


        if (parts.length !== 3) {

            throw new Error(
                "Invalid JWT structure"
            );

        }


        const header =
            JSON.parse(
                base64URLDecode(
                    parts[0]
                )
            );


        const payload =
            JSON.parse(
                base64URLDecode(
                    parts[1]
                )
            );


        jwtHeader.textContent =
            JSON.stringify(
                header,
                null,
                4
            );


        jwtPayload.textContent =
            JSON.stringify(
                payload,
                null,
                4
            );


    } catch (error) {

        jwtHeader.textContent =
            "—";

        jwtPayload.textContent =
            "—";

        jwtError.textContent =
            "ERROR: INVALID JWT OR INVALID JSON";

    }

}


// ==========================================
// BASE64URL DECODER
// ==========================================

function base64URLDecode(value) {

    value =
        value
            .replace(/-/g, "+")
            .replace(/_/g, "/");


    while (
        value.length % 4 !== 0
    ) {

        value += "=";

    }


    const binary =
        atob(value);


    const bytes =
        Uint8Array.from(
            binary,
            character =>
                character.charCodeAt(0)
        );


    return new TextDecoder()
        .decode(bytes);

}


// ==========================================
// STARTUP MESSAGE
// ==========================================

console.log(
    "%cNEXUS // CYBEROPS",
    "color:#7dff9a;font-size:20px;font-weight:bold;"
);

console.log(
    "Local-first defensive security toolkit."
);
