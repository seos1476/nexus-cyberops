// ==========================================
// NEXUS // CYBEROPS
// VERSION 0.3.0
// ==========================================


// ==========================================
// CLOCK
// ==========================================

function updateClock() {

    const now = new Date();

    document.getElementById("clock")
        .textContent =
        now.toLocaleTimeString(
            [],
            {
                hour12: false
            }
        );

}

updateClock();

setInterval(
    updateClock,
    1000
);


// ==========================================
// NAVIGATION
// ==========================================

const pages =
    document.querySelectorAll(".page");

const navButtons =
    document.querySelectorAll(".nav-btn");

const currentPage =
    document.getElementById("current-page");


function openPage(pageName) {

    pages.forEach(
        page =>
            page.classList.remove("active")
    );


    navButtons.forEach(
        button =>
            button.classList.remove("active")
    );


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
        () => openPage(
            button.dataset.page
        )
    );

});


document.querySelectorAll(
    "[data-open]"
).forEach(element => {

    element.addEventListener(
        "click",
        () => openPage(
            element.dataset.open
        )
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


dropZone.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        dropZone.classList.add(
            "dragging"
        );

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


async function analyzeFile(file) {

    const buffer =
        await file.arrayBuffer();

    const bytes =
        new Uint8Array(buffer);


    document.getElementById(
        "file-name"
    ).textContent =
        file.name;


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
        calculateEntropy(bytes)
            .toFixed(4);


    const algorithms = [
        "SHA-256",
        "SHA-384",
        "SHA-512"
    ];


    for (
        const algorithm
        of algorithms
    ) {

        const hashBuffer =
            await crypto.subtle.digest(
                algorithm,
                buffer
            );


        const hashHex =
            bufferToHex(
                hashBuffer
            );


        const elementId =
            algorithm
                .toLowerCase()
                .replace(
                    "-",
                    ""
                );


        document.getElementById(
            elementId
        ).textContent =
            hashHex;

    }


    const strings =
        extractStrings(bytes);


    document.getElementById(
        "file-strings"
    ).textContent =
        strings.length
            ? strings.join("\n")
            : "No printable strings found.";


    hashResults.classList.remove(
        "hidden"
    );

}


// ==========================================
// FILE TYPE
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
        bytes.slice(
            0,
            length
        )
    )
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(
                        2,
                        "0"
                    )
                    .toUpperCase()
        )
        .join(" ");

}


// ==========================================
// ENTROPY
// ==========================================

function calculateEntropy(bytes) {

    if (!bytes.length) {

        return 0;

    }


    const frequencies =
        new Array(256)
            .fill(0);


    for (
        const byte
        of bytes
    ) {

        frequencies[byte]++;

    }


    let entropy = 0;


    for (
        const count
        of frequencies
    ) {

        if (!count) {

            continue;

        }


        const probability =
            count /
            bytes.length;


        entropy -=
            probability *
            Math.log2(
                probability
            );

    }


    return entropy;

}


// ==========================================
// STRINGS
// ==========================================

function extractStrings(bytes) {

    const results = [];

    let current = "";


    for (
        const byte
        of bytes
    ) {

        if (
            byte >= 32 &&
            byte <= 126
        ) {

            current +=
                String.fromCharCode(
                    byte
                );

        } else {

            if (
                current.length >= 4
            ) {

                results.push(
                    current
                );

            }

            current = "";

        }

    }


    if (
        current.length >= 4
    ) {

        results.push(
            current
        );

    }


    return results.slice(
        0,
        200
    );

}


// ==========================================
// HASH HEX
// ==========================================

function bufferToHex(buffer) {

    return Array.from(
        new Uint8Array(buffer)
    )
        .map(
            byte =>
                byte
                    .toString(16)
                    .padStart(
                        2,
                        "0"
                    )
        )
        .join("");

}


// ==========================================
// FORMAT BYTES
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
// JWT
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


        if (
            parts.length !== 3
        ) {

            throw new Error();

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


    } catch {

        jwtHeader.textContent =
            "—";

        jwtPayload.textContent =
            "—";

        jwtError.textContent =
            "ERROR: INVALID JWT OR INVALID JSON";

    }

}


function base64URLDecode(value) {

    value =
        value
            .replace(
                /-/g,
                "+"
            )
            .replace(
                /_/g,
                "/"
            );


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
// PCAP ANALYZER
// ==========================================

const pcapInput =
    document.getElementById(
        "pcap-input"
    );

const pcapDropZone =
    document.getElementById(
        "pcap-drop-zone"
    );

const pcapResults =
    document.getElementById(
        "pcap-results"
    );

const pcapError =
    document.getElementById(
        "pcap-error"
    );


pcapInput.addEventListener(
    "change",
    async event => {

        const file =
            event.target.files[0];

        if (file) {

            await analyzePCAP(file);

        }

    }
);


pcapDropZone.addEventListener(
    "dragover",
    event => {

        event.preventDefault();

        pcapDropZone.classList.add(
            "dragging"
        );

    }
);


pcapDropZone.addEventListener(
    "dragleave",
    () => {

        pcapDropZone.classList.remove(
            "dragging"
        );

    }
);


pcapDropZone.addEventListener(
    "drop",
    async event => {

        event.preventDefault();

        pcapDropZone.classList.remove(
            "dragging"
        );


        const file =
            event.dataTransfer.files[0];


        if (file) {

            await analyzePCAP(file);

        }

    }
);


// ==========================================
// PCAP ENTRY POINT
// ==========================================

async function analyzePCAP(file) {

    pcapError.textContent = "";

    pcapResults.classList.add(
        "hidden"
    );


    try {

        const buffer =
            await file.arrayBuffer();


        const bytes =
            new Uint8Array(buffer);


        let result;


        if (
            isPCAPNG(bytes)
        ) {

            result =
                parsePCAPNG(bytes);

        } else {

            result =
                parsePCAP(bytes);

        }


        document.getElementById(
            "pcap-file-name"
        ).textContent =
            file.name;


        document.getElementById(
            "pcap-format"
        ).textContent =
            result.format;


        renderPCAPResults(
            result
        );


        pcapResults.classList.remove(
            "hidden"
        );


    } catch (error) {

        console.error(error);

        pcapError.textContent =
            "ERROR: " +
            error.message;

    }

}


// ==========================================
// DETECT PCAPNG
// ==========================================

function isPCAPNG(bytes) {

    return (
        bytes.length >= 4 &&
        bytes[0] === 0x0A &&
        bytes[1] === 0x0D &&
        bytes[2] === 0x0D &&
        bytes[3] === 0x0A
    );

}


// ==========================================
// PCAP CLASSIC PARSER
// ==========================================

function parsePCAP(bytes) {

    if (
        bytes.length < 24
    ) {

        throw new Error(
            "File is too small to be a PCAP capture."
        );

    }


    const magic =
        readU32LE(
            bytes,
            0
        );


    let littleEndian = true;


    if (
        magic === 0xa1b2c3d4
    ) {

        littleEndian = true;

    } else if (
        magic === 0xd4c3b2a1
    ) {

        littleEndian = false;

    } else if (
        magic === 0xa1b23c4d
    ) {

        littleEndian = true;

    } else if (
        magic === 0x4d3cb2a1
    ) {

        littleEndian = false;

    } else {

        throw new Error(
            "Unsupported PCAP file format."
        );

    }


    const read32 =
        littleEndian
            ? readU32LE
            : readU32BE;


    const linkType =
        read32(
            bytes,
            20
        );


    const packets = [];

    let offset = 24;


    while (
        offset + 16 <= bytes.length
    ) {

        const tsSec =
            read32(
                bytes,
                offset
            );


        const tsFraction =
            read32(
                bytes,
                offset + 4
            );


        const capturedLength =
            read32(
                bytes,
                offset + 8
            );


        const originalLength =
            read32(
                bytes,
                offset + 12
            );


        offset += 16;


        if (
            offset +
            capturedLength >
            bytes.length
        ) {

            break;

        }


        const packet =
            bytes.slice(
                offset,
                offset +
                capturedLength
            );


        const parsed =
            parsePacket(
                packet,
                linkType
            );


        parsed.number =
            packets.length + 1;

        parsed.timestamp =
            tsSec +
            tsFraction / 1000000;

        parsed.length =
            originalLength;

        parsed.capturedLength =
            capturedLength;


        packets.push(
            parsed
        );


        offset += capturedLength;

    }


    return {

        format: "PCAP",

        packets

    };

}


// ==========================================
// PCAPNG PARSER
// ==========================================

function parsePCAPNG(bytes) {

    const packets = [];

    const interfaces = [];

    let offset = 0;

    let endian = "little";


    while (
        offset + 12 <= bytes.length
    ) {

        const blockType =
            readU32LE(
                bytes,
                offset
            );


        let blockLength =
            readU32LE(
                bytes,
                offset + 4
            );


        if (
            blockType === 0x0A0D0D0A
        ) {

            const bom =
                readU32LE(
                    bytes,
                    offset + 8
                );


            if (
                bom === 0x1A2B3C4D
            ) {

                endian = "little";

            } else if (
                bom === 0x4D3C2B1A
            ) {

                endian = "big";

            } else {

                throw new Error(
                    "Invalid PCAPNG byte-order marker."
                );

            }

        }


        if (
            blockLength < 12 ||
            offset + blockLength >
            bytes.length
        ) {

            break;

        }


        if (
            blockType === 0x00000001
        ) {

            const linkType =
                readEndian16(
                    bytes,
                    offset + 8,
                    endian
                );


            interfaces.push(
                linkType
            );

        }


        if (
            blockType === 0x00000006
        ) {

            const interfaceId =
                readEndian32(
                    bytes,
                    offset + 8,
                    endian
                );


            const timestampHigh =
                readEndian32(
                    bytes,
                    offset + 12,
                    endian
                );


            const timestampLow =
                readEndian32(
                    bytes,
                    offset + 16,
                    endian
                );


            const capturedLength =
                readEndian32(
                    bytes,
                    offset + 20,
                    endian
                );


            const originalLength =
                readEndian32(
                    bytes,
                    offset + 24,
                    endian
                );


            const packetStart =
                offset + 28;


            if (
                packetStart +
                capturedLength <=
                bytes.length
            ) {

                const packet =
                    bytes.slice(
                        packetStart,
                        packetStart +
                        capturedLength
                    );


                const linkType =
                    interfaces[
                        interfaceId
                    ] ?? 1;


                const parsed =
                    parsePacket(
                        packet,
                        linkType
                    );


                const timestampRaw =
                    timestampHigh *
                    4294967296 +
                    timestampLow;


                parsed.timestamp =
                    timestampRaw /
                    1000000;


                parsed.length =
                    originalLength;

                parsed.capturedLength =
                    capturedLength;

                parsed.number =
                    packets.length + 1;


                packets.push(
                    parsed
                );

            }

        }


        offset += blockLength;

    }


    return {

        format: "PCAPNG",

        packets

    };

}


// ==========================================
// PACKET PARSER
// ==========================================

function parsePacket(
    packet,
    linkType
) {

    const result = {

        source: "—",

        destination: "—",

        protocol: "OTHER",

        sourcePort: "—",

        destinationPort: "—",

        timestamp: 0,

        length: packet.length,

        capturedLength: packet.length

    };


    // Ethernet

    if (
        linkType === 1 &&
        packet.length >= 14
    ) {

        const etherType =
            readU16BE(
                packet,
                12
            );


        if (
            etherType === 0x0800
        ) {

            parseIPv4(
                packet,
                14,
                result
            );

        } else if (
            etherType === 0x86DD
        ) {

            result.protocol =
                "IPv6";

        } else if (
            etherType === 0x0806
        ) {

            result.protocol =
                "ARP";

        } else {

            result.protocol =
                "ETHERNET";

        }


        return result;

    }


    // Raw IPv4

    if (
        linkType === 101 &&
        packet.length >= 20
    ) {

        parseIPv4(
            packet,
            0,
            result
        );

        return result;

    }


    result.protocol =
        "OTHER";


    return result;

}


// ==========================================
// IPv4
// ==========================================

function parseIPv4(
    bytes,
    start,
    result
) {

    if (
        start + 20 >
        bytes.length
    ) {

        return;

    }


    const version =
        bytes[start] >> 4;


    if (
        version !== 4
    ) {

        return;

    }


    const ihl =
        (bytes[start] & 0x0F) *
        4;


    if (
        start + ihl >
        bytes.length
    ) {

        return;

    }


    result.source =
        ipFromBytes(
            bytes,
            start + 12
        );


    result.destination =
        ipFromBytes(
            bytes,
            start + 16
        );


    const protocol =
        bytes[start + 9];


    const transportStart =
        start + ihl;


    if (
        protocol === 6
    ) {

        result.protocol =
            "TCP";


        if (
            transportStart + 4 <=
            bytes.length
        ) {

            result.sourcePort =
                readU16BE(
                    bytes,
                    transportStart
                );

            result.destinationPort =
                readU16BE(
                    bytes,
                    transportStart + 2
                );

        }

    } else if (
        protocol === 17
    ) {

        result.protocol =
            "UDP";


        if (
            transportStart + 4 <=
            bytes.length
        ) {

            result.sourcePort =
                readU16BE(
                    bytes,
                    transportStart
                );

            result.destinationPort =
                readU16BE(
                    bytes,
                    transportStart + 2
                );

        }

    } else if (
        protocol === 1
    ) {

        result.protocol =
            "ICMP";

    } else if (
        protocol === 2
    ) {

        result.protocol =
            "IGMP";

    } else {

        result.protocol =
            "IPv4/" +
            protocol;

    }

}


// ==========================================
// PCAP RENDERING
// ==========================================

function renderPCAPResults(result) {

    const packets =
        result.packets;


    const totalBytes =
        packets.reduce(
            (
                total,
                packet
            ) =>
                total +
                packet.length,
            0
        );


    const ipv4Count =
        packets.filter(
            packet =>
                packet.source !== "—"
        ).length;


    const tcpCount =
        packets.filter(
            packet =>
                packet.protocol === "TCP"
        ).length;


    const udpCount =
        packets.filter(
            packet =>
                packet.protocol === "UDP"
        ).length;


    const icmpCount =
        packets.filter(
            packet =>
                packet.protocol === "ICMP"
        ).length;


    document.getElementById(
        "packet-count"
    ).textContent =
        packets.length.toLocaleString();


    document.getElementById(
        "packet-bytes"
    ).textContent =
        formatBytes(totalBytes);


    document.getElementById(
        "ipv4-count"
    ).textContent =
        ipv4Count.toLocaleString();


    document.getElementById(
        "tcp-count"
    ).textContent =
        tcpCount.toLocaleString();


    document.getElementById(
        "udp-count"
    ).textContent =
        udpCount.toLocaleString();


    document.getElementById(
        "icmp-count"
    ).textContent =
        icmpCount.toLocaleString();


    renderProtocolStats(
        packets
    );


    renderEndpointStats(
        packets
    );


    renderPacketTable(
        packets
    );


    if (
        packets.length
    ) {

        const first =
            packets[0].timestamp;

        const last =
            packets[
                packets.length - 1
            ].timestamp;


        document.getElementById(
            "packet-range"
        ).textContent =
            formatTimestamp(first) +
            " → " +
            formatTimestamp(last);

    } else {

        document.getElementById(
            "packet-range"
        ).textContent =
            "NO PACKETS";

    }

}


// ==========================================
// PROTOCOL STATISTICS
// ==========================================

function renderProtocolStats(
    packets
) {

    const counts = {};


    packets.forEach(
        packet => {

            counts[
                packet.protocol
            ] =
                (
                    counts[
                        packet.protocol
                    ] || 0
                ) + 1;

        }
    );


    const sorted =
        Object.entries(counts)
            .sort(
                (
                    a,
                    b
                ) =>
                    b[1] -
                    a[1]
            );


    const container =
        document.getElementById(
            "protocol-stats"
        );


    if (!sorted.length) {

        container.textContent =
            "No packets found.";

        return;

    }


    container.innerHTML =
        sorted
            .map(
                ([name, count]) => `

                    <div class="protocol-row">

                        <span class="protocol-name">
                            ${escapeHTML(name)}
                        </span>

                        <span class="protocol-value">
                            ${count.toLocaleString()}
                        </span>

                    </div>

                `
            )
            .join("");

}


// ==========================================
// ENDPOINT STATISTICS
// ==========================================

function renderEndpointStats(
    packets
) {

    const counts = {};


    packets.forEach(
        packet => {

            if (
                packet.source !== "—"
            ) {

                counts[
                    packet.source
                ] =
                    (
                        counts[
                            packet.source
                        ] || 0
                    ) + 1;

            }


            if (
                packet.destination !== "—"
            ) {

                counts[
                    packet.destination
                ] =
                    (
                        counts[
                            packet.destination
                        ] || 0
                    ) + 1;

            }

        }
    );


    const sorted =
        Object.entries(counts)
            .sort(
                (
                    a,
                    b
                ) =>
                    b[1] -
                    a[1]
            )
            .slice(
                0,
                10
            );


    const container =
        document.getElementById(
            "endpoint-stats"
        );


    if (!sorted.length) {

        container.textContent =
            "No IPv4 endpoints found.";

        return;

    }


    container.innerHTML =
        sorted
            .map(
                ([ip, count]) => `

                    <div class="endpoint-row">

                        <span class="endpoint-name">
                            ${escapeHTML(ip)}
                        </span>

                        <span class="endpoint-value">
                            ${count.toLocaleString()}
                        </span>

                    </div>

                `
            )
            .join("");

}


// ==========================================
// PACKET TABLE
// ==========================================

function renderPacketTable(
    packets
) {

    const tbody =
        document.getElementById(
            "packet-table"
        );


    const displayPackets =
        packets.slice(
            0,
            1000
        );


    tbody.innerHTML =
        displayPackets
            .map(
                packet => `

                    <tr>

                        <td>
                            ${packet.number}
                        </td>

                        <td>
                            ${formatTimestamp(
                                packet.timestamp
                            )}
                        </td>

                        <td>
                            ${escapeHTML(
                                packet.source
                            )}
                            ${
                                packet.sourcePort !== "—"
                                    ? ":" +
                                      packet.sourcePort
                                    : ""
                            }
                        </td>

                        <td>
                            ${escapeHTML(
                                packet.destination
                            )}
                            ${
                                packet.destinationPort !== "—"
                                    ? ":" +
                                      packet.destinationPort
                                    : ""
                            }
                        </td>

                        <td>
                            ${escapeHTML(
                                packet.protocol
                            )}
                        </td>

                        <td>
                            ${packet.length}
                        </td>

                    </tr>

                `
            )
            .join("");


    if (
        packets.length > 1000
    ) {

        const row =
            document.createElement(
                "tr"
            );


        row.innerHTML = `

            <td colspan="6">

                Showing first 1000 packets
                of ${packets.length.toLocaleString()}.

            </td>

        `;


        tbody.appendChild(row);

    }

}


// ==========================================
// TIMESTAMP
// ==========================================

function formatTimestamp(
    seconds
) {

    if (
        !Number.isFinite(seconds)
    ) {

        return "—";

    }


    const date =
        new Date(
            seconds * 1000
        );


    return (
        date.toISOString()
            .replace(
                "T",
                " "
            )
            .replace(
                "Z",
                ""
            )
    );

}


// ==========================================
// IP
// ==========================================

function ipFromBytes(
    bytes,
    offset
) {

    return [

        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3]

    ].join(".");

}


// ==========================================
// INTEGER HELPERS
// ==========================================

function readU16BE(
    bytes,
    offset
) {

    return (
        bytes[offset] * 256 +
        bytes[offset + 1]
    );

}


function readU32LE(
    bytes,
    offset
) {

    return (
        bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)
    ) >>> 0;

}


function readU32BE(
    bytes,
    offset
) {

    return (
        (
            bytes[offset] * 16777216
        ) +
        (
            bytes[offset + 1] * 65536
        ) +
        (
            bytes[offset + 2] * 256
        ) +
        bytes[offset + 3]
    ) >>> 0;

}


function readEndian16(
    bytes,
    offset,
    endian
) {

    if (
        endian === "little"
    ) {

        return (
            bytes[offset] |
            (
                bytes[offset + 1]
                << 8
            )
        );

    }


    return readU16BE(
        bytes,
        offset
    );

}


function readEndian32(
    bytes,
    offset,
    endian
) {

    if (
        endian === "little"
    ) {

        return readU32LE(
            bytes,
            offset
        );

    }


    return readU32BE(
        bytes,
        offset
    );

}


// ==========================================
// HTML SAFETY
// ==========================================

function escapeHTML(
    value
) {

    return String(value)
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );

}


// ==========================================
// STARTUP
// ==========================================

console.log(
    "%cNEXUS // CYBEROPS v0.3.0",
    "color:#7dff9a;font-size:18px;font-weight:bold;"
);

console.log(
    "PCAP analysis running locally in the browser."
);
