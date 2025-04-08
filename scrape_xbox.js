'use strict';

// An object to accumulate data per SSL connection (keyed by its pointer as string)
var accumulators = {};

if (!globalThis.processedPresenceCache) {
    globalThis.processedPresenceCache = {};
}


// Convert a JSON string into CSV using only the relevant telemetry columns.
function jsonToCSV(jsonStr) {
    let data;
    try {
        data = JSON.parse(jsonStr);
    } catch (e) {
        return null;
    }
    
    if (!data.people || !Array.isArray(data.people)) {
        return null;
    }
    
    const headers = [
        "platform",
        "userName",
        "accountID",
        "presenceState",
        "presenceText",
        "presencePlatform",
        "titleId",
        "gamerScore",
        "multiplayerSummary",
        "lastSeen"
    ];
    
    let csv = headers.join(",") + "\n";
    
    data.people.forEach(person => {
        const platform = "Xbox";
        const userName = person.gamertag || "";
        const accountID = person.xuid || "";
        const friendCount = (person.detail && person.detail.friendCount) || "";
        const presenceState = person.presenceState || "";
        const presenceText = person.presenceText || "";
        const gamerScore = (person.gamerScore) || "";
        const presencePlatform = "";
        const titleId = "";
        const multiplayerSummary = JSON.stringify(person.multiplayerSummary) || "";
        const lastSeen = person.lastSeenDateTimeUtc || "";
        
        let row = [platform, userName, accountID, presenceState, presenceText, presenceState, presencePlatform, titleId, gamerScore, multiplayerSummary, lastSeen];
        row = row.map(field => `"${String(field).replace(/"/g, '""')}"`);
        csv += row.join(",") + "\n";
    });
    
    return csv;
}

// Parse HTTP headers from a string.
function parseHeaders(headerStr) {
    var headers = {};
    var lines = headerStr.split("\r\n");
    lines.forEach(function (line) {
        var parts = line.split(": ");
        if (parts.length === 2) {
            headers[parts[0].toLowerCase()] = parts[1];
        }
    });
    return headers;
}

// Accumulate data, detect full HTTP response, and process it.
function processData(sslKey, data) {
    if (!(sslKey in accumulators)) {
        accumulators[sslKey] = [];
    }
    accumulators[sslKey].push(new Uint8Array(data));
    var totalLength = accumulators[sslKey].reduce((acc, curr) => acc + curr.length, 0);
    var combined = new Uint8Array(totalLength);
    var offset = 0;
    for (var chunk of accumulators[sslKey]) {
        combined.set(chunk, offset);
        offset += chunk.length;
    }

    // Convert combined data to a string.
    var combinedStr = "";
    for (var i = 0; i < combined.length; i++) {
        combinedStr += String.fromCharCode(combined[i]);
    }
    
    var headerEndIndex = combinedStr.indexOf("\r\n\r\n");
    if (headerEndIndex === -1) {
        return;
    }
    var headerPart = combinedStr.substring(0, headerEndIndex);
    var headers = parseHeaders(headerPart);
    var bodyOffset = headerEndIndex + 4;
    
    if (headers["content-length"]) {
        var contentLength = parseInt(headers["content-length"]);
        var bodyLength = combined.length - bodyOffset;
        if (bodyLength < contentLength) {
            return;
        }
    }
    var body = combined.slice(bodyOffset);
    
    function processBody(result) {
        var csvStr = jsonToCSV(result);
        if (csvStr) {
            // console.log("Decoded HTTP body:\n" + result + "\n------------------------------------");
            console.log("[*] Extracted JSON data and converted to CSV:");
            console.log(csvStr);
            send({type: "csv-data", csv: csvStr, platform: "Xbox"});
        } else {
            // console.log("[DEBUG] Intercepted HTTP response on SSL " + sslKey + " did not contain valid telemetry data.");
        }
    }
    
    if (headers["content-encoding"] && headers["content-encoding"].toLowerCase() === "gzip") {
        Java.perform(function() {
            try {
                var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
                var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                var jsArray = Array.from(body);
                var javaByteArray = Java.array('byte', jsArray);
                var bais = ByteArrayInputStream.$new(javaByteArray);
                var gzipIS = GZIPInputStream.$new(bais);
                var baos = ByteArrayOutputStream.$new();
                var buffer = Java.array('byte', new Array(1024).fill(0));
                var n;
                while ((n = gzipIS.read(buffer, 0, buffer.length)) > 0) {
                    baos.write(buffer, 0, n);
                }
                gzipIS.close();
                baos.close();
                var decompressed = baos.toByteArray();
                var result = "";
                for (var i = 0; i < decompressed.length; i++) {
                    result += String.fromCharCode(decompressed[i]);
                }
                processBody(result);
            } catch (err) {
                // Suppress decompression errors.
            }
        });
    } else {
        var result = "";
        for (var i = 0; i < body.length; i++) {
            result += String.fromCharCode(body[i]);
        }
        processBody(result);
    }
    delete accumulators[sslKey];
}

// Find SSL_read in libssl.so and attach our interceptor.
var sslReadAddr = Module.findExportByName("libssl.so", "SSL_read");
if (sslReadAddr === null) {
    console.error("SSL_read not found in libssl.so");
} else {
    Interceptor.attach(sslReadAddr, {
        onEnter: function(args) {
            this.sslPtr = args[0].toString();
            this.buf = args[1];
            this.num = args[2].toInt32();
        },
        onLeave: function(retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;
            try {
                var data = Memory.readByteArray(this.buf, bytesRead);
                processData(this.sslPtr, data);
            } catch (e) {
                // Suppress errors reading the SSL buffer.
            }
        }
    });
}
