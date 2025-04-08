'use strict';

// An object to accumulate data per SSL connection (keyed by its pointer as string)
var accumulators = {};

// Convert a JSON string into CSV using only the relevant telemetry columns.
function jsonToCSV(jsonStr) {
    // Parse the JSON string into an object
    let data;
    try {
        data = JSON.parse(jsonStr);
    } catch (e) {
        console.error("Invalid JSON string", e);
        return null;
    }
    
    // Ensure that the expected "people" array exists
    if (!data.people || !Array.isArray(data.people)) {
        console.error("JSON does not contain a valid 'people' array.");
        return null;
    }
    
    // Define the headers/columns for the CSV.
    // Adjust these to include whichever telemetry columns are relevant.
    const headers = [
        "gamertag",
        "displayName",
        "realName",
        "friendCount",
        "presenceState",
        "presenceText",
        "lastSeenDateTimeUtc",
        "xuid"
    ];
    
    // Create the CSV string with the headers first.
    let csv = headers.join(",") + "\n";
    
    // Process each person in the people array.
    data.people.forEach(person => {
        // Extract values safely (using empty string if missing).
        // Note that friendCount is nested under "detail".
        const gamertag = person.gamertag || "";
        const displayName = person.displayName || "";
        const realName = person.realName || "";
        const friendCount = (person.detail && person.detail.friendCount) || "";
        const presenceState = person.presenceState || "";
        const presenceText = person.presenceText || "";
        const lastSeenDateTimeUtc = person.lastSeenDateTimeUtc || "";
        const xuid = person.xuid || "";
        
        // Create an array representing one CSV row.
        let row = [gamertag, displayName, realName, friendCount, presenceState, presenceText, lastSeenDateTimeUtc, xuid];
        
        // Escape each field (wrap in quotes, doubling any quotes inside)
        row = row.map(field => `"${String(field).replace(/"/g, '""')}"`);
        
        // Append the row to the CSV string.
        csv += row.join(",") + "\n";
    });
    
    return csv;
}

// Save the CSV string to a file using the local date/time in the filename.
function saveCSV(csvStr) {
    Java.perform(function() {
        try {
            var SimpleDateFormat = Java.use("java.text.SimpleDateFormat");
            var Date = Java.use("java.util.Date");
            var StringBuffer = Java.use("java.lang.StringBuffer");
            var FieldPosition = Java.use("java.text.FieldPosition");

            // Create a SimpleDateFormat instance with the desired pattern.
            var sdf = SimpleDateFormat.$new("yyyy-MM-dd_HH-mm-ss");
            var nowDate = Date.$new();

            // Create a new StringBuffer and FieldPosition (using 0 as the field index).
            var sb = StringBuffer.$new("");
            var fp = FieldPosition.$new(0);

            // Call the format(Date, StringBuffer, FieldPosition) overload.
            var now = sdf.format(nowDate, sb, fp).toString();

            var filename = "/sdcard/telemetry_" + now + ".csv";
            var File = Java.use("java.io.File");
            var FileOutputStream = Java.use("java.io.FileOutputStream");
            var file = File.$new(filename);
            var fos = FileOutputStream.$new(file);
            // Write the CSV string as bytes (using the default charset).
            fos.write(Java.use("java.lang.String").$new(csvStr).getBytes());
            fos.close();
            console.log("CSV saved to " + filename);
        } catch (e) {
            console.error("Error saving CSV: " + e);
        }
    });
}


// Helper: parse HTTP headers from a string
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

    // Convert combined data to a string for header detection.
    var combinedStr = "";
    for (var i = 0; i < combined.length; i++) {
        combinedStr += String.fromCharCode(combined[i]);
    }
    // Look for end of headers.
    var headerEndIndex = combinedStr.indexOf("\r\n\r\n");
    if (headerEndIndex === -1) {
        return; // Not yet complete.
    }
    var headerPart = combinedStr.substring(0, headerEndIndex);
    var headers = parseHeaders(headerPart);
    var bodyOffset = headerEndIndex + 4;
    // If a Content-Length header exists, wait until we have the full body.
    if (headers["content-length"]) {
        var contentLength = parseInt(headers["content-length"]);
        var bodyLength = combined.length - bodyOffset;
        if (bodyLength < contentLength) {
            return;
        }
    }
    var body = combined.slice(bodyOffset);
    
    // Process the body based on Content-Encoding.
    if (headers["content-encoding"] && headers["content-encoding"].toLowerCase() === "gzip") {
        console.log("Data is gzip-compressed; decompressing...");
        // Use Java to decompress in a Java.perform block.
        Java.perform(function() {
            try {
                var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                var GZIPInputStream = Java.use("java.util.zip.GZIPInputStream");
                var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                // Convert 'body' (a Uint8Array) to a Java byte array.
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
                console.log("----- HTTP Response (SSL " + sslKey + ") -----\n" +
                            headerPart + "\n\n" +
                            "Decoded HTTP body:\n" + result + "\n------------------------------------");
                
                // Optionally, you might want to check for certain keywords before processing.
                // Here, we assume that the body is the JSON we want.
                var csvStr = jsonToCSV(result);
                if (csvStr) {
                    send({ type: "csv-data" }, csvStr);
                } else {
                    console.log("No valid CSV produced from the response.");
                }
            } catch (err) {
                console.error("Decompression error: " + err);
            }
        });
    } else {
        var result = "";
        for (var i = 0; i < body.length; i++) {
            result += String.fromCharCode(body[i]);
        }
        console.log("----- HTTP Response (SSL " + sslKey + ") -----\n" +
                    headerPart + "\n\n" +
                    "Decoded HTTP body:\n" + result + "\n------------------------------------");
    }
    // Clear the accumulator for this SSL connection.
    delete accumulators[sslKey];
}

// Dynamically find the address of SSL_read
var sslReadAddr = Module.findExportByName("libssl.so", "SSL_read");
if (sslReadAddr === null) {
    console.error("SSL_read not found in libssl.so");
} else {
    console.log("SSL_read found at: " + sslReadAddr);
    Interceptor.attach(sslReadAddr, {
        onEnter: function(args) {
            // args[0]: pointer to SSL structure, args[1]: output buffer, args[2]: number of bytes to read.
            this.sslPtr = args[0].toString();
            this.buf = args[1];
            this.num = args[2].toInt32();
        },
        onLeave: function(retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;
            try {
                var data = Memory.readByteArray(this.buf, bytesRead);
                console.log("SSL_read returned " + bytesRead + " bytes on SSL " + this.sslPtr);
                processData(this.sslPtr, data);
            } catch (e) {
                console.error("Error reading SSL_read buffer: " + e);
            }
        }
    });
}
