'use strict';

// An object to accumulate data per SSL connection (keyed by its pointer as string)
var accumulators = {};

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

// Hook SSL_read (update the address as necessary)
Interceptor.attach(ptr("0x6fb569dbb0"), {
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
