'use strict';

console.log("[*] Starting PlayStation network hook script...");

// Enumerate loaded modules to help identify the networking stack
Process.enumerateModules({
    onMatch: function(module) {
        console.log(module.name + " @ " + module.base);
    },
    onComplete: function() {
        console.log("[*] Module enumeration complete.");
    }
});

// Attempt to locate SSL_read in libssl.so
var sslReadAddr = Module.findExportByName("libssl.so", "SSL_read");
if (sslReadAddr === null) {
    console.error("[!] SSL_read not found in libssl.so. Check if the app uses a different SSL library.");
} else {
    console.log("[*] SSL_read found at: " + sslReadAddr);
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
                console.log("[*] SSL_read returned " + bytesRead + " bytes on SSL " + this.sslPtr);
                // Dump a snippet of data (first 100 bytes) to help identify the network request
                var snippet = "";
                for (var i = 0; i < Math.min(100, bytesRead); i++) {
                    snippet += String.fromCharCode(Memory.readU8(this.buf.add(i)));
                }
                console.log("[*] Data snippet: " + snippet);
            } catch (e) {
                console.error("[!] Error reading SSL_read buffer: " + e);
            }
        }
    });
}
