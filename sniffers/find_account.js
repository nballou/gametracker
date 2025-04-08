'use strict';

Interceptor.attach(Module.findExportByName("libssl.so", "SSL_read"), {
    onEnter: function(args) {
        // Save SSL pointer, buffer and number of bytes requested
        this.sslPtr = args[0].toString();
        this.buf = args[1];
        this.num = args[2].toInt32();
    },
    onLeave: function(retval) {
        var bytesRead = retval.toInt32();
        if (bytesRead <= 0) return;
        try {
            // Read the data from the buffer
            var data = Memory.readByteArray(this.buf, bytesRead);
            // Convert the data into a string
            var str = "";
            for (var i = 0; i < bytesRead; i++) {
                str += String.fromCharCode(Memory.readU8(this.buf.add(i)));
            }
            // Check if the account ID appears in the data
            if (str.indexOf("4645135650815230075") !== -1) {
                console.log("[*] Found account ID '4645135650815230075' in SSL response on SSL " + this.sslPtr + ":");
                console.log(str);
            }
        } catch (e) {
            console.error("[!] Error processing SSL data: " + e);
        }
    }
});
