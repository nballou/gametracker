// Pseudocode for hooking a native function (adjust address/symbol as needed)
Interceptor.attach(Module.findExportByName("libMirandaParty.so", "???getProfileInfo???"), {
    onEnter: function(args) {
        console.log("[*] getProfileInfo called");
    },
    onLeave: function(retval) {
        try {
            // Log the raw retval and its type
            console.log("[*] Raw retval: " + retval);
            console.log("[*] Typeof retval: " + typeof retval);

            var retPtr;
            try {
                // Attempt to create a NativePointer from retval
                retPtr = new NativePointer(retval);
            } catch (err) {
                console.error("[!] Could not create NativePointer from retval: " + err);
                return;
            }
            console.log("[*] Interpreting retval as pointer: " + retPtr);
            if (retPtr.isNull()) {
                console.log("[*] getProfileInfo returned a null pointer");
                return;
            }
            // Attempt to read a UTF-8 string from the pointer
            var jsonStr = Memory.readUtf8String(retPtr);
            console.log("[*] getProfileInfo returned: " + jsonStr);
            
            var profile = JSON.parse(jsonStr);
            console.log("[*] AccountID: " + profile.accountId + ", OnlineID: " + profile.onlineId);
        } catch (e) {
            console.error("[!] Error processing getProfileInfo return: " + e);
        }
    }
});
