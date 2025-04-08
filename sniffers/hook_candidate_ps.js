Java.perform(function() {
    Java.enumerateLoadedClasses({
        onMatch: function(className) {
            if (className.indexOf("Friend") !== -1 || className.indexOf("Presence") !== -1 || className.indexOf("Status") !== -1) {
                console.log("Found class: " + className);
            }
        },
        onComplete: function() {
            console.log("Enumeration complete.");
        }
    });
});
