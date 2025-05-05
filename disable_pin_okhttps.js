// find_pinning.js
Java.perform(() => {
    console.log("[*] Enumerating loaded classes for ‘Pinner’ or ‘OkHttp’…");
    Java.enumerateLoadedClasses({
      onMatch(name) {
        if (name.match(/Pinner|OkHttp|okhttp/i))
          console.log("  → " + name);
      },
      onComplete() {
        console.log("[*] Done.");
      }
    });
  });