// sniffers/hook_nintendo_delay.js
'use strict';
var Module = Process.getModuleByName; // just shorthand

// 1) Intercept dlopen so we know when the native lib loads
var dlopen = Module.findExportByName(null, 'dlopen');
Interceptor.attach(dlopen, {
  onEnter(args) {
    this.lib = args[0].readCString();
  },
  onLeave(retval) {
    if (this.lib.indexOf('libpairipcore.so') !== -1) {
      console.log('[+] libpairipcore loaded — installing Java hooks');

      Java.perform(function () {
        var ResponseBody = Java.use('okhttp3.ResponseBody');
        ResponseBody.string.overload().implementation = function () {
          var json = this.string();
          if (json.indexOf('"friends"') !== -1) {
            console.log('[🎉 friends JSON] ' + json);
          }
          return json;
        };
      });

      // 2) All hooks in place, resume the main thread
      console.log('[+] Hooks installed — resuming app');
      send('resume');  // tell CLI it’s safe to go
    }
  }
});

// 3) Wait for the CLI to call resume()
recv('resume', function () {
  console.log('[*] Resuming now');
  // this call comes back to the Frida REPL:
  //   %resume
});
