/*
 * Auto-generated by Frida. Please modify to match the signature of OPENSSL_config.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`OPENSSL_config(appname="${args[0].readUtf8String()}")`);
  },

  onLeave(log, retval, state) {
  }
});
