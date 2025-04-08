/*
 * Auto-generated by Frida. Please modify to match the signature of OpenSSL_version.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`OpenSSL_version(t=${args[0]})`);
  },

  onLeave(log, retval, state) {
  }
});
