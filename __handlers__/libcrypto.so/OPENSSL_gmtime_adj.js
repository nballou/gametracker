/*
 * Auto-generated by Frida. Please modify to match the signature of OPENSSL_gmtime_adj.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`OPENSSL_gmtime_adj(tm=${args[0]}, offset_day=${args[1]}, offset_sec=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
