/*
 * Auto-generated by Frida. Please modify to match the signature of OPENSSL_secure_clear_free.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`OPENSSL_secure_clear_free(ptr=${args[0]}, num=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
