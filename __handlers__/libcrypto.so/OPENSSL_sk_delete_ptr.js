/*
 * Auto-generated by Frida. Please modify to match the signature of OPENSSL_sk_delete_ptr.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('OPENSSL_sk_delete_ptr()');
  },

  onLeave(log, retval, state) {
  }
});
