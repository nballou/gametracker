/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CREDENTIAL_set_private_key_method.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_CREDENTIAL_set_private_key_method()');
  },

  onLeave(log, retval, state) {
  }
});
