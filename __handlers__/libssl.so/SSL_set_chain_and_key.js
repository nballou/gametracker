/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set_chain_and_key.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_set_chain_and_key()');
  },

  onLeave(log, retval, state) {
  }
});
