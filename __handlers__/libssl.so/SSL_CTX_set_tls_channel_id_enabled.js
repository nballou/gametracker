/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CTX_set_tls_channel_id_enabled.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_CTX_set_tls_channel_id_enabled()');
  },

  onLeave(log, retval, state) {
  }
});
