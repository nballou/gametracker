/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_get0_peer_certificates.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_get0_peer_certificates()');
  },

  onLeave(log, retval, state) {
  }
});
