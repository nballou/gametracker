/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set_cert_cb.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set_cert_cb(s=${args[0]}, (*cert_cb=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
