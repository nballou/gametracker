/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CTX_set_psk_client_callback.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_CTX_set_psk_client_callback(ctx=${args[0]}, cb=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
