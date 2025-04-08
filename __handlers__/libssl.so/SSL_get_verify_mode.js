/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_get_verify_mode.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_get_verify_mode(ssl=${args[0]})`);
  },

  onLeave(log, retval, state) {
  }
});
