/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_add_client_CA.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_add_client_CA(ssl=${args[0]}, cacert=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
