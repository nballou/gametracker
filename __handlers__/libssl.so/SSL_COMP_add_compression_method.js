/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_COMP_add_compression_method.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_COMP_add_compression_method(id=${args[0]}, cm=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
