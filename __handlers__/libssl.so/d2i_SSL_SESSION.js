/*
 * Auto-generated by Frida. Please modify to match the signature of d2i_SSL_SESSION.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`d2i_SSL_SESSION(*a=${args[0]}, *pp=${args[1]}, length=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
