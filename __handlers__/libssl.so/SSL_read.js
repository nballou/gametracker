/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_read.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_read(ssl=${args[0]}, buf=${args[1]}, num=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
