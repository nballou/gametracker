/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set1_host.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set1_host(s=${args[0]}, hostname="${args[1].readUtf8String()}")`);
  },

  onLeave(log, retval, state) {
  }
});
