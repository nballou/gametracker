/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set1_groups.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set1_groups(ssl=${args[0]}, glist=${args[1]}, glistlen=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
