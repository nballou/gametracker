/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set1_chain.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set1_chain(ssl=${args[0]}, STACK_OF(X509=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
