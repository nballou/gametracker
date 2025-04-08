/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set0_verify_cert_store.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set0_verify_cert_store(ctx=${args[0]}, st=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
