/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CTX_set_verify.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_CTX_set_verify(ctx=${args[0]}, mode=${args[1]}, verify_callback=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
