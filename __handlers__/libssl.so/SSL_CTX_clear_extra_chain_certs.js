/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CTX_clear_extra_chain_certs.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_CTX_clear_extra_chain_certs(ctx=${args[0]})`);
  },

  onLeave(log, retval, state) {
  }
});
