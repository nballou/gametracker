/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_add1_chain_cert.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_add1_chain_cert(ssl=${args[0]}, x509=${args[1]})`);
  },

  onLeave(log, retval, state) {
  }
});
