/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_CTX_use_RSAPrivateKey_file.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_CTX_use_RSAPrivateKey_file(ctx=${args[0]}, file="${args[1].readUtf8String()}", type=${args[2]})`);
  },

  onLeave(log, retval, state) {
  }
});
