/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set_cipher_list.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log(`SSL_set_cipher_list(ssl=${args[0]}, str="${args[1].readUtf8String()}")`);
  },

  onLeave(log, retval, state) {
  }
});
