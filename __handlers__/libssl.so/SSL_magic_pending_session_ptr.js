/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_magic_pending_session_ptr.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_magic_pending_session_ptr()');
  },

  onLeave(log, retval, state) {
  }
});
