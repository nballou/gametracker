/*
 * Auto-generated by Frida. Please modify to match the signature of SSL_set_compliance_policy.
 * This stub is currently auto-generated from manpages when available.
 *
 * For full API reference, see: https://frida.re/docs/javascript-api/
 */

defineHandler({
  onEnter(log, args, state) {
    log('SSL_set_compliance_policy()');
  },

  onLeave(log, retval, state) {
  }
});
