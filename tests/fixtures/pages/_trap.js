// Shared by the fake trap pages. The "attack" command is harmless: it only
// prints a message. It is shaped like a real ClickFix command so the
// extension has to catch it.
window.TRAP_COMMAND = 'cmd /c echo ClickFix First Aid test, this is harmless # I am not a robot - reCAPTCHA Verification ID: 1234';
window.TRAP_INSTRUCTIONS =
  'Verify you are human. Complete these verification steps: ' +
  '1. Press Windows Key + R  2. Press CTRL + V  3. Press Enter';
