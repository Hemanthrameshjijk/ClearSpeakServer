"""Create the production signing key (encrypted file) and print the public key bytes to put into the app
(`app/src/license_key.rs`).  python scripts/newkey.py signing.key
The passphrase is read from the prompt, never from the command line. Back the file up offline and keep it off git."""

import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from licsrv.keys import write_encrypted_key  # noqa: E402

if len(sys.argv) != 2:
    sys.exit("usage: python scripts/newkey.py <key-file>")
pw = getpass.getpass("Passphrase (12+ characters): ")
if pw != getpass.getpass("Again: "):
    sys.exit("The passphrases differ.")
pk = write_encrypted_key(Path(sys.argv[1]), pw)
print(f"Signing key written to {sys.argv[1]}. Keep it and the passphrase safe; back them up offline.")
print("Public key for the app:")
print("[" + ", ".join(f"0x{b:02x}" for b in pk) + "]")
