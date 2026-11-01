"""Régénère signatures.json. Le motif EICAR est stocké en base64 : le dépôt lui-même n'est donc pas détecté."""
import base64, hashlib, json, pathlib
EICAR = ("X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").encode()
db = {
  "version": "1.0",
  "hashes": [{"sha256": hashlib.sha256(EICAR).hexdigest(), "name": "Test.EICAR"}],
  "patterns": [
    {"name": "Test.EICAR", "b64": base64.b64encode(EICAR).decode()},
    {"name": "Sim.Trojan.Dropper", "text": "MINIAV-TEST-TROJAN-DROPPER"},
    {"name": "Sim.Ransomware.Note", "text": "MINIAV-TEST-RANSOM-NOTE"},
    {"name": "Sim.Miner.Process", "text": "MINIAV-TEST-MINER-9F3A"},
    {"name": "Sim.Worm.Spreader", "text": "MINIAV-TEST-WORM-SPREADER"},
  ],
}
pathlib.Path(__file__).with_name("signatures.json").write_text(json.dumps(db, indent=2))
print("signatures.json régénéré")
