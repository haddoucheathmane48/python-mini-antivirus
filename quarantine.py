"""Quarantaine : le fichier est déplacé, rendu illisible (XOR) et non exécutable. Restauration possible."""
import json, os, shutil, time, uuid
from pathlib import Path

KEY = 0x5A

def _xor(data: bytes) -> bytes:
    return bytes(b ^ KEY for b in data)


class Quarantine:
    def __init__(self, directory="quarantine"):
        self.dir = Path(directory); self.dir.mkdir(parents=True, exist_ok=True)

    def add(self, path, threat: str, sha256: str = "") -> str:
        src = Path(path); qid = uuid.uuid4().hex[:8]
        blob = self.dir / f"{qid}.quarantine"
        blob.write_bytes(_xor(src.read_bytes()))
        os.chmod(blob, 0o600)
        meta = {"id": qid, "original_path": str(src.resolve()), "threat": threat, "sha256": sha256,
                "date": time.strftime("%Y-%m-%d %H:%M:%S")}
        (self.dir / f"{qid}.json").write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        src.unlink()                                   # le fichier d'origine disparaît
        return qid

    def list(self):
        return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.dir.glob("*.json"))]

    def restore(self, qid: str, dest=None) -> Path:
        meta = json.loads((self.dir / f"{qid}.json").read_text(encoding="utf-8"))
        target = Path(dest or meta["original_path"]); target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(_xor((self.dir / f"{qid}.quarantine").read_bytes()))
        self.delete(qid); return target

    def delete(self, qid: str):
        for ext in (".quarantine", ".json"):
            p = self.dir / f"{qid}{ext}"
            if p.exists(): p.unlink()
