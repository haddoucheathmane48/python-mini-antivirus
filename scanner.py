"""Moteur de détection : signatures (hash + motifs d'octets) puis heuristiques à score."""
from __future__ import annotations
import base64, hashlib, json, math, os, re
from dataclasses import dataclass, field
from pathlib import Path

MAX_READ = 20 * 1024 * 1024          # on n'analyse en profondeur que les 20 premiers Mo
SUSPICIOUS_THRESHOLD = 5             # score >= 5 => SUSPICIOUS

# (regex, points, description) : chaînes typiques de scripts malveillants (analyse de TEXTE uniquement)
HEURISTIC_PATTERNS = [
    (rb"powershell(\.exe)?\s+.*-(enc|encodedcommand)\b", 3, "PowerShell encodé"),
    (rb"certutil\s+.*-urlcache", 3, "Téléchargement via certutil"),
    (rb"vssadmin\s+delete\s+shadows", 4, "Suppression des clichés instantanés (ransomware)"),
    (rb"bcdedit\s+.*recoveryenabled\s+no", 3, "Désactivation de la récupération Windows"),
    (rb"invoke-expression|\biex\s*\(", 2, "Exécution dynamique de code"),
    (rb"wscript\.shell", 2, "Objet WScript.Shell"),
    (rb"(curl|wget)\s+[^|\n]*\|\s*(ba)?sh", 3, "Téléchargement puis exécution (curl | sh)"),
    (rb"base64\s+-d\s*\|\s*(ba)?sh", 3, "Décodage base64 puis exécution"),
    (rb"/dev/tcp/", 3, "Reverse shell bash"),
    (rb"\bnc(\.exe)?\s+.*-e\s", 3, "Netcat avec exécution"),
    (rb"stratum\+tcp://", 3, "Connexion à un pool de minage"),
    (rb"hkcu\\\\?software\\\\?microsoft\\\\?windows\\\\?currentversion\\\\?run", 2, "Persistance via clé Run"),
    (rb"your files (have been|are) encrypted", 4, "Message de rançon"),
]
MAGICS = {b"MZ": "exécutable Windows (PE)", b"\x7fELF": "exécutable Linux (ELF)"}
SAFE_EXT_FOR_BINARY = {".exe", ".dll", ".sys", ".so", ".bin", ".elf", ".o", ""}


@dataclass
class Detection:
    path: str
    status: str                       # CLEAN | SUSPICIOUS | INFECTED | ERROR
    threat: str = ""
    sha256: str = ""
    score: int = 0
    reasons: list = field(default_factory=list)

    def to_dict(self): return self.__dict__


class Scanner:
    def __init__(self, signatures_path: str | Path | None = None):
        p = Path(signatures_path) if signatures_path else Path(__file__).with_name("signatures.json")
        db = json.loads(p.read_text(encoding="utf-8"))
        self.hashes = {h["sha256"]: h["name"] for h in db["hashes"]}
        self.patterns = []
        for s in db["patterns"]:
            raw = base64.b64decode(s["b64"]) if "b64" in s else s["text"].encode()
            self.patterns.append((s["name"], raw))

    # ---- outils ----
    @staticmethod
    def entropy(data: bytes) -> float:
        if not data: return 0.0
        counts = [0] * 256
        for b in data: counts[b] += 1
        n = len(data)
        return -sum(c / n * math.log2(c / n) for c in counts if c)

    @staticmethod
    def sha256_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""): h.update(chunk)
        return h.hexdigest()

    # ---- analyse d'un fichier ----
    def scan_file(self, path) -> Detection:
        path = Path(path)
        try:
            digest = self.sha256_file(path)
            if digest in self.hashes:                                  # 1) signature de hash
                return Detection(str(path), "INFECTED", self.hashes[digest], digest, 10, ["hash connu"])
            with open(path, "rb") as f: data = f.read(MAX_READ)
            for name, pat in self.patterns:                            # 2) signature de motif
                if pat in data:
                    return Detection(str(path), "INFECTED", name, digest, 10, ["motif connu"])
            score, reasons = self._heuristics(path, data)              # 3) heuristiques
            if score >= SUSPICIOUS_THRESHOLD:
                return Detection(str(path), "SUSPICIOUS", "Heur.Suspicious", digest, score, reasons)
            return Detection(str(path), "CLEAN", "", digest, score, reasons)
        except (PermissionError, FileNotFoundError, OSError) as e:
            return Detection(str(path), "ERROR", "", "", 0, [str(e)])

    def _heuristics(self, path: Path, data: bytes):
        score, reasons = 0, []
        low = data.lower()
        for rx, pts, desc in HEURISTIC_PATTERNS:
            if re.search(rx, low):
                score += pts; reasons.append(f"+{pts} {desc}")
        parts = path.name.lower().split(".")                           # double extension : facture.pdf.exe
        if len(parts) >= 3 and parts[-1] in {"exe", "scr", "bat", "cmd", "vbs", "js", "ps1"} \
                and parts[-2] in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "zip"}:
            score += 5; reasons.append("+5 double extension trompeuse")
        for magic, label in MAGICS.items():                            # binaire déguisé en document
            if data.startswith(magic) and path.suffix.lower() not in SAFE_EXT_FOR_BINARY:
                score += 5; reasons.append(f"+5 {label} déguisé en {path.suffix or 'fichier'}")
        if len(data) > 4096 and self.entropy(data[:MAX_READ]) > 7.5 and path.suffix.lower() not in {".zip", ".gz", ".png", ".jpg", ".jpeg", ".mp3", ".mp4", ".pdf", ".7z", ".rar"}:
            score += 2; reasons.append("+2 entropie très élevée (fichier packé/chiffré ?)")
        return score, reasons

    # ---- analyse d'un dossier ----
    def scan_path(self, root, skip_dirs=()):
        root = Path(root)
        skip = {str(Path(d).resolve()) for d in skip_dirs}
        files = [root] if root.is_file() else []
        if root.is_dir():
            for dp, dn, fn in os.walk(root):
                dn[:] = [d for d in dn if str((Path(dp) / d).resolve()) not in skip]
                files += [Path(dp) / f for f in fn]
        for f in files:
            if f.is_symlink(): continue
            yield self.scan_file(f)
