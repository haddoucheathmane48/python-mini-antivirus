"""Protection en temps (quasi) réel : surveille un dossier et analyse les fichiers nouveaux ou modifiés."""
import time
from pathlib import Path

def watch(scanner, folder, on_detect, interval=1.0, stop=lambda: False, skip_dirs=()):
    folder = Path(folder); seen = {}
    def snapshot():
        for p in folder.rglob("*"):
            if p.is_file() and not any(str(p).startswith(str(Path(d).resolve())) for d in skip_dirs):
                try: yield p, p.stat().st_mtime_ns
                except OSError: pass
    for p, m in snapshot(): seen[p] = m                  # état initial (déjà présent = ignoré)
    while not stop():
        time.sleep(interval)
        for p, m in snapshot():
            if seen.get(p) != m:
                seen[p] = m
                det = scanner.scan_file(p)
                if det.status in ("INFECTED", "SUSPICIOUS"): on_detect(det)
