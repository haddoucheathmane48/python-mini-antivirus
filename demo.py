"""Démo complète : crée des échantillons, analyse, met en quarantaine, restaure, puis détecte et TUE un faux processus."""
import subprocess, sys, tempfile, time
from pathlib import Path
from miniav.scanner import Scanner
from miniav.quarantine import Quarantine
from miniav.process_guard import scan_processes
from tests.make_samples import make, make_fake_malware_script

def titre(t): print(f"\n{'='*70}\n{t}\n{'='*70}")

with tempfile.TemporaryDirectory() as tmp:
    sc, qr = Scanner(), Quarantine(Path(tmp) / "quarantine")
    samples = make(Path(tmp) / "samples")

    titre("1) ANALYSE DU DOSSIER D'ÉCHANTILLONS")
    res = list(sc.scan_path(samples))
    for d in sorted(res, key=lambda x: x.path):
        icon = {"INFECTED": "🦠", "SUSPICIOUS": "⚠️ ", "CLEAN": "✅", "ERROR": "❌"}[d.status]
        print(f"{icon} {d.status:10s} {Path(d.path).name:26s} {d.threat:22s} {'; '.join(d.reasons)}")
    n = {s: sum(r.status == s for r in res) for s in ("INFECTED", "SUSPICIOUS", "CLEAN")}
    print(f"\nRésumé : {n}")

    titre("2) QUARANTAINE DES MENACES CERTAINES")
    for d in res:
        if d.status == "INFECTED": print(f"quarantaine → {Path(d.path).name} (id {qr.add(d.path, d.threat, d.sha256)})")
    print("Fichiers restants infectés ?", sum(r.status == "INFECTED" for r in sc.scan_path(samples)))
    print("En quarantaine :", len(qr.list()))

    titre("3) RESTAURATION D'UN FICHIER (faux positif)")
    first = qr.list()[0]; print("restauré :", qr.restore(first["id"]).name)

    titre("4) DÉTECTION ET ARRÊT D'UN PROCESSUS MALVEILLANT (simulé)")
    script = make_fake_malware_script(tmp)
    proc = subprocess.Popen([sys.executable, str(script)]); time.sleep(0.7)
    print(f"faux malware lancé : pid={proc.pid}")
    for t in scan_processes(sc, kill=True):
        print(f"🦠 processus {t.pid} ({t.name}) → {t.threat} | arrêté : {t.killed} {t.note}")
    time.sleep(0.5); print("processus toujours en vie ?", proc.poll() is None)
