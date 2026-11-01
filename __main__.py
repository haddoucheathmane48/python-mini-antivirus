import argparse, json, sys, time
from pathlib import Path
from . import __version__
from .scanner import Scanner
from .quarantine import Quarantine
from .process_guard import scan_processes
from .monitor import watch

RED, YEL, GRN, END = "\033[91m", "\033[93m", "\033[92m", "\033[0m"
COL = {"INFECTED": RED, "SUSPICIOUS": YEL, "CLEAN": GRN, "ERROR": YEL}

def main(argv=None):
    ap = argparse.ArgumentParser(prog="miniav", description=f"MiniAV {__version__} – antivirus éducatif")
    ap.add_argument("--quarantine-dir", default="quarantine")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="analyser un fichier ou un dossier")
    s.add_argument("path"); s.add_argument("--quarantine", action="store_true", help="mettre les INFECTED en quarantaine")
    s.add_argument("--quarantine-suspicious", action="store_true", help="inclure aussi les SUSPICIOUS")
    s.add_argument("--json", help="écrire un rapport JSON"); s.add_argument("--verbose", "-v", action="store_true")
    p = sub.add_parser("procs", help="analyser les processus en cours"); p.add_argument("--kill", action="store_true")
    w = sub.add_parser("watch", help="surveiller un dossier"); w.add_argument("path"); w.add_argument("--quarantine", action="store_true")
    q = sub.add_parser("quarantine", help="gérer la quarantaine"); q.add_argument("action", choices=["list", "restore", "delete"]); q.add_argument("id", nargs="?")
    a = ap.parse_args(argv)
    sc, qr = Scanner(), Quarantine(a.quarantine_dir)

    if a.cmd == "scan":
        results, bad, t0 = [], 0, time.time()
        for d in sc.scan_path(a.path, skip_dirs=[a.quarantine_dir]):
            results.append(d.to_dict())
            if d.status in ("INFECTED", "SUSPICIOUS"):
                bad += 1
                print(f"{COL[d.status]}[{d.status}]{END} {d.path}  →  {d.threat} (score {d.score}) {'; '.join(d.reasons)}")
                if a.quarantine and (d.status == "INFECTED" or a.quarantine_suspicious):
                    print(f"    ↳ mis en quarantaine (id {qr.add(d.path, d.threat, d.sha256)})")
            elif a.verbose: print(f"{COL[d.status]}[{d.status}]{END} {d.path}")
        print(f"\n{len(results)} fichiers analysés en {time.time()-t0:.2f}s, {bad} menace(s).")
        if a.json: Path(a.json).write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding="utf-8")
        return 1 if bad else 0
    if a.cmd == "procs":
        th = scan_processes(sc, kill=a.kill)
        for t in th: print(f"{RED}[PROCESSUS MALVEILLANT]{END} pid={t.pid} {t.name} → {t.threat} ({t.file}) {'ARRÊTÉ' if t.killed else ''} {t.note}")
        print(f"{len(th)} processus malveillant(s)."); return 1 if th else 0
    if a.cmd == "watch":
        print(f"Surveillance de {a.path} (Ctrl+C pour arrêter)")
        def on(d):
            print(f"{COL[d.status]}[{d.status}]{END} {d.path} → {d.threat}")
            if a.quarantine and d.status == "INFECTED": print("   ↳ quarantaine", qr.add(d.path, d.threat, d.sha256))
        try: watch(sc, a.path, on, skip_dirs=[a.quarantine_dir])
        except KeyboardInterrupt: print("Arrêt.")
        return 0
    if a.cmd == "quarantine":
        if a.action == "list":
            for m in qr.list(): print(f"{m['id']}  {m['date']}  {m['threat']:22s} {m['original_path']}")
        elif a.action == "restore": print("Restauré :", qr.restore(a.id))
        else: qr.delete(a.id); print("Supprimé définitivement.")
        return 0

if __name__ == "__main__":
    sys.exit(main())
