"""Surveillance des processus : si un processus exécute un fichier infecté, on le TERMINE."""
import os
from dataclasses import dataclass
from pathlib import Path
import psutil

@dataclass
class ProcessThreat:
    pid: int
    name: str
    file: str
    threat: str
    killed: bool = False
    note: str = ""


def _protected_pids():
    """Ne jamais s'arrêter soi-même ni ses parents (terminal, IDE...)."""
    pids = {os.getpid()}
    try: pids |= {p.pid for p in psutil.Process().parents()}
    except Exception: pass
    return pids


def scan_processes(scanner, kill=False, timeout=3):
    """Analyse l'exécutable et les fichiers passés en argument (scripts) de chaque processus."""
    protected, threats, seen = _protected_pids(), [], {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        info = proc.info
        if info["pid"] in protected or info["pid"] <= 4: continue
        candidates = []
        if info.get("exe"): candidates.append(info["exe"])
        for arg in (info.get("cmdline") or [])[1:]:
            if not arg.startswith("-") and os.path.isfile(arg): candidates.append(arg)
        for fpath in dict.fromkeys(candidates):
            if fpath not in seen:
                try: seen[fpath] = scanner.scan_file(fpath)
                except Exception: continue
            det = seen[fpath]
            if det.status == "INFECTED":                                # processus : on agit seulement sur les menaces CERTAINES
                t = ProcessThreat(info["pid"], info["name"] or "?", fpath, det.threat)
                if kill: _kill(proc, t, timeout)
                threats.append(t); break
    return threats


def _kill(proc, t, timeout):
    try:
        for child in proc.children(recursive=True):                     # d'abord les enfants
            try: child.terminate()
            except psutil.Error: pass
        proc.terminate()                                                # arrêt "poli"
        try: proc.wait(timeout)
        except psutil.TimeoutExpired:
            proc.kill(); proc.wait(timeout); t.note = "kill forcé"      # arrêt forcé
        t.killed = True
    except psutil.AccessDenied: t.note = "accès refusé (droits administrateur requis)"
    except psutil.NoSuchProcess: t.killed = True; t.note = "déjà terminé"
