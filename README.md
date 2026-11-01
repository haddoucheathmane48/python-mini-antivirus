# 🛡️ MiniAV : un petit antivirus éducatif en Python

Antivirus minimaliste qui **détecte** les menaces, les met en **quarantaine** et **tue** les processus malveillants.
Projet pédagogique pour comprendre comment fonctionne un antivirus. Il **ne remplace pas** un vrai antivirus (Windows Defender, ClamAV...).

## Fonctionnalités
| Module | Rôle |
|---|---|
| `scanner.py` | Détection par **signatures** (hash SHA-256 + motifs d'octets) puis **heuristiques à score** (chaînes suspectes, double extension, binaire déguisé, entropie élevée) |
| `quarantine.py` | Déplace le fichier, le rend illisible (XOR) et non exécutable ; **restauration** possible (faux positifs) |
| `process_guard.py` | Analyse les processus en cours (exécutable + scripts lancés) et **termine** ceux qui exécutent un fichier infecté (arrêt poli, puis forcé) |
| `monitor.py` | **Protection temps réel** : surveille un dossier et analyse les fichiers nouveaux ou modifiés |
| `__main__.py` | Interface en ligne de commande |

### Deux niveaux de verdict
- 🦠 **INFECTED** : signature connue, menace certaine → quarantaine, processus tué.
- ⚠️ **SUSPICIOUS** : score heuristique ≥ 5 → signalé, **jamais tué automatiquement** (risque de faux positif).

## Installation
```bash
pip install -r requirements.txt     # psutil
```

## Utilisation
```bash
python -m tests.make_samples                       # crée le dossier ./samples (échantillons de test inoffensifs)
python -m miniav scan samples                      # analyser
python -m miniav scan samples --quarantine --json rapport.json
python -m miniav quarantine list
python -m miniav quarantine restore <id>
python -m miniav procs                             # détecter les processus malveillants
python -m miniav procs --kill                      # ... et les arrêter
python -m miniav watch ~/Downloads --quarantine    # protection temps réel
```
Démo complète : `python demo.py` · Tests : `python -m unittest tests.test_miniav -v`

## 🧪 Les « virus » de test (tous inoffensifs)
**Aucun code malveillant n'est dans ce dépôt.** Les échantillons sont de simples fichiers texte contenant des marqueurs, générés à l'exécution :

| Échantillon | Famille simulée | Détection |
|---|---|---|
| `eicar_test.com` | **EICAR** (standard mondial de test des antivirus, inoffensif) | hash + motif |
| `trojan_dropper_sim.txt`, `worm_sim.txt`, `RANSOM_NOTE_sim.txt` | Trojan, ver, rançongiciel (marqueurs texte) | motif |
| `script_suspect.ps1`, `droper.sh` | Scripts avec chaînes typiques (texte, jamais exécutés) | heuristique |
| `facture.pdf.exe`, `photo.jpg` (en-tête `MZ`) | Double extension, exécutable déguisé | heuristique |
| `fake_miner.py` | Faux « mineur » : une boucle qui dort | **processus tué** |

Fichiers sains (`notes.txt`, `rapport.csv`, `image_ok.png`, `script_ok.py`) : aucun faux positif.

### Résultat de la démo
```
🦠 INFECTED   RANSOM_NOTE_sim.txt   Sim.Ransomware.Note   motif connu
🦠 INFECTED   eicar_test.com        Test.EICAR            hash connu
⚠️  SUSPICIOUS facture.pdf.exe       Heur.Suspicious       +5 double extension trompeuse
⚠️  SUSPICIOUS script_suspect.ps1    Heur.Suspicious       +3 PowerShell encodé; +4 Suppression des clichés...
✅ CLEAN      notes.txt
...
Résumé : INFECTED 4 · SUSPICIOUS 4 · CLEAN 4
🦠 processus 121 (python3) → Sim.Miner.Process | arrêté : True
```
> ⚠️ Windows Defender ou un autre antivirus peut **bloquer le fichier EICAR** généré : c'est normal (cela prouve que le test fonctionne). Teste dans un dossier exclu ou une machine virtuelle.

## Limites (à connaître)
- Détection **basée sur des signatures connues** : un malware inconnu, obfusqué ou polymorphe passera.
- Pas de protection noyau, pas d'analyse comportementale ni de mise à jour des signatures.
- Le scan de processus agit sur les fichiers **présents sur disque** ; un malware qui vit seulement en mémoire n'est pas vu.
- Tuer un processus système ou protégé nécessite des droits administrateur (et miniav s'interdit de se tuer lui-même ou ses parents).

## Pistes d'amélioration
- Importer des signatures réelles (base ClamAV, hashes MalwareBazaar) avec des règles **YARA** (`yara-python`).
- Analyse comportementale (connexions réseau suspectes avec `psutil`, création massive de fichiers).
- Détection ML à partir de caractéristiques statiques de fichiers (jeu EMBER).
- Interface graphique (Tkinter ou Streamlit) et service en arrière-plan.
