import subprocess, sys, tempfile, time, unittest
from pathlib import Path
from miniav.scanner import Scanner
from miniav.quarantine import Quarantine
from miniav.process_guard import scan_processes
from tests.make_samples import make, make_fake_malware_script

class TestMiniAV(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.root = Path(self.tmp.name)
        self.sc = Scanner(); self.samples = make(self.root / "s")
    def tearDown(self): self.tmp.cleanup()
    def status(self, name): return self.sc.scan_file(self.samples / name)

    def test_eicar_detected(self):
        d = self.status("eicar_test.com"); self.assertEqual((d.status, d.threat), ("INFECTED", "Test.EICAR"))
    def test_signature_markers(self):
        for f, t in [("trojan_dropper_sim.txt", "Sim.Trojan.Dropper"), ("RANSOM_NOTE_sim.txt", "Sim.Ransomware.Note"), ("worm_sim.txt", "Sim.Worm.Spreader")]:
            self.assertEqual(self.status(f).threat, t)
    def test_heuristics_catch_suspicious_scripts(self):
        self.assertEqual(self.status("script_suspect.ps1").status, "SUSPICIOUS")
        self.assertEqual(self.status("droper.sh").status, "SUSPICIOUS")
    def test_disguised_binaries(self):
        self.assertEqual(self.status("facture.pdf.exe").status, "SUSPICIOUS")
        self.assertEqual(self.status("photo.jpg").status, "SUSPICIOUS")
    def test_no_false_positive_on_clean_files(self):
        for f in ("notes.txt", "rapport.csv", "image_ok.png", "script_ok.py"):
            self.assertEqual(self.status(f).status, "CLEAN", f)
    def test_quarantine_and_restore(self):
        q = Quarantine(self.root / "q"); f = self.samples / "eicar_test.com"; original = f.read_bytes()
        qid = q.add(f, "Test.EICAR"); self.assertFalse(f.exists())
        self.assertNotEqual((q.dir / f"{qid}.quarantine").read_bytes(), original)       # contenu illisible
        self.assertEqual(self.sc.scan_file(q.dir / f"{qid}.quarantine").status, "CLEAN")  # plus détectable (XOR)
        q.restore(qid); self.assertEqual(f.read_bytes(), original)
    def test_process_killed(self):
        script = make_fake_malware_script(self.root)
        proc = subprocess.Popen([sys.executable, str(script)]); time.sleep(0.7)
        try:
            threats = scan_processes(self.sc, kill=True)
            self.assertTrue(any(t.pid == proc.pid and t.killed for t in threats))
            proc.wait(timeout=5); self.assertIsNotNone(proc.returncode)
        finally:
            if proc.poll() is None: proc.kill()
    def test_scanner_never_kills_itself(self):
        self.assertFalse(any(t.pid == __import__("os").getpid() for t in scan_processes(self.sc, kill=False)))

if __name__ == "__main__":
    unittest.main(verbosity=2)
