import unittest

from src.analyse import analyser, classer, est_doublon, rechercher_runbook
from src.contrat import RUNBOOKS, Evenement


def evt(event_type="LOG", severity="LOW", message="ok", component="backend",
        source="DOCKER"):
    return Evenement("EVT-00001", "2026-10-05T10:00:00Z", source, component,
                     "production", event_type, severity, message)


class TestAnalyse(unittest.TestCase):

    # --- est_doublon ---
    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(message="a"), vus))
        self.assertTrue(est_doublon(evt(message="a"), vus))

    def test_pas_doublon_si_message_different(self):
        vus = set()
        est_doublon(evt(message="a"), vus)
        self.assertFalse(est_doublon(evt(message="b"), vus))

    # --- rechercher_runbook ---
    def test_runbook_trouve(self):
        e = evt(message="OOMKilled restarts=14")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_insensible_a_la_casse(self):
        e = evt(message="TIMEOUT sur la base")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["timeout"])

    def test_runbook_premier_mot_cle(self):
        e = evt(message="timeout puis OOMKilled")
        self.assertEqual(rechercher_runbook(e, RUNBOOKS), RUNBOOKS["OOMKilled"])

    def test_runbook_absent(self):
        self.assertIsNone(rechercher_runbook(evt(message="tout va bien"), RUNBOOKS))

    # --- classer ---
    def test_classer_redemarrages(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_seuil_10(self):
        e = evt("CONTAINER_RESTART", "LOW", "restarts=10")
        self.assertEqual(classer(e), "CRITICAL")

    def test_classer_redemarrages_faibles(self):
        e = evt("CONTAINER_RESTART", "HIGH", "restarts=3")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_vulnerabilite_critique(self):
        e = evt("VULNERABILITY", "CRITICAL", "CVE-2026-1234", source="TRIVY")
        self.assertEqual(classer(e), "HIGH")

    def test_classer_vulnerabilite_non_critique(self):
        e = evt("VULNERABILITY", "MEDIUM", "CVE-2026-1234", source="TRIVY")
        self.assertEqual(classer(e), "MEDIUM")

    def test_classer_par_defaut(self):
        self.assertEqual(classer(evt("LOG", "LOW")), "LOW")

    # --- analyser ---
    def test_analyser_redemarrage(self):
        e = evt("CONTAINER_RESTART", "HIGH", "OOMKilled restarts=14")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.event_id, "EVT-00001")
        self.assertEqual(a.criticite, "CRITICAL")
        self.assertEqual(a.cause_probable, RUNBOOKS["OOMKilled"])
        self.assertEqual(a.action_recommandee, "Redémarrer backend")
        self.assertTrue(a.sensible)
        self.assertEqual(a.sources, ["DOCKER"])
        self.assertEqual(e.status, "ANALYSED")

    def test_analyser_vulnerabilite(self):
        e = evt("VULNERABILITY", "CRITICAL",
                "Vulnérabilité CVE-2026-1234 détectée dans lib 1.2.3",
                source="TRIVY")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.criticite, "HIGH")
        self.assertEqual(a.action_recommandee, "Mettre à jour la dépendance")
        self.assertEqual(a.cause_probable, RUNBOOKS["CVE"])
        self.assertEqual(a.sources, ["TRIVY"])

    def test_analyser_cause_inconnue_non_sensible(self):
        e = evt("LOG", "MEDIUM", "slow response time=2300ms")
        a = analyser(e, RUNBOOKS)
        self.assertEqual(a.cause_probable,
                         "Cause inconnue : analyse manuelle requise")
        self.assertEqual(a.action_recommandee, "Consulter les logs")
        self.assertFalse(a.sensible)


if __name__ == "__main__":
    unittest.main()
