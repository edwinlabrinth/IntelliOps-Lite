import unittest

from src.contrat import Analyse, Evenement
from src.notification import (choisir_canal, demander_validation, notifier,
                              rediger)


def exemple(sensible=True, criticite="CRITICAL"):
    e = Evenement("EVT-00125", "2026-10-05T10:02:11Z", "DOCKER", "backend",
                  "production", "CONTAINER_RESTART", "HIGH",
                  "OOMKilled restarts=14")
    a = Analyse("EVT-00125", criticite, "Limite mémoire", "Redémarrer backend",
                sensible, ["DOCKER"])
    return e, a


class TestNotification(unittest.TestCase):
    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "TEAMS")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

    def test_canal_inconnu_leve_valueerror(self):
        with self.assertRaises(ValueError):
            choisir_canal("INCONNU")

    def test_validation(self):
        _, a = exemple()
        self.assertTrue(demander_validation(a, " OUI "))
        self.assertFalse(demander_validation(a, "n"))

    def test_validation_accepte_o_oui_y_yes(self):
        _, a = exemple()
        self.assertTrue(demander_validation(a, " o "))
        self.assertTrue(demander_validation(a, "oui"))
        self.assertTrue(demander_validation(a, "YES"))
        self.assertTrue(demander_validation(a, "y"))
        self.assertFalse(demander_validation(a, "non"))

    def test_validation_action_non_sensible_toujours_vrai(self):
        _, a = exemple(sensible=False)
        self.assertTrue(demander_validation(a, "n"))

    def test_rediger_5_lignes(self):
        e, a = exemple()
        attendu = (
            "[CRITICAL] Service : backend\n"
            "Incident : OOMKilled restarts=14\n"
            "Cause probable : Limite mémoire\n"
            "Action : Redémarrer backend\n"
            "Sources : DOCKER"
        )
        self.assertEqual(rediger(e, a), attendu)

    def test_notifier_cree_et_historise(self):
        e, a = exemple()
        journal = []
        notif = notifier(e, a, journal)
        self.assertEqual(notif.event_id, "EVT-00125")
        self.assertEqual(notif.canal, "TEAMS")
        self.assertEqual(notif.destinataire, "equipe-ops")
        self.assertEqual(notif.message, rediger(e, a))
        self.assertEqual(len(journal), 1)          # historise
        self.assertEqual(e.status, "NOTIFIED")      # passe a NOTIFIED

    def test_notifier_canal_email_pour_medium(self):
        e, a = exemple(criticite="MEDIUM")
        notif = notifier(e, a, [])
        self.assertEqual(notif.canal, "EMAIL")


if __name__ == "__main__":
    unittest.main()
