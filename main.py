import sys
from src.notification import demander_validation
from src.workflow import traiter_docker, traiter_trivy

LIGNES_DOCKER = [
    "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02",
    "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 node=db-02",
    "2026-10-05 10:05:40 WARN frontend slow response password=abc123 time=2300ms",
    "2026-10-05 10:09:00 INFO api health check ok",
]

RAPPORTS_TRIVY = [
    {
        "Target": "backend", 
        "VulnerabilityID": "CVE-2026-1234",
        "PkgName": "lib", 
        "InstalledVersion": "1.2.3", 
        "Severity": "CRITICAL",
        "Timestamp": "2026-10-05T10:07:00Z"
    },
]

def afficher(resultat):
    notif = resultat["notification"]
    ana = resultat["analyse"]
    
    print(f"--- {notif.event_id} -> {notif.canal} ({notif.destinataire})")
    print(notif.message)
    
    if ana.sensible:
        reponse = input("Action sensible. Approuver ? (o/n) : ")
        ok = demander_validation(ana, reponse)
        print("Action", "APPROUVEE" if ok else "REFUSEE", 
              "(simulation : rien n'est exécuté)")
    print()

def main():
    sys.stdout.reconfigure(encoding="utf-8")
    deja_vus, journal = set(), []
    
    entrees = [(traiter_docker, ligne) for ligne in LIGNES_DOCKER]
    entrees += [(traiter_trivy, rapport) for rapport in RAPPORTS_TRIVY]
    
    ignores = 0
    for numero, (traiter, brut) in enumerate(entrees, start=1):
        resultat = traiter(brut, numero, deja_vus, journal)
        if resultat is None:
            ignores += 1
            print(f"--- EVT-{numero:05d} ignoré (doublon)\n")
        else:
            afficher(resultat)
            
    print(f"{len(entrees)} événements reçus, {ignores} doublon(s) ignoré(s), "
          f"{len(journal)} notification(s) envoyée(s).")

if __name__ == "__main__":
    main()