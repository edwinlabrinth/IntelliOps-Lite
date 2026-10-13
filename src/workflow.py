from src import analyse, extraction, notification
from src.contrat import RUNBOOKS

def _traiter(evt, deja_vus, journal, base):
    if analyse.est_doublon(evt, deja_vus):
        return None
        
    ana = analyse.analyser(evt, base)
    notif = notification.notifier(evt, ana, journal)
    
    return {"evenement": evt, "analyse": ana, "notification": notif}

def traiter_docker(ligne, numero, deja_vus, journal, base=RUNBOOKS):
    evt = extraction.normaliser_docker(ligne, numero)
    return _traiter(evt, deja_vus, journal, base)

def traiter_trivy(rapport, numero, deja_vus, journal, base=RUNBOOKS):
    evt = extraction.normaliser_trivy(rapport, numero)
    return _traiter(evt, deja_vus, journal, base)