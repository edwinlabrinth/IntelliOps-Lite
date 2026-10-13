import re

from src.contrat import Analyse, Evenement

CAUSE_INCONNUE = "Cause inconnue : analyse manuelle requise"
SEUIL_REDEMARRAGES = 10


def est_doublon(evt: Evenement, deja_vus: set) -> bool:
    cle = (evt.source, evt.component, evt.event_type, evt.message)
    if cle in deja_vus:
        return True
    deja_vus.add(cle)
    return False


def rechercher_runbook(evt: Evenement, base: dict):
    message = evt.message.lower()
    for mot_cle, procedure in base.items():
        if mot_cle.lower() in message:
            return procedure
    return None


def _nombre_redemarrages(message: str) -> int:
    trouve = re.search(r"restarts=(\d+)", message)
    return int(trouve.group(1)) if trouve else 0


def classer(evt: Evenement) -> str:
    if evt.event_type == "CONTAINER_RESTART":
         if _nombre_redemarrages(evt.message) > 100:
            return "CRITICAL"
         return "MEDIUM"
    if evt.event_type == "VULNERABILITY" and evt.severity == "CRITICAL":
        return "HIGH"
    return evt.severity


def _action(evt: Evenement) -> str:
    if evt.event_type == "CONTAINER_RESTART":
        return f"Redémarrer {evt.component}"
    if evt.event_type == "VULNERABILITY":
        return "Mettre à jour la dépendance"
    return "Consulter les logs"


def analyser(evt: Evenement, base: dict) -> Analyse:
    criticite = classer(evt)
    cause = rechercher_runbook(evt, base) or CAUSE_INCONNUE
    evt.status = "ANALYSED"
    return Analyse(
        event_id=evt.id,
        criticite=criticite,
        cause_probable=cause,
        action_recommandee=_action(evt),
        sensible=criticite in ("HIGH", "CRITICAL"),
        sources=[evt.source],
    )
