from src.contrat import Analyse, Evenement, Notification


def choisir_canal(criticite: str) -> str:
    """Choisit le canal de notification en fonction de la criticite."""
    if criticite in ("CRITICAL", "HIGH"):
        return "TEAMS"
    if criticite == "MEDIUM":
        return "EMAIL"
    if criticite == "LOW":
        return "DASHBOARD"
    raise ValueError(f"Criticite inconnue : {criticite}")


def rediger(evt: Evenement, analyse: Analyse) -> str:
    """Redige un message de notification sur 5 lignes."""
    sources = ", ".join(analyse.sources)
    return "\n".join([
        f"[{analyse.criticite}] Service : {evt.component}",
        f"Incident : {evt.message}",
        f"Cause probable : {analyse.cause_probable}",
        f"Action : {analyse.action_recommandee}",
        f"Sources : {sources}",
    ])


def notifier(evt: Evenement, analyse: Analyse, journal: list) -> Notification:
    """Cree la notification, l'ajoute au journal et passe evt a NOTIFIED."""
    notif = Notification(
        event_id=evt.id,
        canal=choisir_canal(analyse.criticite),
        destinataire="equipe-ops",
        message=rediger(evt, analyse),
    )
    journal.append(notif)
    evt.status = "NOTIFIED"
    return notif


def demander_validation(analyse: Analyse, reponse: str) -> bool:
    """Validation humaine : vraie sauf action sensible non approuvee."""
    if not analyse.sensible:
        return True
    return reponse.strip().lower() in ("o", "oui", "y", "yes")
