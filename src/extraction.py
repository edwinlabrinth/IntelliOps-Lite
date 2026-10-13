import re
from src.contrat import Evenement, SEVERITES

def masquer_secrets(texte: str) -> str:
    # Pattern looks for keys (case-insensitive) followed by = or : and capturing the non-whitespace value
    pattern = re.compile(r'(?i)\b(password|passwd|token|secret|api_key)([=:])(\S+)')
    return pattern.sub(r'\1\2[SECRET]', texte)

def normaliser_docker(ligne: str, numero: int, environment: str = "production") -> Evenement:
    parts = ligne.split(maxsplit=4)
    if len(parts) < 5:
        raise ValueError("La ligne doit contenir au moins 5 champs.")
    
    date_str, time_str, niveau, composant, message_brut = parts
    
    event_id = f"EVT-{numero:05d}"
    timestamp = f"{date_str}T{time_str}Z"
    source = "DOCKER"
    event_type = "CONTAINER_RESTART" if "restarts" in message_brut else "LOG"
    
    niveau = niveau.upper()
    if niveau == "ERROR":
        severity = "HIGH"
    elif niveau == "WARN":
        severity = "MEDIUM"
    elif niveau == "INFO":
        severity = "LOW"
    else:
        severity = "LOW"
        
    message = masquer_secrets(message_brut)
    
    return Evenement(
        id=event_id,
        timestamp=timestamp,
        source=source,
        component=composant,
        environment=environment,
        event_type=event_type,
        severity=severity,
        message=message
    )

def normaliser_trivy(rapport: dict, numero: int, environment: str = "production") -> Evenement:
    cles_requises = ["Target", "VulnerabilityID", "PkgName", "InstalledVersion", "Severity", "Timestamp"]
    for cle in cles_requises:
        if cle not in rapport:
            raise ValueError(f"Clé manquante dans le rapport Trivy: {cle}")
            
    event_id = f"EVT-{numero:05d}"
    
    severity = rapport["Severity"].upper()
    if severity not in SEVERITES:
        severity = "LOW"
        
    message = f"Vulnérabilité {rapport['VulnerabilityID']} détectée dans {rapport['PkgName']} {rapport['InstalledVersion']}"
    
    return Evenement(
        id=event_id,
        timestamp=rapport["Timestamp"],
        source="TRIVY",
        component=rapport["Target"],
        environment=environment,
        event_type="VULNERABILITY",
        severity=severity,
        message=message
    )