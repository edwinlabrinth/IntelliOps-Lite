from dataclasses import dataclass 
SEVERITES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] 
# Base documentaire du RAG simplifié : mot-clé -> procédure 
RUNBOOKS = { 
 "OOMKilled": "Limite mémoire : augmenter la limite du conteneur "  "ou corriger la fuite mémoire.", 
 "CVE": "Vulnérabilité : mettre à jour la dépendance " 
 "vers une version corrigée.", 
 "timeout": "Timeout : vérifier la base de données et le réseau.", } 
@dataclass 
class Evenement: 
 id: str 
 timestamp: str 
 source: str 
 component: str 
 environment: str 
 event_type: str 
 severity: str 
 message: str 
 status: str = "NEW" # NEW -> ANALYSED -> NOTIFIED 
@dataclass 
class Analyse: 
 event_id: str 
 criticite: str 
 cause_probable: str 
 action_recommandee: str 
 sensible: bool 
 sources: list 
@dataclass 
class Notification: 
 event_id: str 
 canal: str 
 destinataire: str 
 message: str
