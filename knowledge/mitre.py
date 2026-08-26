# Catalogo MITRE ATT&CK (enterprise v16) + MITRE ATLAS (AI/LLM) curado.
# Las tecnicas existentes se mantienen; se agregan las novedades de
# ATT&CK v16 (cloud, identidad, Linux) y las tecnicas ATLAS para sistemas
# con IA/LLM. `framework` distingue la fuente (att&ck | atlas).

TECHNIQUES: dict[str, dict] = {
    # ------------------------------------------------------------------
    # ATT&CK enterprise (reconnaissance / initial access)
    # ------------------------------------------------------------------
    "T1595": {"name": "Active Scanning", "tactic": "reconnaissance", "framework": "att&ck"},
    "T1592": {"name": "Gather Victim Host Information", "tactic": "reconnaissance", "framework": "att&ck"},
    "T1590": {"name": "Gather Victim Network Information", "tactic": "reconnaissance", "framework": "att&ck"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "initial_access", "framework": "att&ck"},
    "T1133": {"name": "External Remote Services", "tactic": "initial_access", "framework": "att&ck"},
    "T1078": {"name": "Valid Accounts", "tactic": "initial_access", "framework": "att&ck"},
    "T1566": {"name": "Phishing", "tactic": "initial_access", "framework": "att&ck"},
    "T1098": {"name": "Account Manipulation", "tactic": "persistence", "framework": "att&ck"},
    # ------------------------------------------------------------------
    # execution / persistence / privilege escalation
    # ------------------------------------------------------------------
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "execution", "framework": "att&ck"},
    "T1204": {"name": "User Execution", "tactic": "execution", "framework": "att&ck"},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "execution", "framework": "att&ck"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "command_and_control", "framework": "att&ck"},
    "T1027": {"name": "Obfuscated Files or Information", "tactic": "defense_evasion", "framework": "att&ck"},
    "T1574": {"name": "Hijack Execution Flow", "tactic": "persistence", "framework": "att&ck"},
    "T1546": {"name": "Event Triggered Execution (incl. udev rules T1546.017)", "tactic": "persistence", "framework": "att&ck"},
    "T1556": {"name": "Modify Authentication Process (incl. Conditional Access T1556.009)", "tactic": "credential_access", "framework": "att&ck"},
    "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "privilege_escalation", "framework": "att&ck"},
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "privilege_escalation", "framework": "att&ck"},
    # ------------------------------------------------------------------
    # discovery / lateral movement / collection
    # ------------------------------------------------------------------
    "T1082": {"name": "System Information Discovery", "tactic": "discovery", "framework": "att&ck"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "discovery", "framework": "att&ck"},
    "T1046": {"name": "Network Service Discovery", "tactic": "discovery", "framework": "att&ck"},
    "T1018": {"name": "Remote System Discovery", "tactic": "discovery", "framework": "att&ck"},
    "T1482": {"name": "Domain Trust Discovery", "tactic": "discovery", "framework": "att&ck"},
    "T1021": {"name": "Remote Services", "tactic": "lateral_movement", "framework": "att&ck"},
    "T1550": {"name": "Use Alternate Authentication Material", "tactic": "lateral_movement", "framework": "att&ck"},
    "T1570": {"name": "Lateral Tool Transfer", "tactic": "lateral_movement", "framework": "att&ck"},
    "T1005": {"name": "Data from Local System", "tactic": "collection", "framework": "att&ck"},
    "T1213": {"name": "Data from Information Repositories (incl. Messaging T1213.005)", "tactic": "collection", "framework": "att&ck"},
    # ------------------------------------------------------------------
    # credential access / exfiltration / impact / cloud
    # ------------------------------------------------------------------
    "T1003": {"name": "OS Credential Dumping", "tactic": "credential_access", "framework": "att&ck"},
    "T1555": {"name": "Credentials from Password Stores", "tactic": "credential_access", "framework": "att&ck"},
    "T1558": {"name": "Steal or Forge Kerberos Tickets (incl. ccache T1558.005)", "tactic": "credential_access", "framework": "att&ck"},
    "T1110": {"name": "Brute Force", "tactic": "credential_access", "framework": "att&ck"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "exfiltration", "framework": "att&ck"},
    "T1485": {"name": "Data Destruction", "tactic": "impact", "framework": "att&ck"},
    "T1486": {"name": "Data Encrypted for Impact (ransomware)", "tactic": "impact", "framework": "att&ck"},
    "T1530": {"name": "Data from Cloud Storage", "tactic": "collection", "framework": "att&ck"},
    "T1666": {"name": "Modify Cloud Resource Hierarchy", "tactic": "defense_evasion", "framework": "att&ck"},
    "T1496": {"name": "Resource Hijacking (incl. Cloud Service Hijacking T1496.004 / LLMJacking)", "tactic": "impact", "framework": "att&ck"},
    # ------------------------------------------------------------------
    # MITRE ATLAS: sistemas con IA / LLM
    # ------------------------------------------------------------------
    "AML.T0051": {"name": "LLM Prompt Injection", "tactic": "initial_access", "framework": "atlas"},
    "AML.T0054": {"name": "Indirect Prompt Injection (via RAG/documentos)", "tactic": "ai_attack_staging", "framework": "atlas"},
    "AML.T0043": {"name": "Craft Adversarial Data (jailbreaks, encoding)", "tactic": "ai_attack_staging", "framework": "atlas"},
    "AML.T0024": {"name": "Exfiltration via AI Inference API (model/protocol theft)", "tactic": "exfiltration", "framework": "atlas"},
    "AML.T0034": {"name": "Cost Harvesting (denial of wallet, token abuse)", "tactic": "impact", "framework": "atlas"},
    "AML.T0020": {"name": "Poison Training Data", "tactic": "ai_attack_staging", "framework": "atlas"},
    "AML.T0048": {"name": "Compromise ML Software Supply Chain", "tactic": "initial_access", "framework": "atlas"},
    "AML.T0070": {"name": "Privilege Escalation via Prompt Injection (excessive agency)", "tactic": "privilege_escalation", "framework": "atlas"},
}

PHASE_TACTICS: dict[str, list[str]] = {
    # red
    "recon": ["reconnaissance"],
    "enumeration": ["discovery"],
    "modeling": [],
    "hypothesis": ["initial_access", "execution", "privilege_escalation", "lateral_movement"],
    "validation": ["initial_access", "execution", "privilege_escalation", "lateral_movement"],
    "impact": ["collection", "impact"],
    "evidence": ["collection"],
    "report": [],
    # blue
    "detect": [
        "initial_access", "execution", "persistence", "privilege_escalation",
        "lateral_movement", "command_and_control", "ai_attack_staging",
    ],
    "triage": [
        "initial_access", "execution", "persistence", "privilege_escalation",
        "lateral_movement", "command_and_control", "ai_attack_staging",
    ],
    "investigate": ["collection", "exfiltration", "impact"],
    # purple
    "plan": ["reconnaissance", "discovery"],
    "emulate": [
        "initial_access", "execution", "privilege_escalation",
        "lateral_movement", "command_and_control", "ai_attack_staging",
    ],
    "coverage": [],
    "improve": ["reconnaissance", "discovery"],
}
