from __future__ import annotations

# Catalogo curado de reglas de deteccion (estilo Sigma simplificado).
# Se evaluan SOLO contra telemetria ingerida (nunca se ejecuta nada en el host).
# Cada regla: id estable, patrones sobre command/stdout/fields del evento
# ingerido, tecnicas MITRE asociadas y fuentes de datos tipicas.

RULES: list[dict] = [
    {
        "id": "SIGMA-0001",
        "name": "Credential Dump (LSASS access)",
        "description": "Acceso a LSASS o herramientas de volcado de credenciales",
        "severity": "critical",
        "technique_ids": ["T1003"],
        "data_sources": ["process", "command_line"],
        "patterns": {
            "command": [r"mimikatz", r"sekurlsa", r"procdump.*lsass", r"lsass\.exe.*dump"],
            "stdout": [r"sekurlsa::logonpasswords", r"lsass\.dmp", r"mimikatz"],
        },
    },
    {
        "id": "SIGMA-0002",
        "name": "Webshell Upload / Web Shell Activity",
        "description": "Subida o ejecucion de webshell en aplicacion web",
        "severity": "high",
        "technique_ids": ["T1505.003"],
        "data_sources": ["file", "web_server", "process"],
        "patterns": {
            "command": [r"\.php\s+-r", r"cmd\.exe.*\.aspx", r"upload.*\.jsp"],
            "stdout": [r"<\%\s*if", r"webshell", r"cmd=/c|whoami|id\s*;"],
        },
    },
    {
        "id": "SIGMA-0003",
        "name": "Reverse Shell Detected",
        "description": "Conexion reversa a un host externo (bash/nc/powershell)",
        "severity": "critical",
        "technique_ids": ["T1059"],
        "data_sources": ["network", "process", "command_line"],
        "patterns": {
            "command": [r"/dev/tcp/", r"nc\s+[-]?\w*\s+\d+", r"Invoke-PowerShellTcp", r"bash -i"],
            "stdout": [r"listening on", r"connected!.*127\.0\.0\.1", r"connect to"],
        },
    },
    {
        "id": "SIGMA-0004",
        "name": "C2 Beaconing Pattern",
        "description": "Patron de beacon a infraestructura de comando y control",
        "severity": "high",
        "technique_ids": ["T1071"],
        "data_sources": ["network", "dns"],
        "patterns": {
            "stdout": [r"GET /[a-z0-9]{8,}\.php", r"POST /api/[a-z0-9]{16}", r"beacon", r"sleep \d+"],
            "fields": {"event_type": [r"beacon", r"c2", r"checkin"]},
        },
    },
    {
        "id": "SIGMA-0005",
        "name": "Lateral Movement via Remote Services",
        "description": "Uso de psexec/winrm/wmic para movimiento lateral",
        "severity": "high",
        "technique_ids": ["T1021"],
        "data_sources": ["process", "command_line", "network"],
        "patterns": {
            "command": [r"psexec", r"winrs", r"winrm", r"wmic.*process call create", r"New-PSSession"],
            "stdout": [r"ADMIN\$", r"C\$", r"remote session", r"creating process on"],
        },
    },
    {
        "id": "SIGMA-0006",
        "name": "Port Scan / Reconnaissance Activity",
        "description": "Escaneo de puertos o barrido de red",
        "severity": "medium",
        "technique_ids": ["T1046"],
        "data_sources": ["network", "process"],
        "patterns": {
            "command": [r"nmap\s", r"masscan", r"nc -z", r"zmap"],
            "stdout": [r"open port", r"scan report for", r"\d+ ports scanned"],
        },
    },
    {
        "id": "SIGMA-0007",
        "name": "Privilege Escalation (UAC / EOP)",
        "description": "Abuso de mecanismos de elevacion o bypass de UAC",
        "severity": "high",
        "technique_ids": ["T1548"],
        "data_sources": ["process", "command_line", "registry"],
        "patterns": {
            "command": [r"bypassuac", r"eventvwr\.exe", r"fodhelper", r"computerdefaults", r"sdclt\.exe"],
            "stdout": [r"elevat", r"uac", r"privilege escalation"],
        },
    },
    {
        "id": "SIGMA-0008",
        "name": "Persistence via Scheduled Task",
        "description": "Creacion de tarea programada sospechosa",
        "severity": "medium",
        "technique_ids": ["T1053"],
        "data_sources": ["process", "command_line", "scheduled_task"],
        "patterns": {
            "command": [r"schtasks /create", r"at \d\d:\d\d", r"Register-ScheduledTask"],
            "stdout": [r"SUCCESS: The scheduled task", r"Task Scheduler"],
        },
    },
    {
        "id": "SIGMA-0009",
        "name": "Data Exfiltration Over Network",
        "description": "Transferencia de datos hacia fuera de la red",
        "severity": "high",
        "technique_ids": ["T1041"],
        "data_sources": ["network", "dns", "process"],
        "patterns": {
            "command": [r"curl .* -F ", r"ftp.*put", r"nc .* < /etc", r"tar czf .* base64"],
            "stdout": [r"base64.*[-_A-Za-z0-9]{60,}", r"Exfiltrat", r"upload complete"],
        },
    },
    {
        "id": "SIGMA-0010",
        "name": "Malicious Document / Macro Activity",
        "description": "Ejecucion de macros o documentos maliciosos",
        "severity": "medium",
        "technique_ids": ["T1204"],
        "data_sources": ["process", "file"],
        "patterns": {
            "command": [r"winword.*\.docm", r"powershell.*FromBase64String"],
            "stdout": [r"macro", r"ole_object", r"AutoOpen"],
        },
    },
    {
        "id": "SIGMA-0011",
        "name": "LLM Prompt Injection",
        "description": "Prompt injection directo o indirecto contra sistemas LLM (ATLAS AML.T0051)",
        "severity": "critical",
        "technique_ids": ["AML.T0051", "AML.T0054"],
        "data_sources": ["application_log", "llm_gateway"],
        "patterns": {
            "stdout": [
                r"ignore (all )?(previous|prior) instructions",
                r"system prompt",
                r"disregard.*(rules|instructions)",
                r"jailbreak",
                r"DAN mode",
                r"reveal your (system|base) prompt",
            ],
            "fields": {"event_type": [r"prompt_injection", r"jailbreak", r"pii_extraction"]},
        },
    },
    {
        "id": "SIGMA-0012",
        "name": "LLMJacking / AI Resource Hijacking",
        "description": "Uso no autorizado de workloads GenAI (invoke models, billetera, tokens)",
        "severity": "high",
        "technique_ids": ["T1496", "AML.T0034"],
        "data_sources": ["cloud_audit", "billing", "model_invocation"],
        "patterns": {
            "command": [r"InvokeModel", r"invoke-model", r"bedrock", r"openai.*api"],
            "stdout": [r"InvokeModel", r"model invocation", r"billing alert", r"token.*exceeded", r"cost harvesting"],
            "fields": {"event_type": [r"runinstances", r"getmodelinvocation", r"invokemodel"]},
        },
    },
    {
        "id": "SIGMA-0013",
        "name": "Ransomware / Mass Encryption",
        "description": "Cifrado masivo de archivos o destruccion de datos (T1486/T1485)",
        "severity": "critical",
        "technique_ids": ["T1486", "T1485"],
        "data_sources": ["file", "process", "command_line"],
        "patterns": {
            "command": [r"cipher /e", r"vssadmin delete shadows", r"bcdedit.*recoveryenabled no", r"gpg.*--encrypt.*-r"],
            "stdout": [r"\.locked", r"\.encrypted", r"ransom", r"shadow copies", r"Volume Shadow"],
        },
    },
    {
        "id": "SIGMA-0014",
        "name": "Kerberoasting / Kerberos Ticket Theft",
        "description": "Extraccion de tickets Kerberos (kerberoasting, ccache, AS-REP)",
        "severity": "high",
        "technique_ids": ["T1558"],
        "data_sources": ["process", "command_line", "authentication_log"],
        "patterns": {
            "command": [r"GetUserSPNs", r"GetNPUsers", r"kerberoast", r"Rubeus", r"kirbi"],
            "stdout": [r"krbtgt", r"spn.*hash", r"ticket.*export", r"ccache", r"\$krb5"],
        },
    },
    {
        "id": "SIGMA-0015",
        "name": "Brute Force / Password Spraying",
        "description": "Multiples intentos de autenticacion fallidos contra la misma cuenta",
        "severity": "medium",
        "technique_ids": ["T1110"],
        "data_sources": ["authentication_log", "network"],
        "patterns": {
            "stdout": [r"password incorrect", r"invalid username or password", r"failed logon", r"4625", r"account locked"],
            "fields": {"event_type": [r"logon_failure", r"failed_logon", r"auth_fail"]},
        },
    },
    {
        "id": "SIGMA-0016",
        "name": "Phishing / Credential Harvesting",
        "description": "Envio o deteccion de phishing con harvesting de credenciales",
        "severity": "medium",
        "technique_ids": ["T1566"],
        "data_sources": ["mail", "network", "url"],
        "patterns": {
            "command": [r"swaks", r"evilginx", r"gophish", r"credential harves"],
            "stdout": [r"username.*password", r"phishing", r"evilginx", r"login page.*(captur|harvest)"],
        },
    },
    {
        "id": "SIGMA-0017",
        "name": "Obfuscation / Encoding Evasion",
        "description": "Comandos ofuscados (base64, hex, XOR, encodings)",
        "severity": "medium",
        "technique_ids": ["T1027"],
        "data_sources": ["process", "command_line"],
        "patterns": {
            "command": [r"base64.*-d", r"-enc\s+(Base64|Hex)", r"iex\s*\(.*FromBase64String", r"certutil -decode", r"\\\\x[0-9a-f]{2}\\\\x"],
            "stdout": [r"frombase64string", r"certutil.*decode", r"xored", r"payload.*(encoded|decoded)"],
        },
    },
    {
        "id": "SIGMA-0018",
        "name": "Cloud Account / Policy Abuse",
        "description": "Manipulacion de cuentas, credenciales o politicas en la nube",
        "severity": "high",
        "technique_ids": ["T1098", "T1078", "T1556"],
        "data_sources": ["cloud_audit", "identity_provider"],
        "patterns": {
            "command": [r"createaccesskey", r"add-roleassignment", r"update-conditionalaccess", r"putbucketpolicy", r"attach-user-policy"],
            "stdout": [r"createpolicyversion", r"putbucketpolicy", r"additional credentials", r"conditional access"],
            "fields": {"event_type": [r"createaccesskey", r"putbucketpolicy", r"adduserrole", r"updateconditionalaccess"]},
        },
    },
]
