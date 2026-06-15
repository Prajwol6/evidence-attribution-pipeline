# Rules ordered most-specific first; first match wins.
_TECHNIQUE_RULES = [
    (["mimikatz", "lsass", "ntds", "hashdump", "credential dump"],
     "T1003", "OS Credential Dumping"),
    (["password spray"],
     "T1110.003", "Brute Force: Password Spraying"),
    (["brute force", "brute-force", "failed login"],
     "T1110", "Brute Force"),
    (["powershell"],
     "T1059.001", "Command and Scripting Interpreter: PowerShell"),
    (["cmd.exe"],
     "T1059.003", "Command and Scripting Interpreter: Windows Command Shell"),
    (["/bin/bash", "/bin/sh", "unix shell"],
     "T1059.004", "Command and Scripting Interpreter: Unix Shell"),
    (["process inject", "dll inject", "process hollow"],
     "T1055", "Process Injection"),
    (["exfiltrat"],
     "T1041", "Exfiltration Over C2 Channel"),
    (["ftp"],
     "T1048.003", "Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol"),
    (["beacon", "c2", "command and control", "callback"],
     "T1071", "Application Layer Protocol"),
    (["http://", "https://"],
     "T1071.001", "Application Layer Protocol: Web Protocols"),
    (["credential", "password", "passwd", "secret"],
     "T1078", "Valid Accounts"),
    (["ssh"],
     "T1021.004", "Remote Services: SSH"),
    (["rdp", "remote desktop"],
     "T1021.001", "Remote Services: Remote Desktop Protocol"),
    (["smb", "admin share"],
     "T1021.002", "Remote Services: SMB/Windows Admin Shares"),
    (["wget", "curl", "tool download", "ingress tool"],
     "T1105", "Ingress Tool Transfer"),
    (["port scan", "network scan", "nmap"],
     "T1046", "Network Service Scanning"),
    (["host discovery", "ping sweep"],
     "T1018", "Remote System Discovery"),
    (["persistence", "autostart", "registry run", "scheduled task", "crontab"],
     "T1547", "Boot or Logon Autostart Execution"),
    (["log clear", "event log", "cover track", "indicator removal"],
     "T1070", "Indicator Removal"),
    (["base64", "obfuscat", "encod"],
     "T1027", "Obfuscated Files or Information"),
    (["compress", "archive", ".zip", ".rar", ".tar"],
     "T1560", "Archive Collected Data"),
    (["exploit", "vulnerability", "public-facing", "rce"],
     "T1190", "Exploit Public-Facing Application"),
    (["phish"],
     "T1566", "Phishing"),
    (["masquerad"],
     "T1036", "Masquerading"),
    (["systeminfo", "system information", "uname"],
     "T1082", "System Information Discovery"),
    (["file listing", "directory listing"],
     "T1083", "File and Directory Discovery"),
    (["lateral movement", "lateral", "network communication"],
     "T1071", "Application Layer Protocol"),
    (["execution", "execute", "command", "script", "process"],
     "T1059", "Command and Scripting Interpreter"),
]

_FALLBACK_ID = "T1204"
_FALLBACK_NAME = "User Execution"


def map_to_attck(claim: str) -> dict:
    """Return the most relevant MITRE ATT&CK technique for a claim string."""
    lower = claim.lower()
    for keywords, tech_id, tech_name in _TECHNIQUE_RULES:
        if any(kw in lower for kw in keywords):
            return {"id": tech_id, "name": tech_name}
    return {"id": _FALLBACK_ID, "name": _FALLBACK_NAME}
