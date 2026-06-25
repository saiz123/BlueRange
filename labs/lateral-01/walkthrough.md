# Walkthrough: Lateral Movement via WMI

## Attack Timeline

1. **02:30:01** — The malware on WS-DEV-09 (`update-service.exe`) uses `net use` to
   connect to DC01's ADMIN$ share with compromised credentials: `bob.admin / P@ssword2024!`
   (credentials likely dumped from memory or browser store).

2. **02:30:10** — WMI remote execution on DC01: runs `whoami`, `ipconfig`, and
   `net localgroup administrators` — standard post-compromise enumeration.

3. **02:31:15** — WMI process creation on FILE-SRV-01 (10.0.1.20): drops and executes
   the malware payload via base64-encoded PowerShell.

4. **02:33:01** — Same attack on EXEC-DM-01 (the CEO's workstation, 10.0.1.5).

5. **02:44:00** — Malware installs itself as a Windows Service on DC01 with
   `SYSTEM` auto-start. This is domain-level persistence.

## Compromised Hosts
- WS-DEV-09 (patient zero)
- DC01 (domain controller — critical)
- FILE-SRV-01
- EXEC-DM-01 (CEO workstation)

## Compromised Account
`bob.admin` — a domain admin account. This is a critical escalation.

## Verdict
**True Positive — Active lateral movement using domain admin credentials**

**Escalate to L2 IMMEDIATELY** — Domain controller compromise requires incident commander
invocation, not just L2. Potential full domain compromise.

## MITRE
- T1047 (WMI remote execution)
- T1021.002 (ADMIN$ share access)
- T1078 (bob.admin credentials)

## Key Learning Points
- **WMIC /node:** — Remote WMI execution. If you see this in Sysmon, assume lateral movement.
- **WmiPrvSE.exe as parent** — Any process spawned by WmiPrvSE from a remote connection
  is a remote execution attempt.
- **Domain admin compromise** — `bob.admin` has full domain admin rights. Every host in
  the domain is now potentially compromised.
- **DC compromise = game over** — An attacker with code running on the DC can create
  golden tickets, dump all hashes, and own the environment.
