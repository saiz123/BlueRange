# Privilege-Escalation-01 Walkthrough

## Overview

**True positive.** Developer `devuser` exploited a sudo misconfiguration allowing
passwordless `vim` execution. Using a GTFOBins technique, they escaped to a root shell,
created a backdoor account, and granted external access.

## Attack Chain

1. SSH login as `devuser` from `10.0.5.88`
2. `sudo vim /etc/hosts` — vim allowed via NOPASSWD in sudoers (**misconfiguration**)
3. Inside vim: `:!/bin/bash` — shell escape to root (**T1548.003**)
4. `useradd backdoor-user` + set password + `usermod -aG sudo` (**T1136.001**)
5. `cat /etc/shadow > /tmp/.shadow_backup` — credential theft
6. External login as `backdoor-user` from **185.233.102.47** — external actor confirmed

## MITRE Mapping

- **T1548.003**: Sudo abuse — vim NOPASSWD misconfiguration
- **T1059.004**: Unix shell escape
- **T1136.001**: Local account creation (backdoor-user)

## Verdict: True Positive — Escalate

Remove `backdoor-user`, fix sudoers (`vim` must require password), rotate `/etc/shadow`,
investigate `devuser` intent, block `185.233.102.47` at firewall. Escalate to IR.
