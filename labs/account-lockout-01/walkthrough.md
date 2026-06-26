# Account-Lockout-01 Walkthrough

## Overview

**False positive.** A legitimate user forgot their password after a 2-week vacation.
All failures came from a single workstation where the user was physically present.

## Key Indicators

- **Single source**: all 5 failures from `DESK-HR-07` only — not distributed spray
- **Slow failure rate**: failures spaced 18–44 seconds apart — human typing speed, not automated
- **User confirmed**: badge access + helpdesk ticket confirm physical presence
- **After vacation**: password change from mandatory rotation is a classic cause
- **Normal resolution**: helpdesk password reset + successful login

## Verdict: False Positive — Close

Reset the account, notify user, close ticket. No investigation needed.
