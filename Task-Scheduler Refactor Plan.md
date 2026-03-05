Plan: Resume Packet for Task Scheduler Refactor
Goal: Resume and complete the current script modification from WinRM-only transport to Task Scheduler + SMB staging, without rewriting the whole script.

1) Current confirmed findings (do not re-test unless environment changed)
WinRM remoting is blocked for this operator; New-PSSession path is not usable.
Network ports 445 and 135 are reachable.
sc \\host query returns access denied (remote SCM rights not sufficient).
dir \\HOST\c$ works (admin share access confirmed).
schtasks /S HOST /Query works.
schtasks /S HOST /Create works.
Running install via Task Scheduler as SYSTEM works as a transport path.
PsExec transport reached installer execution but returned MSI error 1603 (installer-level issue, not transport-level deny).
2) Evidence already collected
MSI verbose log indicates product is already installed/maintenance mode and pending reboot flag appears (MsiSystemRebootPending=1), so 1603 may be package state/context-related.
Task Scheduler + local staged MSI (C:\Temp\...) is viable.
3) Scope for implementation (when we resume)
Keep existing script architecture and reporting.
Replace/augment WinRM transport sections with Task Scheduler + SMB.
Preserve: parsing, sanitization, retry model, summary tables, batch mutation, logging format.
Update documentation to reflect new transport requirements and behavior.
4) Refactor phases to execute
Add transport mode model (WinRM optional, Task Scheduler primary in restricted environments).
Update machine readiness validation to support SMB + Task Scheduler checks.
Replace canary authorization check internals for Task Scheduler mode.
Add SMB staging helpers (ensure remote temp, copy with retry).
Add Scheduled Task execution helpers (create/run/poll/result/log collection/cleanup).
Route sequential and parallel deployment through a single transport-agnostic executor.
Keep reboot evaluation contract; degrade gracefully if deep remote probe is unavailable.
Update docs and testing checklist.
5) Required inputs to provide before restart
Preferred default transport: Task Scheduler only, or dual transport.
Final remote staging path (for example, C:\Temp).
Task naming convention (unique per host/run) and cleanup policy.
Whether to run tasks as SYSTEM always, or configurable account.
Retention policy for remote MSI and log files on success/failure.
Pilot hostnames for validation and a representative mixed batch file.
6) Acceptance criteria for completion
Single-host deployment succeeds end-to-end using Task Scheduler + SMB.
Batch mode supports throttling, retries, and failed-machine-only reruns.
Exit code mapping and summary table remain consistent.
Source batch file success-commenting still works.
No WinRM dependency required in Task Scheduler mode.
README and AI briefing updated to match behavior.
7) Resume prompt to paste later
Please resume the Task Scheduler transport refactor for this repository using the prior discovery state. Treat WinRM as unavailable for my account. Keep the existing script structure and implement transport-layer changes only: SMB staging + scheduled task execution, with preserved retries, logging, summaries, and batch behavior. Then update documentation and run verification for single-host and mixed-batch scenarios.

