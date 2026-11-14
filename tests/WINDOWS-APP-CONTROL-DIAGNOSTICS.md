# Read-only investigation: Windows HIP launch blocked by Code Integrity

**Status:** Final-head RX 7900 XTX binary built and passed static
dependency/provenance checks, but its executable was blocked before GPU
inference. Older df4b193 bundle has 33 physical PASSes. Source parity and
successful Windows build do not turn a newly blocked binary into physical PASS.

## Events and root-cause evidence

Windows Code Integrity event IDs are distinct:

- 3076 = App Control audit-only would-block; NOT proof of enforcement.
- 3077 = enforced App Control policy block.
- 3089 = signing details; correlate by System Correlation ActivityID.
- 3033 = signature or Code Integrity Guard issue, possibly unrelated to
  App Control; evaluate with correlated events, not by itself.
- 3099 = policy load and activation information.

A Smart App Control Evaluation label alone does NOT prove that SAC
Evaluation blocked the executable. Match the enforcing PolicyId of an
actual 3077 to the active policy name and enforcement state from CiTool.

Official Microsoft references:

- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations
- https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/test-your-app-with-smart-app-control
- https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/appcontrol-debugging-and-troubleshooting

## Read-only capture on the affected Windows machine

After reproducing the block, run:

    pwsh -File .\tests\collect-windows-app-control-evidence.ps1 -Hours 12 -OutputDirectory C:\dev\yue2-hip-nightly\qa\codeintegrity

This captures:

1. Read-only CiTool active policy list into active-policy-list.txt.
2. Relevant CodeIntegrity Operational events including correlated 3089
   signing records, event IDs, timestamps and ActivityIDs.
3. Original event XML locally for the signing-level and PolicyId analysis.

**Do not automatically publish raw XML:** it may include usernames,
file paths and other device security metadata. Review and redact before
sharing; preserve the original locally.

## Root-cause decision rules

- 3077 + correlated 3089 + identified active PolicyId: report ENFORCED
  APP CONTROL block with the actual enforcing policy, not merely SAC.
- 3076 without 3077: report AUDIT, and investigate other launch failures.
- 3033 without 3077: examine signing/CIG conditions; no ungrounded WDAC claim.
- No matching events or conflicting evidence: UNKNOWN / INCONCLUSIVE.

Exit 4551 in the prior report is only a suspected external block until the
active policy and event XML are correlated. A generic 126 code could be a
genuine missing-DLL error and MUST NOT be classified as policy blocking.

Maintain all security protections; never switch off SAC, alter active
policies or weaken driver validation for test success.

When the intact engine is externally BLOCKED, all five negative checks
must be BLOCKED (or NOT RUN, depending on prerequisite failure), never
PASS. This is an evidence-classification fix, NOT a new physical GPU PASS.
