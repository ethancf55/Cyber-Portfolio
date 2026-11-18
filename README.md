# Ethan Flmeing — Mythos Defense Access application packet
Prepared November 17, 2026. Draft for applicant review; not submitted.

## Recommended application
Apply as Ethan Fleming, an individual, for Cyber Verification Program Defense Access on the account 

## Evidence reviewed
Portfolio: https://github.com/ethancf55/Cyber-Portfolio
Reviewed README at repository commit fdee5b5e8b943ed55a4de104ebfaffb13374c28b.
Permanent evidence link: https://github.com/ethancf55/Cyber-Portfolio/blob/fdee5b5e8b943ed55a4de104ebfaffb13374c28b/README.md

### Carnage Network Traffic Investigation
Applicant-confirmed contribution: Ethan completed the Carnage investigation himself.

The published report documents a defensive training investigation of historical Squirrelwaffle, Qakbot, and Cobalt Strike-associated traffic. It includes a capture SHA-256, packet references, UTC timeline, HTTP/DNS/TLS pivots, beacon-interval analysis, historical indicators, ATT&CK interpretations, and proposed incident-response steps. It explicitly distinguishes observations, scenario details, and attribution from Brad Duncan's source research.

The report documents 26 POST requests with an approximately 25.10-second median interval. These figures were read in the report, not independently recalculated during this application preparation. The report identifies Wireshark, TShark, and VirusTotal in its investigation workflow. No claim is made that payloads were executed or that a live attack was conducted.

Best evidence of: analytical care, traceable investigation reasoning, scope discipline, communication of uncertainty.
Does not establish: original vulnerability discovery, production incident response, independently attributed Cobalt Strike malware, or an employment history.

### Nexus Vortex
Applicant-confirmed contribution: Ethan originated the Nexus Vortex concept, selected its tools and features, and reports that he built the app. This does not specify whether particular development tools or AI assistance were used.

Project URL: https://nexus-vortex.safebison1024.chatgpt.site/
The portfolio describes a personal browser-based project for imported-evidence review, incident reconstruction, file hashing, case notes, and training simulations. It explicitly labels fictional C2/quantum displays and other simulated features, and distinguishes browser functionality from capabilities requiring a local companion.

The portfolio repository contains the README only. Application source and local companion are not included. The live site could not be retrieved using the web reader in this review; functionality has not been independently verified here.

Best evidence of: a relevant project direction and an emphasis on evidence provenance.
Next useful improvement: a small reproducible validation example and, if appropriate, inspectable source with accurate AI-assistance attribution.

## Suggested application responses
These are adaptable drafts, not a transcription of the authenticated application form. Review first-person statements before submission.

### Background / security work
I am Ethan Fleming, an entry-level cybersecurity practitioner in Prosper, Texas, focused on defensive network investigation and evidence-based incident analysis. My public portfolio includes a completed Carnage network-traffic training case study and Nexus Vortex, a personal security-analysis and training web project. I hold an Associate of Arts from Collin College and am studying for CompTIA Security+.

I personally completed the Carnage investigation. My report documents HTTP, DNS, and TLS investigation of a historical capture involving Squirrelwaffle, Qakbot, and Cobalt Strike-associated infrastructure. It provides packet references, a UTC timeline, a capture hash, historical indicators, and recommended escalation steps. I distinguish packet observations from source-research attribution and from actions that would be recommended in a real incident.

I conceived and built Nexus Vortex, including choosing the tools and features. It explores imported-evidence analysis, hashing, investigation notes, and explicitly labelled simulations. My experience is portfolio and training work; I am not representing it as professional SOC employment or production incident response.

### Intended use
I am requesting individual Defense Access for defensive analysis of historical public captures, synthetic log datasets, and code or test environments that I own or am authorized to assess. My proposed work focuses on correlating network evidence, evaluating detection hypotheses, checking incident timelines, and improving the reliability of evidence-handling tools.

I plan to use Claude to compare competing explanations against source evidence, identify unsupported conclusions, and propose regression tests for malformed, duplicate, contradictory, or untrusted records. Outputs would undergo human review before becoming portfolio findings. I would document data provenance, known ground truth, limitations, and attribution.

### Why advanced cyber access
I would like to evaluate Mythos for deeper defensive interpretation of malware-associated network activity and rigorous review of security-analysis logic. My current portfolio provides concrete datasets and workflows for this evaluation. I do not claim that ordinary models have been proven inadequate or that I have documented safeguard blocks; I would provide specific examples if they arise.

My objective is a reproducible assessment of analytical accuracy and evidence integrity, including whether the model preserves uncertainty and avoids treating untrusted records as authoritative. I am requesting the Defense tier appropriate to this scope.

### Evidence links
Public portfolio and Carnage report:
https://github.com/ethancf55/Cyber-Portfolio

Version reviewed for this application:
https://github.com/ethancf55/Cyber-Portfolio/blob/fdee5b5e8b943ed55a4de104ebfaffb13374c28b/README.md

Nexus Vortex:
https://nexus-vortex.safebison1024.chatgpt.site/

### Short version if the form has limited space
I am an independent, entry-level cybersecurity practitioner focused on defensive network investigation and evidence integrity. My public portfolio includes a Carnage packet-analysis training report with capture hash, packet references, UTC timeline, and careful attribution of malware-associated traffic, plus Nexus Vortex, a personal evidence-analysis and security-training web project. I seek individual Defense Access to evaluate historical captures, synthetic logs, and owned code, with human-reviewed findings and reproducible validation. My work is training and project development, not professional SOC employment.
Portfolio: https://github.com/ethancf55/Cyber-Portfolio

## Proposed next project — not completed work
Evidence Integrity Validation for Nexus Vortex.

1. Use a synthetic, non-sensitive fixture with explicit expected outcomes.
2. Test valid and malformed imports, timestamp interpretation, duplicate records, contradictory evidence, source provenance, and inert rendering of untrusted text.
3. Check supported hash outputs against independently calculated reference values.
4. Record actual results, failures, fixes, and regression checks.
5. Publish a concise report with exact app version, fixture, reproduction instructions, and limitations.
6. Describe AI assistance and Ethan's own review accurately.

Suggested metrics: accepted/rejected record counts versus expected counts; duplicate-handling correctness; timeline ordering; provenance preservation; false-positive and false-negative counts on the fixture; reproducibility of exported cases. Do not invent numeric performance targets or achieved results. This project can improve the application evidence, but is not an Anthropic-mandated deliverable or a guarantee of approval.

## Security readiness — not yet verified
Do not attest that a control is active until it has been checked.

| Item | Status / action |
|---|---|
| Correct account and eligible plan/billing | Pending account choice; must be Ethan's if Ethan operates the model |
| Government ID and possible live selfie | Applicant completes privately in official verification flow |
| Google or equivalent identity-provider sign-in | Not checked |
| MFA enabled | Not checked |
| Passkey/security key and no email magic-link use by December 15, 2026 | Not checked; configure phishing-resistant MFA now if possible |
| Individual-only access, no shared sessions | Applicant must accept and maintain |
| Interim API key handling | If used before cutoff: one key, password manager/local secrets store, no sharing/source-code storage, replace at least every seven days |
| Credentials from December 15, 2026 | No static/long-lived API keys; interactive OAuth, workload federation where offered |
| Retention and monitoring | Applicant must understand and accept; no individual ZDR |
| Incident response | Report security incident within 24 hours; suspected breach/misuse within 72 hours |
| Cooperation | Investigate identified abuse within 48 hours, cooperate with remediation, respond to misuse inquiries within seven days |
| Ongoing compliance review | Applicant must be able to supply evidence on request |

Never place passwords, recovery codes, API keys, or identity-document images in this packet or a public repository.

## Remaining applicant facts
1. Which account will Ethan use, and does it have a qualifying plan or billing?
2. Are the required identity-provider login and MFA controls enabled?

Contribution clarification received: Ethan completed Carnage himself and originated the concept, selected tools/features, and reports building Nexus Vortex. Specific assistance should be described if an application field asks about it.

If the form asks about credentials, incident-response history, vulnerability disclosures, or model refusals, answer with actual facts. Do not convert studying Security+ into being certified or a training case into an original discovery.

## Submission and follow-up
Portal: https://portal.anthropic.com/
Select Cyber Verification Program, Apply, individual verification and Defense Access as offered. Complete identity verification privately. Adapt the drafts to the actual form fields, inspect the completed answers, and personally accept accurate security attestations and terms.

The currently published help page lists a two-day target for Defense review, not a guarantee. Pro/Max/Ultra access activates automatically after approval. If rejected, the page permits reapplication after seven days; strengthen evidence first rather than resubmitting an unchanged application.

No application has been submitted, no account settings changed, and no public portfolio changes made in preparing this packet.

## Official references
Checked November 10, 2026:
- Program, eligibility and application: https://support.claude.com/en/articles/14604842-cyber-verification-program
- Security requirements: https://support.claude.com/en/articles/17202708-cyber-verification-program-security-requirements
- Program announcement: https://www.anthropic.com/news/cyber-verification-program

The strongest supported current presentation is a careful, evidence-backed early-career defensive practitioner. Approval is discretionary; neither a Max subscription nor polished wording establishes professional qualifications.
