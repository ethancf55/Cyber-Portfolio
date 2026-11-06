# Ethan Fleming — Cybersecurity Portfolio

## About me

I am an entry-level cybersecurity candidate in Prosper, Texas, pursuing SOC Analyst, MDR Analyst, and security operations opportunities with MSSPs and other security teams. I hold an **Associate of Arts from Collin College** and am **actively studying for CompTIA Security+; I have not yet earned the certification**.

My portfolio focuses on investigating suspicious activity, documenting evidence, explaining uncertainty, and communicating clear next steps. My Carnage training case study demonstrates network-traffic analysis with Wireshark, a UTC investigation timeline, historical indicators, and proposed escalation steps. Nexus Vortex is a personal web project that brings together imported-evidence analysis, file hashing, case notes, and clearly labelled simulations.

I bring writing and customer-service experience, a methodical approach to problem solving, and a willingness to learn through feedback and structured training. I am available for **full-time work, including overnight, evening, weekend, and rotating shifts**, with a preference for remote roles.

These projects demonstrate my learning and project work. They are not claims of professional SOC employment or production incident-response experience.

**Contact:** [ethanflem1@gmail.com](mailto:ethanflem1@gmail.com) · [GitHub profile](https://github.com/ethancf55)

## Featured projects

| Project | Type | What to explore |
| --- | --- | --- |
| [Carnage Network Traffic Investigation](#carnage-network-traffic-investigation) | Completed defensive training case study | Packet evidence, investigation timeline, indicators, and proposed escalation steps |
| [Nexus Vortex](https://nexus-vortex.safebison1024.chatgpt.site/) | Interactive web project with evidence-analysis tools and training simulations | Imported evidence, file hashing, case documentation, and visual investigation workflows |

## Nexus Vortex

**[Open the live project](https://nexus-vortex.safebison1024.chatgpt.site/)**

Nexus Vortex is my personal cyber-operations web project, hosted through ChatGPT Sites. It brings browser-based evidence tools and interactive security-training scenarios into one interface.

### Features in the published web edition

- **Incident reconstruction:** Import supported logs, review accepted and rejected records, inspect source records and timestamp assumptions, and explore findings through a timeline and interactive mesh.
- **Evidence Lab and case notes:** Inspect supplied text/log evidence, review rule-based findings, and save or export investigation notes and case data.
- **File hashing and verification:** Compute SHA-256, SHA-512, and BLAKE3 digests and compare a result against a supplied reference digest.
- **File integrity review:** On supported browsers, select a folder, capture a baseline, and review changes during subsequent scans.
- **Training simulations:** Explore alert-triage exercises, network visualizations, and incident-sequence reconstruction using simulated scenarios.

### Relevance to security work

The project explores evidence provenance, clear investigation records, the distinction between an observation and a conclusion, and presenting technical information in an interactive interface. It complements the packet-analysis case study below.

### Scope and limitations

The public web edition processes selected evidence in the browser. Browser storage and exported cases may contain sensitive information, so use synthetic or sanitized examples for demonstrations.

Training dashboards, scoring, memory views, and the fictional C2/quantum displays are simulations. They do not demonstrate live threat detection, real memory acquisition, or cryptographic decryption. A rule match is a prompt for investigation, not proof of compromise.

Live log collection, account connectors, and scoped network scanning require a separate local companion and are not available just by opening the hosted page. Folder monitoring depends on browser support, permission, and the page remaining active; this is not continuous endpoint protection.

This entry links to the current hosted project. Its application source and local companion are not included in this portfolio repository.

---

# Carnage Network Traffic Investigation

**Analyst:** Ethan Fleming  
**Type:** Defensive training case study  
**Tools:** Wireshark on macOS, VirusTotal for the original investigation, and TShark for packet-reference verification  
**Capture date:** September 24, 2021  
**Skills demonstrated:** HTTP and DNS investigation, TLS metadata review, timeline construction, indicator documentation, and incident escalation reasoning

## Executive summary

The capture shows workstation `10.9.23.102` requesting `documents.zip` from `attirenepal[.]com`, followed by connections to three domains associated with loader delivery in the source research. The host then sends 26 HTTP POST requests to `maldivehost[.]net`, with a median interval of approximately 25.10 seconds. Later traffic includes infrastructure identified by the source researcher as Cobalt Strike, plus a lookup for the public IP-check service `api[.]ipify[.]org`.

Together, the network evidence and source research support treating the workstation as compromised in this training scenario. In a real investigation, I would escalate the findings with the affected host, UTC timeline, and relevant packet references, then recommend containment and collection of endpoint evidence.

This is lab analysis of historical traffic. The response actions below are recommendations; they were not performed on a production environment.

## Scenario and evidence scope

[TryHackMe's Carnage scenario](https://tryhackme.com/room/c2carnage) describes a Bartell Ltd employee opening a Word attachment and enabling content, followed by an endpoint alert. Those user actions come from the scenario, rather than direct observation in this network capture.

The underlying capture and indicator list were published by [Brad Duncan at Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/2021/09/24/index.html) as a Squirrelwaffle infection involving Qakbot and Cobalt Strike. That research describes an email-link-to-ZIP-to-Office-document chain. I keep the training narrative and the source research distinct rather than presenting them as identical evidence.

The source researcher also states uncertainty about whether Squirrelwaffle loaded Qakbot or whether they were loaded at the same time. This report does not claim to resolve that sequence.

### Reproducibility

Packet references below were checked against the original public capture:

- **Filename:** `2021-09-24-Squirrelwaffle-with-Qakbot-and-Cobalt-Strike.pcap`
- **Size:** 56,029,783 bytes
- **SHA-256:** `3cacb2c09f2309cec8bddc31a52fe0f9595837501f89a4dbeee589dc11e28d19`
- **Time convention:** UTC, displayed as whole seconds with fractional seconds truncated
- **Scope:** Selected download, loader-connection, post-infection, Cobalt Strike-related, and IP-check activity

The capture was examined as recorded data. Embedded payloads were not executed, and the suspicious destinations were not contacted. The capture itself is not redistributed in this repository.

## Timeline

All events occurred on **September 24, 2021, in UTC**. Frame numbers refer to the capture identified above.

| Time | Frame | Observation |
|---|---:|---|
| 16:44:38 | 1735 | HTTP GET to `85.187.128.24`, Host `attirenepal[.]com`, requesting `/incidunt-consequatur/documents.zip` |
| 16:45:11 | 2422, 2427 | DNS query for `finejewels[.]com[.]au`, followed by a TLS ClientHello to `148.72.192.206` with that server name |
| 16:45:20–16:45:21 | 2983, 3009 | DNS query for `thietbiagt[.]com`, followed by a TLS ClientHello to `210.245.90.247` with that server name |
| 16:45:25 | 3224, 3229 | DNS query for `new[.]americold[.]com`, followed by a TLS ClientHello to `148.72.53.144` with that server name |
| 16:46:16 | 3822 | First HTTP POST to `208.91.128.6`, Host `maldivehost[.]net`, with URI prefix `/zLIisQRWZI9/` |
| 16:46:41 | 3908 | Next POST to the same host, approximately 25.11 seconds after the first |
| 16:53:27 | 4493 | DNS query for `securitybusinpuff[.]com`, associated with Cobalt Strike in the source indicator list |
| 16:55:10–16:55:11 | 6510, 6516 | DNS query for `survmeter[.]live`, followed by HTTP to `185.106.96.158` using Host `ocsp.verisign[.]com` |
| 16:55:44 | 7112 | TLS ClientHello to `185.125.204.174` with server name `securitybusinpuff[.]com` |
| 17:00:04 | 24147, 24162 | DNS query for `api[.]ipify[.]org`, followed by a TLS ClientHello using that server name |

## Findings and reasoning

### Initial archive request

Frame 1735 identifies the source workstation, destination IP, HTTP Host header, and requested ZIP path. The source research identifies the archive member as `chart-1530076591.xls`.

The network request establishes contact with the archive-delivery location. The ZIP contents and source research support the Office-document link in the infection chain. A request alone does not prove that a user opened the downloaded file or enabled macros.

### Connections associated with loader delivery

The workstation queries three domains and then initiates TLS sessions using matching server names: `finejewels[.]com[.]au`, `thietbiagt[.]com`, and `new[.]americold[.]com`. Brad Duncan's indicator list identifies URLs on these hosts as loader DLL locations.

Frame 2436 contains the certificate for `finejewels[.]com[.]au`; the leaf certificate issuer is **Go Daddy Secure Certificate Authority - G2**. A recognized certificate issuer does not establish that a destination is safe.

DNS queries and TLS metadata show the contacted infrastructure. Without decryption, they do not independently reveal the HTTPS response bodies or prove successful payload execution.

### Repeated post-infection traffic

Filtering for POST requests to `208.91.128.6` with Host `maldivehost.net` returns **26 requests**. Their URI paths start with `/zLIisQRWZI9/`. Across the 25 consecutive intervals, the median is approximately **25.10 seconds**, with a range of approximately **24.98–25.70 seconds**.

That regularity supports a beaconing hypothesis in the context of this infection. Periodicity alone would be insufficient to label traffic malicious. The source researcher specifically attributes this destination and URI pattern to **Squirrelwaffle post-infection traffic**.

### Cobalt Strike infrastructure and Host-header mismatch

The source indicator list associates `185.125.204.174` with `securitybusinpuff[.]com`, and `185.106.96.158` with `survmeter[.]live`. The capture contains traffic to both IPs.

One useful detail is the HTTP Host header `ocsp.verisign.com` in requests sent to `185.106.96.158`. In this context, the familiar-looking header should not override the destination IP, DNS evidence, and source attribution. This is not evidence that Verisign's own service was compromised.

The Cobalt Strike attribution here relies on the original research, alongside the observed network evidence. It is not presented as a new, independently reproduced VirusTotal verdict.

### Public IP-check activity

At 17:00:04 UTC, the workstation queries `api[.]ipify[.]org` and begins a TLS connection using that server name. The source research identifies this as Qakbot-related public IP-check activity.

An IP-check service is not inherently malicious. Its relevance comes from the host's surrounding infection activity, so I would correlate it with other evidence rather than recommend blocking the service broadly.

## Historical indicators

These values describe the 2021 capture and source research. They are investigation pivots for this case, not claims about current domain ownership or reputation. Dots in domains are defanged as `[.]`.

| Indicator | Role in this case | Evidence basis |
|---|---|---|
| `10.9.23.102` | Affected workstation | Capture |
| `attirenepal[.]com` / `85.187.128.24` | Initial archive request | HTTP frame 1735; source research |
| `documents.zip` / `chart-1530076591.xls` | Archive and Office document | Requested ZIP in capture; archive member in source research |
| `finejewels[.]com[.]au` / `148.72.192.206` | Loader-associated infrastructure | DNS/TLS metadata; source research |
| `thietbiagt[.]com` / `210.245.90.247` | Loader-associated infrastructure | DNS/TLS metadata; source research |
| `new[.]americold[.]com` / `148.72.53.144` | Loader-associated infrastructure | DNS/TLS metadata; source research |
| `maldivehost[.]net` / `208.91.128.6` | Squirrelwaffle post-infection POSTs | Capture; source attribution |
| `securitybusinpuff[.]com` / `185.125.204.174` | Cobalt Strike-associated infrastructure | Capture; source attribution |
| `survmeter[.]live` / `185.106.96.158` | Cobalt Strike-associated infrastructure | Capture; source attribution |
| `ocsp.verisign[.]com` | Host header used in traffic to `185.106.96.158` | HTTP frame 6516; not a blanket domain-block recommendation |
| `api[.]ipify[.]org` | Public IP-check service contacted by the workstation | Frame 24147; contextual indicator only |

## Investigation method

1. Set Wireshark's time display to UTC and identify the source workstation.
2. Inspect HTTP requests while excluding background SSDP discovery traffic:
   ```text
   ip.src == 10.9.23.102 && http.request && !ssdp
   ```
3. Inspect frame 1735 and follow its TCP stream to review the archive request and response context. Compare the filenames with the source indicator list.
4. Review the POST sequence and calculate intervals from packet timestamps:
   ```text
   ip.src == 10.9.23.102 && ip.dst == 208.91.128.6 &&
   http.request.method == "POST" && http.host == "maldivehost.net"
   ```
5. Examine DNS queries and TLS ClientHello server names after the initial archive request:
   ```text
   ip.src == 10.9.23.102 && frame.number > 1735 &&
   (dns.flags.response == 0 || tls.handshake.type == 1)
   ```
6. Review the server certificate in frame 2436 and correlate server names with destination IPs. Certificate identity is contextual evidence, not a malware verdict.
7. Compare the observed infrastructure with Brad Duncan's indicator list. VirusTotal can provide additional context, but a lookup's date and evidence should be recorded before treating it as independent confirmation.

Excluding SSDP in this workflow is an analysis filter. This case does not claim deployment or tuning of a production detection rule.

## Recommended response in a real environment

- **Escalate and contain:** Send the host identity, UTC timeline, and packet references to the incident responder. Request authorized endpoint isolation while preserving evidence.
- **Scope the incident:** Search endpoint, DNS, proxy, firewall, and email records for the archive request and associated destinations. Check whether other hosts show the same sequence.
- **Collect endpoint evidence:** Investigate Office child processes, downloaded files, DLL execution, scheduled tasks, and other persistence mechanisms. Network traffic alone does not establish these endpoint details.
- **Apply targeted controls:** Validate current relevance before blocking confirmed malicious destinations. Avoid broad blocks on legitimate services based only on a misleading Host header or an IP-check lookup.
- **Protect accounts and recover:** Review sign-ins and potential credential exposure. Reset credentials, revoke sessions, and rebuild or remediate affected systems as supported by the investigation and response procedures.

In business terms, the concern is that a workstation may remain under external control and expose credentials or business data. This capture does not by itself establish data theft or the full impact of the infection.

## MITRE ATT&CK interpretation

These are analyst mappings, with their evidence limits stated explicitly.

| Technique | Basis |
|---|---|
| [T1566.001 — Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/) | The TryHackMe Word-attachment scenario; not independently established by the network timeline |
| [T1204.002 — Malicious File](https://attack.mitre.org/techniques/T1204/002/) | User action described by the scenario and Office-document execution chain in the source research |
| [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) | Archive delivery and loader locations described in the source research; encrypted transfers have the visibility limits noted above |
| [T1071.001 — Web Protocols](https://attack.mitre.org/techniques/T1071/001/) | HTTP POST activity attributed to Squirrelwaffle and web traffic associated with Cobalt Strike |
| [T1016.001 — Internet Connection Discovery](https://attack.mitre.org/techniques/T1016/001/) | Public IP/connectivity-check behavior described in the source research and correlated with the observed IP-check connection |

## What I learned

My early guesses about suspicious domains relied too heavily on their names. Correlating timestamps, destination IPs, HTTP headers, and TLS metadata produced a stronger explanation. I also learned to separate the scenario, packet observations, source attribution, and recommendations so that each conclusion has a clear basis.

## Sources

- [TryHackMe — Carnage](https://tryhackme.com/room/c2carnage): training scenario and investigation questions.
- [Brad Duncan — September 24, 2021 Squirrelwaffle with Qakbot and Cobalt Strike](https://www.malware-traffic-analysis.net/2021/09/24/index.html): original capture and accompanying IOC text archive. Credit for capture collection and malware-family attribution belongs to the source researcher.
- [Wireshark HTTP display-filter reference](https://www.wireshark.org/docs/dfref/h/http.html): HTTP field definitions.
- [MITRE ATT&CK](https://attack.mitre.org/): technique definitions linked above.
