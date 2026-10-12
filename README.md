# Carnage: Word Macro Infection, Qakbot Download, and Cobalt Strike C2

**Analyst:** Ethan
**Source:** TryHackMe "Carnage" room, using the public Malware-Traffic-Analysis.net capture from 2021-09-24 (credit: Brad Duncan)
**Tools:** Wireshark (macOS), VirusTotal
**Skills:** Packet analysis, DNS and HTTP investigation, TLS certificate review, threat intelligence lookup

## Summary

A user at Bartell Ltd (workstation 10.9.23.102) opened a Word document from an email and enabled its content. Within a minute, the workstation downloaded `documents.zip` from `attirenepal.com`. The zip contained an Excel file, `chart-1530076591.xls`. The host then made DNS lookups and encrypted connections to several unrelated domains, and [describe what followed, e.g., "additional payloads were retrieved"]. About 90 seconds later, it began sending POST requests to `maldivehost.net` roughly every 25 seconds, which is consistent with command-and-control (C2) check-ins. The capture also shows Cobalt Strike C2 IP addresses and a lookup to a public IP-check service.

## Timeline (UTC, 2021-09-24)

| Time | Event |
|---|---|
| 16:44:38 | GET `/incidunt-consequatur/documents.zip` from `attirenepal[.]com` (85.187.128.24) |
| [time] | DNS lookups for `finejewels[.]com[.]au`, `thietbiagt[.]com`, `new[.]americold[.]com` |
| [time] | Encrypted connections to the same three domains |
| 16:46:16 | First POST to `maldivehost[.]net` (208.91.128.6). Check-ins begin |
| 16:46:41 onward | Repeated POSTs about every 25 seconds |
| 17:00:04 | DNS query for `api[.]ipify[.]org`, a public IP-check service |

## Indicators of Compromise

Domains and URLs are defanged (`[.]`) so they can't be clicked by accident.

| Type | Indicator | Context |
|---|---|---|
| Domain | `attirenepal[.]com` | Hosted the malicious zip |
| File | `documents.zip` | Downloaded via Word macro |
| File | `chart-1530076591.xls` | Inside the zip |
| Domain | `maldivehost[.]net` | POST destination (C2 check-ins) |
| IP | `208.91.128.6` | Destination of check-in POSTs |
| IP | `185.125.204.174`, `185.106.96.158` | Cobalt Strike C2 servers (confirmed on VirusTotal) |
| Domain | `[domain for first Cobalt Strike IP]` | Resolved to the first Cobalt Strike IP |
| Domain | `finejewels[.]com[.]au` | Encrypted connection; certificate issued by GoDaddy |
| Domain | `thietbiagt[.]com`, `new[.]americold[.]com` | Additional contacted domains |
| Service | `api[.]ipify[.]org` | Public IP lookup by the malware |

## Analysis Method

1. **Set the time format** to UTC so every timestamp could be compared with the others.
2. **Filtered web requests** with `http.request && !ssdp` to remove background SSDP noise. This exposed the zip download at packet 1735.
3. **Followed the TCP stream** for that download. The response headers showed `filename=documents.zip`, and the zip's internal file name was visible after the `PK` signature.
4. **Read the post-infection traffic** with `http.request.method == POST && ip.dst == 208.91.128.6`. The Host header showed `maldivehost.net`, and the request path began `/zLIisQRWZI9`.
5. **Isolated the lookups** that came after the download with `dns.flags.response == 0 && frame.number > 1735`, then excluded Microsoft, Bing, and internal-domain names. The remaining outside domains were the suspects.
6. **Verified the suspects** by checking which domains had encrypted connections (`tls.handshake.extensions_server_name`) and reading the certificate issuer (`tls.handshake.type == 11`).
7. **Checked IPs on VirusTotal**, using the Community and Relations tabs. I never visited the IPs or domains directly.

## Recommendations

- **Block** `attirenepal[.]com`, `maldivehost[.]net`, the Cobalt Strike IPs, and the other listed domains at the firewall and proxy.
- **Isolate** workstation 10.9.23.102 and check it for persistence, including scheduled tasks, new services, and additional payloads.
- **Reset** the affected user's credentials, revoke active sessions, and review recent sign-ins.
- **Search** all endpoints and proxy logs for the indicators above to find other infected hosts.
- **Train** users to treat "Enable Content" prompts on unexpected email attachments as a red flag.

## MITRE ATT&CK Mapping

- T1566.001: Phishing, Spearphishing Attachment
- T1204.002: User Execution, Malicious File
- T1105: Ingress Tool Transfer
- T1071.001: Application Layer Protocol, Web Protocols
- T1016: System Network Configuration Discovery (IP check)

## What I Would Do Differently

My first guesses about suspicious domains were based on names alone and were often wrong. I got better at filtering by time window and confirming each name with evidence, such as a completed connection or a certificate, before drawing a conclusion.