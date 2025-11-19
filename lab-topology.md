
# Karbonbike SOC Lab – Topology & Pipelines

This document describes the current state of the **Karbonbike SOC Lab** running on VMware Workstation.

The lab is designed as a compact **SOC + DFIR playground** with:

- Windows domain (DC + workstations)
- OPNsense firewall
- Wazuh SIEM
- Splunk Enterprise + Logstash
- FleetDM (osquery)
- Velociraptor
- OWASP Juice Shop as an attack target
- Kali as the attacker box

---

## 1. Network Topology

- **Router / Firewall:** OPNsense  
  - LAN: `172.16.58.2/24` (gateway for all VMs)  
  - WAN: NAT to host network  
  - DHCP pool: `172.16.58.10 – 172.16.58.100`

- **Lab network:** `172.16.58.0/24` (all VMs attached here)

---

## 2. VM Inventory

| VM Name           | Hostname               | OS / Role                                                                 | IP             |
|-------------------|------------------------|---------------------------------------------------------------------------|----------------|
| **OPNsense**      | opnsense.local         | OPNsense firewall + Suricata + Zenarmor                                  | 172.16.58.2    |
| **DC**            | DC.karbonbike.local    | Windows Server 2025 – Domain Controller + Wazuh Agent                     | 172.16.58.50   |
| **PC1**           | PC1.karbonbike.local   | Windows 11 24H2 – main workstation (Wazuh, Splunk UF, Sysmon, Fleet, Velociraptor, Atomic Red Team) | 172.16.58.61 |
| **PC2**           | PC2.karbonbike.local   | Windows 11 (Eval) – test client                                           | 172.16.58.52   |
| **JuiceShopClone**| juice-shop.local       | Ubuntu 20.04 – OWASP Juice Shop + Filebeat                                | 172.16.58.133  |
| **Kali**          | kali.local             | Kali Linux – attacker tools                                               | 172.16.58.20   |
| **Wazuh Manager** | wazuh-manager.local    | Ubuntu 22.04 – Wazuh Manager + Filebeat                                   | 172.16.58.137  |
| **Splunk/Logstash** | splunk.local         | Ubuntu 22.04 – Splunk Enterprise + Logstash + FleetDM + Velociraptor      | 172.16.58.134  |

---

## 3. Pipeline A – Windows → Wazuh → Filebeat → Logstash → Splunk

### 3.1 Wazuh Agents (DC & PC1)

- **Service:** `WazuhSvc`  
- **Config:**  
  `C:\Program Files (x86)\ossec-agent\ossec.conf`

Key sections (simplified):

```xml
<ossec_config>
  <client>
    <server>
      <address>172.16.58.137</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
  </client>

  <localfile>
    <location>Application</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <query>
      Event[System[
        (EventID=4624 or EventID=4634 or EventID=4688 or EventID=4672 or
         EventID=4663 or EventID=5140 or EventID=5156 or EventID=5157)
      ]]
    </query>
  </localfile>

  <localfile>
    <location>System</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
````

Connectivity check from a Windows host:

```powershell
Test-NetConnection -ComputerName 172.16.58.137 -Port 1514
```

### 3.2 Wazuh Manager (172.16.58.137)

* **Service:** `wazuh-manager.service`
* **Listens on:** `0.0.0.0:1514/tcp`
* **JSON alerts enabled:**

```xml
<ossec_config>
  <remote>
    <connection>secure</connection>
  </remote>
  <global>
    <alerts_log>json</alerts_log>
  </global>
</ossec_config>
```

* Alerts file:
  `/var/ossec/logs/alerts/alerts.json`

### 3.3 Filebeat on Wazuh Manager → Logstash

* **Service:** `filebeat.service`
* **Config:** `/etc/filebeat/filebeat.yml` (core idea)

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.add_error_key: true

output.logstash:
  hosts: ["172.16.58.134:5044"]

output.elasticsearch:
  enabled: false
```

Registry reset if paths change:

```bash
sudo systemctl stop filebeat
sudo rm -rf /var/lib/filebeat/registry/filebeat
sudo systemctl start filebeat
```

### 3.4 Logstash (172.16.58.134) → Splunk HEC

* Input: `beats { port => 5044 }`
* Output: Splunk HEC at `http://127.0.0.1:8088/services/collector`
* Uses a dedicated **Wazuh HEC token**
  (actual GUID kept out of this public doc).

Example props on Splunk side:

```ini
[wazuh-alerts]
INDEXED_EXTRACTION = json
KV_MODE            = json
NO_BINARY_CHECK    = true
TRUNCATE           = 0
```

---

## 4. Pipeline B – Juice Shop → Filebeat → Logstash → Splunk

### 4.1 JuiceShopClone (172.16.58.133)

* App log file: `/var/log/juiceshop/app.log`

Filebeat snippet:

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/log/juiceshop/*.log

output.logstash:
  hosts: ["172.16.58.134:5044"]

output.elasticsearch:
  enabled: false
```

### 4.2 Logstash → Splunk HEC RAW

* For paths under `/var/log/juiceshop/`, events are sent to:

  * `http://127.0.0.1:8088/services/collector/raw`
  * With a dedicated **Juice Shop HEC token**
  * Defaults in Splunk: `sourcetype=juiceshop:app`, `index=wazuh` (lab choice)

---

## 5. Pipeline C – OPNsense → Splunk (Suricata EVE + Zenarmor IPDR)

### 5.1 OPNsense Syslog

* Remote syslog target: `172.16.58.134:5514/udp`

### 5.2 Suricata EVE

* Config: `/usr/local/etc/suricata/suricata.yaml`
* Outputs JSON via syslog with identity `suricata`.

On Splunk:

* UDP input on `5514`
* Props/transforms:

  * Strip syslog preamble (preamble → JSON)
  * `sourcetype=suricata`
  * `KV_MODE=json`

### 5.3 Zenarmor IPDR

* `syslog-ng` tails Zenarmor IPDR files, prefixes with `zenarmor:`
* Sends to `172.16.58.134:5514/udp`
* Splunk:

  * `sourcetype=zenarmor`
  * Strips prefix and parses JSON
  * Drops `{"index":{}}` noise lines

---

## 6. FleetDM + Orbit

* Fleet server runs on the Splunk node:
  `https://172.16.58.134:8412` (self-signed)
* Backed by MySQL + Redis.
* Orbit/osquery agents installed on hosts like PC1 & DC, enrolled into Fleet.
* Used for:

  * Live queries
  * Baseline visibility
  * Future policies / scheduled queries

---

## 7. Velociraptor

* Server binary: `/usr/local/bin/velociraptor`
* Config: `/etc/velociraptor/server.config.yaml`
* Service: `velociraptor_server`
* Frontend: `https://172.16.58.134:8008` (self-signed)

Enrolled endpoints include:

* DC, PC1, PC2, JuiceShopClone, Splunk server.

Used for:

* VFS browsing
* File collection
* Basic forensic artefacts

---

## 8. Port Matrix

| From                            | To                     | Proto/Port       | Purpose                       |
| ------------------------------- | ---------------------- | ---------------- | ----------------------------- |
| DC / PC1 (Wazuh Agent)          | Wazuh Manager          | TCP 1514         | Agent → Manager               |
| Wazuh Manager (Filebeat)        | Logstash               | TCP 5044         | Beats → Logstash              |
| JuiceShopClone (Filebeat)       | Logstash               | TCP 5044         | App logs → Logstash           |
| Logstash                        | Splunk HEC (localhost) | HTTP 8088        | Wazuh + Juice logs → Splunk   |
| OPNsense                        | Splunk                 | UDP 5514         | Suricata + Zenarmor syslog    |
| Browser / Users                 | JuiceShopClone         | HTTP 3000        | Juice Shop web UI             |
| PC1 / DC / PC2                  | FleetDM                | TCP 8412 (HTTPS) | Orbit/osquery TLS             |
| PC1 / DC / PC2 / Juice / Splunk | Velociraptor           | TCP 8008 (HTTPS) | Velociraptor frontend         |
| PC1 (Splunk UF)                 | Splunk                 | TCP 9997         | Universal Forwarder → Indexer |

---

## 9. Where to Look (Log Locations)

* **Wazuh Agent (Windows):**
  `C:\Program Files (x86)\ossec-agent\logs\ossec.log`

* **Wazuh Manager:**
  `/var/ossec/logs/ossec.log`
  `/var/ossec/logs/alerts/alerts.json`

* **Filebeat:**
  `/var/log/filebeat/filebeat`

* **Logstash:**
  `journalctl -u logstash`
  `curl -s localhost:9600/_node/pipelines?pretty`

* **Splunk:**
  `$SPLUNK_HOME/var/log/splunk/splunkd.log`
  `index=_internal sourcetype=splunkd component=HttpInput*`

---

This file is the **authoritative blueprint** for the Karbonbike SOC Lab that Nexusnode operates.

````

3. Save the file.

---

### Optional: commit this “Level 0” state

If you’re happy with README + topology:

```bash
cd "E:\Projects\soc-lab-iac"
git add README.md docs/lab-topology.md
git commit -m "Add Nexusnode SOC lab README and topology"
````


