
# Nexusnode SOC Lab – Karbonbike Cyber Range

This repository contains documentation and infrastructure-as-code for the **Karbonbike SOC Lab**, a compact cyber range operated by **Nexusnode** for research, training, and detection engineering.

The lab runs on VMware Workstation and emulates a small organisation with:

- Windows domain (DC + workstations)
- OPNsense firewall with Suricata & Zenarmor
- Wazuh SIEM
- Splunk Enterprise + Logstash
- FleetDM (osquery)
- Velociraptor (DFIR / incident response)
- OWASP Juice Shop application
- Kali attacker box

> **Goal:** Make the lab reproducible and explainable as code, without exposing VM images or secrets.

---

## 1. Architecture snapshot

Core ideas of the Karbonbike lab:

- **Network:** Single routed lab network `172.16.58.0/24` behind an **OPNsense** firewall.
- **Endpoints:** `DC`, `PC1`, `PC2` (Windows) plus **JuiceShopClone**, **Splunk/Logstash/Fleet/Velociraptor**, **Wazuh Manager**, **Kali**.
- **Pipelines:**
  - Windows → **Wazuh Agent** → **Wazuh Manager** → **Filebeat** → **Logstash** → **Splunk HEC**
  - **Juice Shop** app logs → **Filebeat** → **Logstash** → **Splunk (RAW HEC)**
  - **OPNsense** (Suricata EVE + Zenarmor IPDR) → syslog → **Splunk**
  - **FleetDM + Orbit** for osquery telemetry
  - **Velociraptor** for DFIR-style collection and hunting

This repository captures that design as **documentation + automation**, so others can understand and replay the lab.

See also:

- [`lab-topology.md`](lab-topology.md) – narrative topology + VM inventory.
- [`docs/diagrams.md`](docs/diagrams.md) – Mermaid diagrams of the topology and pipelines.
- [`docs/attack-chains.md`](docs/attack-chains.md) – worked attack chains and detections.

---

## 2. Repository structure

```text
soc-lab-iac/
  README.md                    ← This file
  .gitignore
  lab-topology.md              ← Network map, VM inventory, pipelines, port matrix, log locations

  docs/
    attack-chains.md           ← Kali → Juice Shop / Windows chains + detections
    diagrams.md                ← Mermaid diagrams (topology + pipelines)

  ansible/
    inventory.ini              ← Ansible inventory for Linux hosts (lab-specific; not for reuse)
    inventory.example.ini      ← Template inventory (copy → inventory.ini and fill in your own details)
    ping.yml                   ← Connectivity / uptime check for Linux hosts

    splunk.yml                 ← Playbook to apply Splunk server role
    wazuh.yml                  ← Playbook to apply Wazuh Manager + Filebeat role
    juice.yml                  ← Playbook to apply Juice Shop Filebeat role
    opnsense.yml               ← Playbook to apply OPNsense logging roles
    fleet.yml                  ← Playbook to apply FleetDM server configuration
    velociraptor.yml           ← Playbook to apply Velociraptor server configuration

    roles/
      splunk_server/
        files/system/local/…   ← Captured `/opt/splunk/etc/system/local/*` from the lab
        tasks/main.yml         ← Copies configs + restarts Splunk

      wazuh_manager/
        files/
          ossec.conf           ← Wazuh manager config from the lab
          filebeat.yml         ← Filebeat config for Wazuh alerts → Logstash
        tasks/main.yml         ← Deploys configs + restarts Wazuh Manager & Filebeat

      juice_filebeat/
        files/
          filebeat.yml         ← Filebeat config for Juice Shop app logs → Logstash
        tasks/main.yml         ← Ensures log dir + deploys Filebeat config + restarts Filebeat

      opnsense_syslog/
        files/
          zenarmor-ipdr.conf   ← syslog-ng include for Zenarmor IPDR → Splunk UDP 5514
        tasks/main.yml         ← Deploys config + restarts syslog-ng

      opnsense_suricata/
        files/
          suricata.yaml        ← Suricata EVE config pointing at Splunk/syslog
        tasks/main.yml         ← Deploys config + restarts Suricata

      fleet_server/
        files/
          config.yml           ← FleetDM server config (`/etc/fleet/config.yml`)
        tasks/main.yml         ← Deploys config + restarts Fleet service

      velociraptor_server/
        files/
          server.config.yaml   ← Velociraptor server config
          client.config.yaml   ← Velociraptor client config
        tasks/main.yml         ← Deploys configs + ensures config dir exists
        handlers/main.yml      ← Restarts `velociraptor_server` systemd service
````

* **`docs/`** holds all conceptual documentation: topology, diagrams, and narrative explanations.
* **`ansible/`** is where configuration is slowly migrated into code: starting with connectivity, then Splunk, Wazuh Manager + Filebeat, Juice Shop log shipping, OPNsense logging, FleetDM and Velociraptor, and later the rest of the stack.

---

## 3. Current Ansible coverage

Right now, Ansible is used for **seven** main things:

### 3.1 Connectivity check (all Linux lab hosts)

From **Kali** (or any Ansible control node):

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini ping.yml
```

This runs `uptime` on:

* `splunk` (172.16.58.134)
* `wazuh` (172.16.58.137)
* `juice` (172.16.58.133)

and confirms SSH + sudo basics are OK.

---

### 3.2 Splunk server config as code

Role: `ansible/roles/splunk_server`

* Copies the lab’s `system/local` configs from the repo to `/opt/splunk/etc/system/local/` on the **Splunk** VM.
* Restarts Splunk so changes take effect.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini splunk.yml
```

Any edits you make to `roles/splunk_server/files/system/local/*.conf` in Git are now replayable onto the Splunk VM with a single playbook run.

---

### 3.3 Wazuh Manager + Filebeat as code

Role: `ansible/roles/wazuh_manager`

* Deploys `ossec.conf` for the **Wazuh Manager**.
* Deploys `filebeat.yml` for sending Wazuh alerts (`alerts.json`) to Logstash.
* Restarts **Wazuh Manager** and **Filebeat** cleanly.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini wazuh.yml
```

This ensures the **Wazuh Manager + Filebeat** side of the Windows → Wazuh → Filebeat → Logstash → Splunk pipeline is under version control and repeatable.

---

### 3.4 Juice Shop Filebeat as code

Role: `ansible/roles/juice_filebeat`

* Ensures the Juice Shop log directory exists: `/var/log/juiceshop`.
* Deploys `filebeat.yml` that tails Juice Shop app logs (e.g. `/var/log/juiceshop/app.log`) and ships them to **Logstash**.
* Restarts **Filebeat** so the new config is active.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini juice.yml
```

This keeps the **Juice Shop → Filebeat → Logstash → Splunk (RAW HEC)** pipeline driven from source-controlled config instead of manual edits.

---

### 3.5 OPNsense logging (Suricata + Zenarmor) → Splunk as code

Roles:

* `ansible/roles/opnsense_syslog`
* `ansible/roles/opnsense_suricata`

On the OPNsense firewall (`172.16.58.2`), these roles:

**Zenarmor IPDR → Splunk (syslog-ng)**

* Deploy `/usr/local/etc/syslog-ng.conf.d/zenarmor-ipdr.conf`.
* Tail Zenarmor IPDR files under `/usr/local/zenarmor/output/active/temp/*.ipdr`.
* Prefix messages with `zenarmor: ...`.
* Ship events via syslog to the Splunk node at `172.16.58.134:5514/udp`.

**Suricata EVE → Splunk**

* Deploy `/usr/local/etc/suricata/suricata.yaml` from `roles/opnsense_suricata/files/suricata.yaml`.
* Restart the `suricata` service so EVE-over-syslog output is active again.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini opnsense.yml
```

---

### 3.6 FleetDM server configuration as code

Role: `ansible/roles/fleet_server`

* Ensures Fleet’s config directory exists (`/etc/fleet`).
* Deploys `config.yml` from the repo into `/etc/fleet/config.yml`.
* Restarts the Fleet service so new settings take effect.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini fleet.yml
```

This puts the **FleetDM server configuration** (listener ports, MySQL connection, TLS settings, etc.) under source control, instead of only living on the box.

> Note: This role focuses on **Fleet server config**, not osquery packs/queries or Splunk log ingestion yet.

---

### 3.7 Velociraptor server configuration as code

Role: `ansible/roles/velociraptor_server`

* Ensures `/etc/velociraptor` exists with sensible permissions.
* Deploys `server.config.yaml` to `/etc/velociraptor/server.config.yaml`.
* Deploys `client.config.yaml` to `/etc/velociraptor/client.config.yaml`.
* Restarts the `velociraptor_server` systemd service so changes apply.

Run:

```bash
cd ~/soc-lab-iac/ansible
ansible-playbook -i inventory.ini velociraptor.yml
```

This locks in the **Velociraptor server and client configs** as code, making it easier to rebuild or clone the DFIR controller.

> Note: This role controls **Velociraptor itself**, not the Splunk side of Velociraptor log ingestion yet.

---

## 4. What is **not** in this repo

To keep the repository safe to publish and reuse, we explicitly **do not** include:

* ❌ VM images, exports, or snapshots (no `.vmdk`, `.ova`, etc.)
* ❌ Secrets: Splunk HEC tokens, Wazuh keys, Fleet / Velociraptor keys, passwords
* ❌ Proprietary customer or production data

Only **topology, patterns, and automation code** live here.

If you clone this repo, you still need to:

* Provide your own VM images / licenses.
* Generate your own secrets and credentials.
* Point configs at your own IP ranges.

---

## 5. Intended use

This project is meant to serve as a:

* 🧪 **Research environment**
  Test log pipelines, enrichment strategies, and detections end-to-end
  (Windows + Wazuh + Splunk, OPNsense → Splunk, FleetDM, Velociraptor, etc.).

* 🎓 **Training & workshops**
  Use the lab as a reference architecture for short SOC, DFIR, and detection-engineering trainings.
  The documentation in `docs/` is written to be presentable in talks and live demos.

* 🧱 **Foundation for “SOC Lab as Code” products**
  Over time, this repo will grow into a reusable blueprint:
  pre-built exercises, automation, and configs that can be adapted by universities,
  bootcamps, and teams who want an affordable SOC range.

For concrete examples of how Kali, Juice Shop, Windows, Wazuh, OPNsense and Splunk
come together in practice, see:

* `docs/attack-chains.md` – step-by-step attack chains + matching detections.

---

## 6. Roadmap

Planned steps for this repository:

* [x] Finalise base Ansible inventory (`ansible/inventory.ini`) and connectivity checks (`ping.yml`).

* [x] Add roles for:

  * [x] Splunk server (system/local configs, basic inputs)
  * [x] Wazuh Manager + Filebeat (manager-side pipeline into Logstash)
  * [x] Juice Shop Filebeat (app logs shipping into Logstash → Splunk)
  * [x] OPNsense logging (Suricata + Zenarmor → Splunk syslog)
  * [x] FleetDM & Velociraptor **server configuration**

* [ ] Extend roles for:

  * [ ] FleetDM + Velociraptor **log shipping** into Splunk (sourcetypes, indexes)
  * [ ] OPNsense → Splunk parsing (props/transforms) + saved searches
  * [ ] Splunk dashboards / detection content for key sourcetypes

* [ ] Provide Vagrant / Terraform examples for non-VMware deployments.

---

## 7. Contact

Maintained by **Nexusnode**
🌐 [https://nexusnode.co.za](https://nexusnode.co.za)

For collaboration, training, or partnerships related to the Karbonbike SOC Lab or Nexusnode’s cyber range work, please reach out via the website contact channels.

