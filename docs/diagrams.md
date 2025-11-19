# Karbonbike SOC Lab – Diagrams

## 1. High-level Network Topology

```mermaid
graph LR
    INET[Internet] --> FW[OPNsense Firewall<br/>172.16.58.2]

    subgraph LAN[Lab Network 172.16.58.0/24]
        DC[DC.karbonbike.local<br/>Win Server 2025 (DC)]
        PC1[PC1.karbonbike.local<br/>Win 11]
        PC2[PC2.karbonbike.local<br/>Win 11 (test)]
        KALI[Kali Linux<br/>Attacker]
        WZ[Wazuh Manager<br/>Ubuntu]
        SPL[Splunk + Logstash + Fleet + Velociraptor<br/>Ubuntu]
        JS[JuiceShopClone<br/>Ubuntu (OWASP Juice Shop)]
    end

    FW --> DC
    FW --> PC1
    FW --> PC2
    FW --> KALI
    FW --> WZ
    FW --> SPL
    FW --> JS
```

---

## 2. Log Pipelines & Telemetry

```mermaid
flowchart LR
    subgraph Win[Windows Endpoints]
        PC1[PC1<br/>Sysmon + Wazuh Agent + Orbit + Velociraptor]
        PC2[PC2<br/>(optional test endpoint)]
    end

    %% Windows → Wazuh → Splunk
    PC1 --> WA[Wazuh Agent]
    WA --> WM[Wazuh Manager<br/>alerts.json]
    WM --> FB1[Filebeat (Wazuh)]
    FB1 --> LS[Logstash]
    LS --> SPW[Splunk<br/>Index: wazuh]

    %% Juice Shop → Splunk
    JS[Juice Shop App<br/>/var/log/juiceshop/app.log] --> FB2[Filebeat (Juice)]
    FB2 --> LS
    LS --> SPJ[Splunk<br/>Index: juiceshop]

    %% OPNsense (Suricata + Zenarmor) → Splunk
    FW[OPNsense<br/>Suricata + Zenarmor] --> SYSLOG[syslog-ng<br/>UDP 5514]
    SYSLOG --> SPO[Splunk<br/>Index: opnsense]

    %% FleetDM + Velociraptor (conceptual feeds)
    Orbit[Fleet Orbit Agents] --> FLEET[FleetDM Server]
    FLEET --> SPF[Splunk<br/>Index: fleetdm]

    VAG[Velociraptor Agents] --> VSRV[Velociraptor Server]
    VSRV --> SPV[Splunk<br/>Index: velociraptor]
```
