
# Karbonbike SOC Lab – Diagrams

## 1. High-level Network Topology

```mermaid
graph LR
  INET[Internet]

  FW[OPNsense Firewall<br/>172.16.58.2]

  INET --> FW

  subgraph LAN_172_16_58_0_24 ["Lab network 172.16.58.0/24"]
    DC[DC.karbonbike.local<br/>Win Server 2025 (DC)]
    PC1[PC1.karbonbike.local<br/>Win 11 (main)]
    PC2[PC2.karbonbike.local<br/>Win 11 (test)]
    WZ[Wazuh Manager<br/>Ubuntu 22.04<br/>172.16.58.137]
    SPL[SPLUNK / Logstash / Fleet / Velociraptor<br/>Ubuntu 22.04<br/>172.16.58.134]
    JS[JuiceShopClone<br/>OWASP Juice Shop<br/>172.16.58.133]
    KALI[Kali attacker<br/>172.16.58.20]
  end

  FW --> DC
  FW --> PC1
  FW --> PC2
  FW --> WZ
  FW --> SPL
  FW --> JS
  FW --> KALI
````

---

## 2. Log Pipelines & Telemetry

```mermaid
flowchart LR
  %% Windows endpoints
  subgraph Windows_Endpoints
    DCW[DC.karbonbike.local<br/>Win Server 2025<br/>Wazuh + Orbit + Velociraptor]
    PC1W[PC1.karbonbike.local<br/>Win 11 main<br/>Wazuh + Sysmon + UF + Orbit + Velociraptor]
  end

  %% Wazuh pipeline
  DCW -->|"eventchannel logs"| WZ_MGR[Wazuh Manager<br/>172.16.58.137]
  PC1W -->|"eventchannel logs"| WZ_MGR

  WZ_MGR -->|"/var/ossec/logs/alerts/alerts.json"| FB_WZ[Filebeat (Wazuh)]
  FB_WZ -->|"Beats 5044"| LS[Logstash<br/>172.16.58.134]

  %% Juice Shop pipeline
  subgraph Juice_Shop
    JSAPP[Juice Shop app<br/>172.16.58.133]
    FB_JS[Filebeat (Juice Shop)]
  end

  JSAPP -->|"/var/log/juiceshop/*.log"| FB_JS
  FB_JS -->|"Beats 5044"| LS

  %% OPNsense → Splunk
  subgraph OPNsense_Firewall
    SUR[Suricata EVE<br/>OPNsense]
    ZEN[Zenarmor IPDR<br/>OPNsense]
  end

  SUR -->|"syslog UDP 5514"| SPL[Splunk Enterprise<br/>172.16.58.134]
  ZEN -->|"syslog UDP 5514"| SPL

  %% Logstash → Splunk
  LS -->|"HEC JSON 8088"| SPL

  %% Fleet & Velociraptor telemetry
  subgraph Telemetry_Controllers
    FLEET[FleetDM<br/>HTTPS 8412]
    VEL[Velociraptor<br/>HTTPS 8008]
  end

  DCW -->|"Orbit TLS"| FLEET
  PC1W -->|"Orbit TLS"| FLEET

  DCW -->|"Velociraptor client"| VEL
  PC1W -->|"Velociraptor client"| VEL
```


