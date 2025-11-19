
# Karbonbike SOC Lab – Diagrams

## 1. High-level Network Topology

```mermaid
graph LR
  INET[Internet]

  FW["OPNsense Firewall<br/>172.16.58.2"]

  INET --> FW

  %% Subgraph for the lab network
  subgraph LAN_172_16_58_0_24 ["Lab network"]
    LANIP["172.16.58.0/24"]

    DC["DC.karbonbike.local<br/>Win Server 2025 DC"]
    PC1["PC1.karbonbike.local<br/>Win 11 main"]
    PC2["PC2.karbonbike.local<br/>Win 11 test"]
    WZ["Wazuh Manager<br/>Ubuntu 22.04<br/>172.16.58.137"]
    SPL["Splunk / Logstash / Fleet / Velociraptor<br/>Ubuntu 22.04<br/>172.16.58.134"]
    JS["JuiceShopClone<br/>OWASP Juice Shop<br/>172.16.58.133"]
    KALI["Kali attacker<br/>172.16.58.20"]
  end

  FW --> DC
  FW --> PC1
  FW --> PC2
  FW --> WZ
  FW --> SPL
  FW --> JS
  FW --> KALI


````

## 2. Log Pipelines & Telemetry

```mermaid
flowchart LR
  %% Windows endpoints
  subgraph Windows_Endpoints
    DCW["DC<br/>Win Server 2025<br/>Wazuh + Orbit + Velociraptor"]
    PC1W["PC1<br/>Win 11 main<br/>Wazuh + Sysmon + UF + Orbit + Velociraptor"]
  end

  %% Controllers
  subgraph Controllers
    WZ_MGR["Wazuh Manager<br/>172.16.58.137"]
    LS["Logstash<br/>172.16.58.134"]
    SPL["Splunk<br/>172.16.58.134"]
    FLEET["FleetDM<br/>HTTPS 8412"]
    VEL["Velociraptor<br/>HTTPS 8008"]
  end

  %% Juice Shop pipeline
  subgraph Juice_Shop
    JSAPP["Juice Shop app<br/>172.16.58.133"]
    FB_JS["Filebeat Juice Shop"]
  end

  %% OPNsense → Splunk
  subgraph OPNsense_Firewall
    SUR["Suricata EVE"]
    ZEN["Zenarmor IPDR"]
  end

  %% Wazuh pipeline
  DCW --> WZ_MGR
  PC1W --> WZ_MGR

  WZ_MGR --> LS

  %% Juice → Logstash
  JSAPP --> FB_JS
  FB_JS --> LS

  %% OPNsense → Splunk
  SUR --> SPL
  ZEN --> SPL

  %% Logstash → Splunk
  LS --> SPL

  %% Fleet & Velociraptor telemetry
  DCW --> FLEET
  PC1W --> FLEET

  DCW --> VEL
  PC1W --> VEL
```


