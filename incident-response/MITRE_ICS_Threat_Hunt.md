# MITRE ATT&CK ICS Threat Hunting Guide
**Focus Area:** Industrial Control Systems (ICS) / Modbus TCP Detection
**Framework:** MITRE ATT&CK for ICS v13

---

## Threat Hunt 1: Lateral Movement (T0890)
**Objective:** Identify unauthorized internal movement crossing Purdue Level 3.5 (DMZ) into Level 1/2 (Control).

### Hunting Query (OpenSearch/Elastic)
```kibana
# Look for traffic originating in the IT/Corporate subnets targeting known PLC IPs on Port 502
source.ip: 10.0.* AND destination.ip: 192.168.1.* AND destination.port: 502
```

### Analysis Steps
1. Filter out known Engineering Workstations.
2. Check for "New Host" alerts in Malcolm Passive Asset Discovery.
3. Correlate with Arkime SPI Graph to see the visual flow of traffic across zones.

---

## Threat Hunt 2: Modify Parameter (T0836)
**Objective:** Detect manipulation of critical process variables via Modbus Write commands.

### Hunting Query (Malcolm / Arkime)
```kibana
# Search for Modbus Function Codes 6 (Write Single) and 16 (Write Multiple)
modbus.function_code: (6 OR 16)
```

### Analysis Steps
1. Identify the register addresses being targeted.
2. Compare the values being written against historical operational baselines.
3. Validate if the source IP is authorized to perform configuration changes during the current time window.

---

## Threat Hunt 3: Alarm Suppression (T0804)
**Objective:** Identify attempts to suppress or disable alarms by writing to alarm-enable registers.

### Hunting Query (Suricata/Malcolm)
```kibana
# Look for Modbus writes specifically targeting the 40500-40600 register range (Alarm Config)
modbus.function_code: (6 OR 16) AND modbus.reference_number: [40500 TO 40600]
```

### MITRE ICS Matrix Mapping
- **Reconnaissance:** T0887 - Remote System Discovery
- **Inhibition of Response Function:** T0804 - Alarm Suppression
- **Impair Process Control:** T0836 - Modify Parameter
- **Impact:** T0814 - Denial of Control
