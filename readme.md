# Network Device Report Generator

This Python script generates comprehensive network device reports using SNMP. It can query multiple devices for information about system details, BGP peers, OSPF neighbors, and interfaces, supporting multiple VRFs through different SNMP community strings. This script was designed specifically for IOS-XR Devices running 7.x. I'm open to pull requests if you want to add additional support.

## Features

- Query multiple network devices
- Support for multiple SNMP community strings to access different VRFs
- Gather information on:
  - Device details
  - BGP peers
  - OSPF neighbors
  - Interfaces
- Generate Markdown reports

## Requirements

- Python 3.6+
- See `requirements.txt` for Python package dependencies

## Installation

1. Clone this repository or download the script.
2. Install the required Python packages:

   ```
   pip install -r requirements.txt
   ```

## Usage

```
python network_report_generator.py <communities> [options]
```

### Arguments:

- `communities`: One or more SNMP community strings. Each community string may be associated with a different VRF.

### Options:

- `-f, --file FILE`: File containing a list of IP addresses to scan
- `-i, --ips [IPS ...]`: IP address(es) to scan
- `-l, --list`: List IP addresses from the file without scanning

### Examples:

1. Scan IP addresses from a file using two community strings (for different VRFs):
   ```
   python network_report_generator.py public public-internet -f hosts.txt
   ```

2. Scan specific IP addresses:
   ```
   python network_report_generator.py public -i 192.168.1.1 192.168.1.2
   ```

3. List IP addresses from a file without scanning:
   ```
   python network_report_generator.py public -f hosts.txt -l
   ```

## VRF and SNMP Community Configuration

The script supports querying different VRFs on network devices by using multiple SNMP community strings. Here's an example of how SNMP might be configured on an IOS-XR device to support this:

```
snmp-server vrf VRF-INTERNET
 context CTX-INTERNET
!
snmp-server community public RO IPv4 ACL4-MGMT-SNMPRO
snmp-server community public-internet RO IPv4 ACL4-MGMT-SNMPRO
snmp-server context CTX-INTERNET
snmp-server community-map public-internet context CTX-INTERNET
snmp-server ifindex persist
snmp-server ifmib stats cache
snmp-server mibs cbqosmib persist
```

In this configuration:
- `public` is the community string for the default VRF
- `public-internet` is the community string for the `VRF-INTERNET` VRF

When using the script, you would provide both community strings to query both VRFs:

```
python network_report_generator.py public public-internet -f hosts.txt
```

## Output

The script generates a Markdown file named `network_report.md` containing the collected information for each scanned IP address, including data from all queried VRFs.


## Example Output

```
$python3 network_report_generator.py public public-internet -i www.xxx.yyy.zzz

2024-10-11 12:27:28,646 - INFO - Using default community: public
2024-10-11 12:27:28,646 - INFO - Additional communities: public-internet
2024-10-11 12:27:28,646 - INFO - Scanning 1 IP address(es)
2024-10-11 12:27:28,646 - INFO - Querying device info, BGP peers, OSPF neighbors, and interfaces for www.xxx.yyy.zzz...
2024-10-11 12:27:28,646 - INFO - Getting device info for www.xxx.yyy.zzz
2024-10-11 12:27:28,975 - INFO - Starting BGP peer discovery for www.xxx.yyy.zzz
2024-10-11 12:27:28,976 - INFO - Querying with community: public
2024-10-11 12:27:31,767 - INFO - Querying with community: public-internet
2024-10-11 12:27:37,350 - INFO - Starting OSPF neighbor discovery for www.xxx.yyy.zzz
2024-10-11 12:27:37,351 - INFO - Querying with community: public
2024-10-11 12:27:39,287 - INFO - Querying with community: public-internet
2024-10-11 12:27:41,221 - INFO - Found 3 unique OSPF neighbors
2024-10-11 12:27:41,221 - INFO - Starting get_interfaces function for www.xxx.yyy.zzz
2024-10-11 12:27:57,334 - INFO - Total up interfaces for www.xxx.yyy.zzz: 18
2024-10-11 12:27:57,335 - INFO - Completed report for www.xxx.yyy.zzz
2024-10-11 12:27:57,336 - INFO - Report generation completed. Saved to network_report.md
```

# Network Device Report

Report generated at: 2024-10-11 12:27:28

# Network Device Report for <ip address>

Report generated at: 2024-10-11 12:27:57

## Device Information

| Attribute | Value |
|-----------|-------|
| sysName | exciting.potato.local |
| sysDescr | Cisco IOS XR Software, Version 7.7.21  Copyright (c) 2013-2023 by Cisco Systems, Inc. |
| sysUpTime | Timeticks: (639352884) 73 days, 23:58:48.84 |
| sysContact | Mr.Nagios |
| sysLocation | Hell |

## BGP Peers

| Neighbor | Type | AS | State | State OID | Community |
|----------|------|----|---------|-----------|-----------|


## OSPF Neighbors

| Neighbor IP | State | State Meaning | StateOID | Community |
|-------------|-------|---------------|----------|----------|


## Interfaces

Total up interfaces:

| Interface | Description | Status | Status OID |
|-----------|-------------|--------|------------|

---


## Notes

- Ensure you have the necessary permissions to perform SNMP queries on the target devices.
- The script uses SNMP version 2c. Make sure this version is enabled on your network devices.

## Troubleshooting

- If you encounter "No Such Object available" errors, verify that the SNMP OIDs used in the script are supported by your network devices.
- For any "Timeout" errors, check network connectivity and ensure that SNMP is properly configured on the target devices.
- If you're not seeing data from a particular VRF, make sure you've provided the correct community string for that VRF.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check [issues page](https://github.com/yourusername/network-report-generator/issues) if you want to contribute.

## License

[MIT](https://choosealicense.com/licenses/mit/)
