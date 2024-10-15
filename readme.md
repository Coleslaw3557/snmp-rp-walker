# Network Device Report Generator

This script catalogs Interfaces, OSPF adjacencies, and BGP peers in the up/full/established state and provides the specific OID that can be used in your NMS to monitor the state of that connection. This is helpful when building out your monitoring infrastructure and want specific OIDs to keep an eye on. The script also helps identify IPv6 peers since IOS-XR currently doesn't list v6 BGP Peers in a human-readable way like v4. This script was tested against IOS-XR 7.x but might be expanded in the future.

## Features

- Query multiple network devices
- Support for SNMPv2c and SNMPv3
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
python network_report_generator.py [options]
```

### Options:

- `-f, --file FILE`: File containing a list of IP addresses to scan
- `-i, --ips [IPS ...]`: IP address(es) to scan
- `-l, --list`: List IP addresses from the file without scanning

#### SNMPv2c options:
- `--v2c`: Use SNMPv2c
- `-c, --community [COMMUNITY ...]`: SNMP community string(s). The first one is used as default.

#### SNMPv3 options:
- `--v3`: Use SNMPv3
- `-u, --username USERNAME`: SNMPv3 username
- `-a, --auth-protocol {MD5,SHA}`: SNMPv3 authentication protocol
- `-A, --auth-password AUTH_PASSWORD`: SNMPv3 authentication password
- `-x, --priv-protocol {DES,AES}`: SNMPv3 privacy protocol
- `-X, --priv-password PRIV_PASSWORD`: SNMPv3 privacy password
- `-n, --context [CONTEXT ...]`: SNMPv3 context(s)

### Environment Variables:

The script supports the following environment variables for SNMPv3:

- `SNMP_USERNAME`: SNMPv3 username
- `SNMP_AUTH_PASSWORD`: SNMPv3 authentication password
- `SNMP_PRIV_PASSWORD`: SNMPv3 privacy password

### Examples:

1. Scan IP addresses from a file using SNMPv2c with two community strings:
   ```
   python network_report_generator.py --v2c -c public public-internet -f hosts.txt
   ```

2. Scan specific IP addresses using SNMPv3:
   ```
   python network_report_generator.py --v3 -u myuser -a SHA -A myauthpass -x AES -X myprivpass -i 192.168.1.1 192.168.1.2
   ```

3. Scan using SNMPv3 with environment variables and a context:
   ```
   export SNMP_USERNAME=myuser
   export SNMP_AUTH_PASSWORD=myauthpass
   export SNMP_PRIV_PASSWORD=myprivpass
   python network_report_generator.py --v3 -a SHA -x AES -n CTX-INTERNET -f hosts.txt
   ```

4. List IP addresses from a file without scanning:
   ```
   python network_report_generator.py -f hosts.txt -l
   ```

## VRF and SNMP Community Configuration

The script supports querying different VRFs on network devices by using multiple SNMP community strings or contexts. Here's an example of how SNMP might be configured on an IOS-XR device to support this:

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

When using the script with SNMPv2c, you would provide both community strings to query both VRFs:

```
python network_report_generator.py --v2c -c public public-internet -f hosts.txt
```

For SNMPv3, you would use contexts instead:

```
python network_report_generator.py --v3 -u myuser -a SHA -A myauthpass -x AES -X myprivpass -n CTX-INTERNET -f hosts.txt
```

## Output

The script generates a Markdown file named `network_report.md` containing the collected information for each scanned IP address, including data from all queried VRFs or contexts.

## Notes

- Ensure you have the necessary permissions to perform SNMP queries on the target devices.
- Make sure the SNMP version you're using (v2c or v3) is enabled on your network devices.

## Troubleshooting

- If you encounter "No Such Object available" errors, verify that the SNMP OIDs used in the script are supported by your network devices.
- For any "Timeout" errors, check network connectivity and ensure that SNMP is properly configured on the target devices.
- If you're not seeing data from a particular VRF, make sure you've provided the correct community string or context for that VRF.

## Contributing

Contributions, issues, and feature requests are welcome.

## License

[MIT](https://choosealicense.com/licenses/mit/)
