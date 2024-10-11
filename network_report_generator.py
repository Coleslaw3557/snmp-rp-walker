import sys
import subprocess
import logging
import ipaddress
import argparse
from typing import Dict, Any, List
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_device_info(ip: str, community: str) -> Dict[str, str]:
    logger.info(f"Getting device info for {ip}")
    info = {}
    oids = {
        'sysName': '1.3.6.1.2.1.1.5.0',
        'sysDescr': '1.3.6.1.2.1.1.1.0',
        'sysUpTime': '1.3.6.1.2.1.1.3.0',
        'sysContact': '1.3.6.1.2.1.1.4.0',
        'sysLocation': '1.3.6.1.2.1.1.6.0'
    }
    for key, oid in oids.items():
        cmd = f"snmpget -v2c -c {community} -On {ip} {oid}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout.strip()
        if output:
            value = output.split(' = ', 1)[-1].strip('"')
            info[key] = value.replace('STRING: ', '') if 'STRING: ' in value else value
        else:
            info[key] = 'N/A'
    return info

BGP_STATES = {
    '1': 'idle',
    '2': 'connect',
    '3': 'active',
    '4': 'opensent',
    '5': 'openconfirm',
    '6': 'established'
}

OSPF_STATES = {
    '1': 'Down',
    '2': 'Attempt',
    '3': 'Init',
    '4': '2-Way',
    '5': 'ExStart',
    '6': 'Exchange',
    '7': 'Loading',
    '8': 'Full'
}

BGP_PEER_OID = '.1.3.6.1.4.1.9.9.187.1.2.5.1'
OSPF_NEIGHBOR_OID = '1.3.6.1.2.1.14.10.1'

def run_snmpwalk(ip: str, community: str, oid: str) -> str:
    cmd = f"snmpwalk -v2c -c {community} -On {ip} {oid}"
    logger.debug(f"Running command: {cmd}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='latin-1')
        output = result.stdout.strip()
        logger.debug(f"SNMP walk output: {output[:200]}...")  # Log first 200 characters
        return output
    except subprocess.CalledProcessError as e:
        logger.error(f"SNMP walk failed for {ip} with OID {oid}: {str(e)}")
        return ""
    except Exception as e:
        logger.error(f"Error during SNMP walk for {ip} with OID {oid}: {str(e)}")
        return ""

def parse_ipv6_from_oid(oid_parts: List[str]) -> str:
    try:
        # Remove the leading '16' if present
        if oid_parts[0] == '16':
            oid_parts = oid_parts[1:]
        
        # Convert groups of numbers to hexadecimal
        hex_groups = []
        for i in range(0, len(oid_parts), 2):
            if i + 1 < len(oid_parts):
                hex_groups.append(f"{int(oid_parts[i]):02x}{int(oid_parts[i+1]):02x}")
        
        # Join groups with colons
        ipv6_addr = ':'.join(hex_groups)
        
        # Use ipaddress module to get the compressed representation
        return str(ipaddress.IPv6Address(ipv6_addr))
    except Exception as e:
        logger.error(f"Error parsing IPv6 address from OID parts {oid_parts}: {str(e)}")
        return "Invalid IPv6"

def parse_snmp_output(output: str) -> Dict[str, Dict[str, str]]:
    result = {}
    for line in output.split('\n'):
        try:
            if ' = ' not in line:
                continue
            oid, value = line.split(' = ', 1)
            oid_parts = oid.split('.')
            if len(oid_parts) < 16:  # Ensure we have the address type
                logger.warning(f"Skipping line due to insufficient OID parts: {line}")
                continue

            sub_oid = oid_parts[14]
            address_type = oid_parts[15]
            peer_address_parts = oid_parts[16:]

            if address_type == '1':  # IPv4
                # Remove the leading '4' and join the last 4 parts
                peer_address = '.'.join(peer_address_parts[-4:])
            elif address_type == '2':  # IPv6
                peer_address = parse_ipv6_from_oid(peer_address_parts)
            else:
                logger.warning(f"Unknown address type {address_type} in OID: {oid}")
                continue

            if peer_address not in result:
                result[peer_address] = {}
            result[peer_address][sub_oid] = {'value': value.strip(), 'oid': oid}
        except Exception as e:
            logger.error(f"Error processing SNMP output line: {line}")
            logger.error(f"Error details: {str(e)}")

    return result

def get_bgp_peers(ip: str, default_community: str, additional_communities: List[str]) -> Dict[str, Dict[str, Any]]:
    logger.info(f"Starting BGP peer discovery for {ip}")
    communities = [default_community] + additional_communities
    peers = {}

    for community in communities:
        logger.info(f"Querying with community: {community}")
        try:
            output = run_snmpwalk(ip, community, BGP_PEER_OID)
            if not output or "No Such Object available on this agent at this OID" in output:
                logger.warning(f"No BGP peers found for {ip} with community {community}")
                continue
            parsed_output = parse_snmp_output(output)
            logger.debug(f"Parsed output: {parsed_output}")
        except Exception as e:
            logger.error(f"Error during SNMP walk for {ip} with community {community}: {str(e)}")
            logger.error(f"SNMP walk output: {output[:1000]}...")  # Log first 1000 characters of output
            continue

        for peer_address, peer_data in parsed_output.items():
            if peer_address not in peers:
                peers[peer_address] = {
                    'address': peer_address,
                    'type': 'IPv6' if ':' in peer_address else 'IPv4',
                    'state': 'unknown',
                    'state_oid': '',
                    'remote_as': 'N/A',
                    'community': community
                }

            if '3' in peer_data:  # cbgpPeer2State
                peers[peer_address]['state'] = BGP_STATES.get(peer_data['3']['value'].split()[-1], 'unknown')
                peers[peer_address]['state_oid'] = peer_data['3']['oid']
            if '11' in peer_data:  # cbgpPeer2RemoteAs
                peers[peer_address]['remote_as'] = peer_data['11']['value'].split()[-1]

    return peers

def get_ospf_neighbors(ip: str, default_community: str, additional_communities: List[str]) -> List[Dict[str, Any]]:
    logger.info(f"Starting OSPF neighbor discovery for {ip}")
    communities = [default_community] + additional_communities
    all_neighbors = {}

    for community in communities:
        logger.info(f"Querying with community: {community}")
        try:
            neighbors_output = run_snmpwalk(ip, community, OSPF_NEIGHBOR_OID)
            
            # Parse neighbor IPs
            neighbor_ips = {}
            for line in neighbors_output.split('\n'):
                if '.1.3.6.1.2.1.14.10.1.1.' in line:
                    oid, value = line.split(' = ')
                    if 'IpAddress:' in value:
                        neighbor_ip = value.split('IpAddress: ')[1].strip()
                        neighbor_oids = oid.split('.')[-5:]  # Last 5 parts of OID
                        neighbor_oids = '.'.join(neighbor_oids)
                        neighbor_ips[neighbor_oids] = neighbor_ip

            # Get states for each neighbor
            for neighbor_oids, neighbor_ip in neighbor_ips.items():
                full_state_oid = f'{OSPF_NEIGHBOR_OID}.6.{neighbor_oids}'
                state_output = run_snmpwalk(ip, community, full_state_oid)
                state = 'Unknown'
                if state_output:
                    state_value = state_output.split(' = ')[-1].strip()
                    if state_value.startswith('INTEGER: '):
                        state = state_value.split('INTEGER: ')[1]
                state_meaning = OSPF_STATES.get(state, 'Unknown')
                
                # Only add or update if it's not already present (prioritize earlier communities)
                if neighbor_ip not in all_neighbors:
                    all_neighbors[neighbor_ip] = {
                        'ip': neighbor_ip,
                        'state': state,
                        'state_oid': full_state_oid,
                        'state_meaning': state_meaning,
                        'community': community
                    }

        except Exception as e:
            logger.error(f"Error during OSPF neighbor discovery for {ip} with community {community}: {str(e)}")

    logger.info(f"Found {len(all_neighbors)} unique OSPF neighbors")
    return list(all_neighbors.values())

def get_interfaces(ip: str, community: str) -> List[Dict[str, Any]]:
    logger.info(f"Starting get_interfaces function for {ip}")
    
    def run_snmpwalk(oid: str) -> Dict[str, str]:
        cmd = f"snmpwalk -v2c -c {community} {ip} {oid}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        output = result.stdout.strip().split('\n')
        if not output or output[0] == '':
            logger.warning(f"No output from SNMP walk for {oid} on {ip}")
            return {}
        try:
            return {line.split()[0]: line.split(' = ', 1)[-1].strip() for line in output}
        except IndexError:
            logger.error(f"Error parsing SNMP output for {oid} on {ip}: {output}")
            return {}
    
    status_data = run_snmpwalk('IF-MIB::ifOperStatus')
    name_data = run_snmpwalk('IF-MIB::ifDescr')
    description_data = run_snmpwalk('IF-MIB::ifAlias')
    
    if not status_data:
        logger.warning(f"No interface status data found for {ip}")
        return []
    
    interfaces = []
    
    for full_oid, status in status_data.items():
        if 'up(1)' in status:
            if_index = full_oid.split('.')[-1]
            name_oid = f'IF-MIB::ifDescr.{if_index}'
            desc_oid = f'IF-MIB::ifAlias.{if_index}'
            description = description_data.get(desc_oid, 'STRING: ').split(': ', 1)[-1].strip('"')
            if description == 'STRING:':
                description = ''
            interface = {
                'name': name_data.get(name_oid, 'Unknown').split(': ', 1)[-1].strip('"'),
                'description': description,
                'status': 'up',
                'status_oid': full_oid.replace('IF-MIB::ifOperStatus', '1.3.6.1.2.1.2.2.1.8')
            }
            interfaces.append(interface)
    
    logger.info(f"Total up interfaces for {ip}: {len(interfaces)}")
    return interfaces

def generate_markdown(ip: str, default_community: str, additional_communities: List[str]) -> str:
    device_info = get_device_info(ip, default_community)
    bgp_peers = get_bgp_peers(ip, default_community, additional_communities)
    ospf_neighbors = get_ospf_neighbors(ip, default_community, additional_communities)
    interfaces = get_interfaces(ip, default_community)

    markdown = f"# Network Device Report for {ip}\n\n"
    markdown += f"Report generated at: {get_timestamp()}\n\n"

    # Device Information
    markdown += "## Device Information\n\n"
    markdown += f"| Attribute | Value |\n"
    markdown += f"|-----------|-------|\n"
    for key, value in device_info.items():
        markdown += f"| {key} | {value} |\n"
    markdown += "\n"

    # BGP Peers
    markdown += "## BGP Peers\n\n"
    if bgp_peers:
        markdown += "| Neighbor | Type | AS | State | State OID | Community |\n"
        markdown += "|----------|------|----|---------|-----------|-----------|\n"
        for peer_address, info in bgp_peers.items():
            markdown += f"| {info['address']} | {info['type']} | {info['remote_as']} | {info['state']} | {info['state_oid']} | {info['community']} |\n"
    else:
        markdown += "No BGP peers found\n"

    # OSPF Neighbors
    markdown += "\n## OSPF Neighbors\n\n"
    if ospf_neighbors:
        markdown += "| Neighbor IP | State | State Meaning | StateOID | Community |\n"
        markdown += "|-------------|-------|---------------|----------|----------|\n"
        for neighbor in ospf_neighbors:
            markdown += f"| {neighbor['ip']} | {neighbor['state']} | {neighbor['state_meaning']} | {neighbor['state_oid']} | {neighbor['community']} |\n"
    else:
        markdown += "No OSPF neighbors found\n"

    # Interfaces
    markdown += f"\n## Interfaces\n\n"
    markdown += f"Total up interfaces: {len(interfaces)}\n\n"
    if interfaces:
        markdown += "| Interface | Description | Status | Status OID |\n"
        markdown += "|-----------|-------------|--------|------------|\n"
        for interface in interfaces:
            markdown += f"| {interface['name']} | {interface['description']} | {interface['status']} | {interface['status_oid']} |\n"
    else:
        markdown += "No up interfaces found\n"

    return markdown

def parse_arguments():
    parser = argparse.ArgumentParser(description="Network Device Report Generator")
    parser.add_argument("communities", nargs="+", help="SNMP community string(s). The first one is used as default.")
    parser.add_argument("-f", "--file", help="File containing list of IP addresses to scan")
    parser.add_argument("-i", "--ips", nargs="*", help="IP address(es) to scan")
    parser.add_argument("-l", "--list", action="store_true", help="List IP addresses from the file without scanning")
    return parser.parse_args()

def read_hosts_from_file(filename):
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logger.error(f"Hosts file '{filename}' not found.")
        return []

def main():
    args = parse_arguments()
    
    # Set up communities
    default_community = args.communities[0]
    additional_communities = args.communities[1:]
    
    # Get list of IP addresses
    if args.file:
        ip_addresses = read_hosts_from_file(args.file)
        if args.list:
            print("IP addresses in file:")
            for ip in ip_addresses:
                print(ip)
            return
    elif args.ips:
        ip_addresses = args.ips
    else:
        logger.error("No IP addresses specified. Use -f for a file or -i for inline IPs.")
        sys.exit(1)

    if not ip_addresses:
        logger.error("No valid IP addresses found.")
        sys.exit(1)

    logger.info(f"Using default community: {default_community}")
    logger.info(f"Additional communities: {', '.join(additional_communities)}")
    logger.info(f"Scanning {len(ip_addresses)} IP address(es)")

    with open('network_report.md', 'w') as f:
        f.write("# Network Device Report\n\n")
        f.write(f"Report generated at: {get_timestamp()}\n\n")

        for ip in ip_addresses:
            logger.info(f"Querying device info, BGP peers, OSPF neighbors, and interfaces for {ip}...")
            try:
                markdown_content = generate_markdown(ip, default_community, additional_communities)
                f.write(markdown_content)
                f.write("\n\n---\n\n")  # Separator between reports for different IPs
                logger.info(f"Completed report for {ip}")
            except Exception as e:
                logger.error(f"Error generating report for {ip}: {str(e)}")

    logger.info("Report generation completed. Saved to network_report.md")

if __name__ == "__main__":
    main()