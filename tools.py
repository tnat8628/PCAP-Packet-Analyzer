import json
import base64
import datetime
import sys
import io
from crewai.tools import tool

# Import necessary components from Scapy
from scapy.all import PcapReader, Ether, IP, TCP, UDP, DNS, Raw, ICMP # rdpcap removed if not explicitly used by tools
from scapy.layers.http import HTTP
# Explicitly import potential layers that might be needed
from scapy.all import load_layer
try:
    load_layer("tls")
    load_layer("http") # Already imported above, but good practice if other layers are needed
    # Add other layers if needed, e.g., load_layer("smb") etc.
except ImportError as e:
    print(f"Warning: Could not load all Scapy layers (e.g., http, tls): {e}")
    print("Analysis of certain protocols might be limited.")
except Exception as e:
     print(f"Warning: An unexpected error occurred while loading Scapy layers: {e}")


# --- Helper Function to Format Packet Details ---
def format_packet_details(packet, packet_index, packet_timestamp):
    """Formats key details of a packet into a dictionary for structured output."""
    details = {
        "packet_index": packet_index,
        "timestamp": datetime.datetime.fromtimestamp(packet_timestamp).strftime('%Y-%m-%d %H:%M:%S.%f'), # Human readable timestamp
        "summary": packet.summary(), # Scapy's summary line
        "layers": [],
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "payload_len": 0,
        "application_layer": {} # Placeholder for app layer details
    }

    current_layer = packet
    while current_layer:
        layer_name = current_layer.name
        details["layers"].append(layer_name)

        if IP in current_layer:
            details["src_ip"] = current_layer[IP].src
            details["dst_ip"] = current_layer[IP].dst
            details["protocol"] = IP.get_ip_proto(current_layer[IP].proto) if current_layer[IP].proto in IP.services else str(current_layer[IP].proto)

        if TCP in current_layer:
            details["src_port"] = current_layer[TCP].sport
            details["dst_port"] = current_layer[TCP].dport
            details["protocol"] = 'TCP'
            details["tcp_flags"] = str(current_layer[TCP].flags)
            details["tcp_seq"] = current_layer[TCP].seq
            details["tcp_ack"] = current_layer[TCP].ack
            details["tcp_window"] = current_layer[TCP].window

        elif UDP in current_layer:
            details["src_port"] = current_layer[UDP].sport
            details["dst_port"] = current_layer[UDP].dport
            details["protocol"] = 'UDP'

        elif ICMP in current_layer:
             details["protocol"] = 'ICMP'
             details["icmp_type"] = current_layer[ICMP].type
             details["icmp_code"] = current_layer[ICMP].code

        if HTTP in current_layer:
             details["protocol"] = 'HTTP'
             details["application_layer"]["type"] = "HTTP"
             if hasattr(current_layer[HTTP], 'Method'): # Request
                 details["application_layer"]["flow"] = "request"
                 details["application_layer"]["method"] = current_layer[HTTP].Method.decode(errors='ignore') if hasattr(current_layer[HTTP].Method, 'decode') else str(current_layer[HTTP].Method)
                 details["application_layer"]["host"] = current_layer[HTTP].Host.decode(errors='ignore') if hasattr(current_layer[HTTP].Host, 'decode') else str(current_layer[HTTP].Host) if hasattr(current_layer[HTTP], 'Host') else None
                 details["application_layer"]["path"] = current_layer[HTTP].Path.decode(errors='ignore') if hasattr(current_layer[HTTP].Path, 'decode') else str(current_layer[HTTP].Path) if hasattr(current_layer[HTTP], 'Path') else None
                 details["application_layer"]["http_version"] = current_layer[HTTP].Http_Version.decode(errors='ignore') if hasattr(current_layer[HTTP].Http_Version, 'decode') else str(current_layer[HTTP].Http_Version) if hasattr(current_layer[HTTP], 'Http_Version') else None
             elif hasattr(current_layer[HTTP], 'Status'): # Response
                  details["application_layer"]["flow"] = "response"
                  details["application_layer"]["status"] = current_layer[HTTP].Status.decode(errors='ignore') if hasattr(current_layer[HTTP].Status, 'decode') else str(current_layer[HTTP].Status)
                  details["application_layer"]["reason"] = current_layer[HTTP].Reason.decode(errors='ignore') if hasattr(current_layer[HTTP].Reason, 'decode') else str(current_layer[HTTP].Reason) if hasattr(current_layer[HTTP], 'Reason') else None
                  details["application_layer"]["http_version"] = current_layer[HTTP].Http_Version.decode(errors='ignore') if hasattr(current_layer[HTTP].Http_Version, 'decode') else str(current_layer[HTTP].Http_Version) if hasattr(current_layer[HTTP], 'Http_Version') else None

        elif DNS in current_layer:
             details["protocol"] = 'DNS'
             details["application_layer"]["type"] = "DNS"
             details["application_layer"]["qr"] = "Response" if current_layer[DNS].qr else "Query"
             details["application_layer"]["id"] = current_layer[DNS].id
             details["application_layer"]["qdcount"] = current_layer[DNS].qdcount
             details["application_layer"]["ancount"] = current_layer[DNS].ancount
             details["application_layer"]["nscount"] = current_layer[DNS].nscount
             details["application_layer"]["arcount"] = current_layer[DNS].arcount
             details["application_layer"]["questions"] = []
             if current_layer[DNS].qdcount > 0 and hasattr(current_layer[DNS], 'qd') and current_layer[DNS].qd:
                 qds = current_layer[DNS].qd if isinstance(current_layer[DNS].qd, list) else [current_layer[DNS].qd]
                 for q in qds:
                     details["application_layer"]["questions"].append({
                         "qname": q.qname.decode(errors='ignore') if hasattr(q.qname, 'decode') else str(q.qname),
                         "qtype": q.qtype,
                         "qclass": q.qclass
                     })
             details["application_layer"]["answers"] = []
             if current_layer[DNS].ancount > 0 and hasattr(current_layer[DNS], 'an') and current_layer[DNS].an:
                  ans = current_layer[DNS].an if isinstance(current_layer[DNS].an, list) else [current_layer[DNS].an]
                  for a in ans:
                       answer_detail = {
                            "rrname": a.rrname.decode(errors='ignore') if hasattr(a.rrname, 'decode') else str(a.rrname),
                            "type": a.type,
                            "class": a.rclass,
                            "ttl": a.ttl
                       }
                       if hasattr(a, 'rdata'):
                            try:
                                 answer_detail["rdata"] = a.rdata.decode(errors='ignore') if hasattr(a.rdata, 'decode') else str(a.rdata)
                            except Exception:
                                 answer_detail["rdata"] = str(a.rdata)
                       details["application_layer"]["answers"].append(answer_detail)

        try:
             # Check for TLS layer by name if loaded
             if 'TLS' in details["layers"]:
                 details["protocol"] = 'TLS/SSL'
                 details["application_layer"]["type"] = "TLS/SSL"
        except NameError: pass # load_layer('tls') might fail

        if Raw in current_layer:
             details["payload_len"] = len(current_layer[Raw].load)

        current_layer = current_layer.payload if hasattr(current_layer, 'payload') else None
        if not current_layer: break

    return details


# --- Define Tools ---

@tool("PCAP Overview Tool")
def pcap_overview(pcap_file_path: str) -> str:
    """
    Reads a PCAP file and provides a high-level summary including total packet count,
    protocol distribution, and top source/destination IP pairs and ports.
    Returns the summary as a JSON formatted string.
    """
    try:
        protocol_counts = {}
        ip_pairs = {}
        port_counts = {}
        total_packets = 0

        with PcapReader(pcap_file_path) as pr:
            for packet in pr:
                total_packets += 1

                if Ether in packet: protocol_counts['Ethernet'] = protocol_counts.get('Ethernet', 0) + 1
                if IP in packet:
                    protocol_counts['IP'] = protocol_counts.get('IP', 0) + 1
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    ip_pairs[(src_ip, dst_ip)] = ip_pairs.get((src_ip, dst_ip), 0) + 1

                    if TCP in packet:
                        protocol_counts['TCP'] = protocol_counts.get('TCP', 0) + 1
                        src_port = packet[TCP].sport
                        dst_port = packet[TCP].dport
                        port_counts[f"{src_port}/TCP(src)"] = port_counts.get(f"{src_port}/TCP(src)", 0) + 1
                        port_counts[f"{dst_port}/TCP(dst)"] = port_counts.get(f"{dst_port}/TCP(dst)", 0) + 1

                        # Check for application layer protocols within TCP
                        if HTTP in packet: protocol_counts['HTTP'] = protocol_counts.get('HTTP', 0) + 1
                        # Check for TLS layer
                        try:
                            # Use haslayer with string name as load_layer might not put it in locals() globally
                            if packet.haslayer("TLS"):
                                protocol_counts['TLS/SSL'] = protocol_counts.get('TLS/SSL', 0) + 1
                            # Fallback check by port if TLS layer isn't loaded/detected
                            elif dst_port == 443 or src_port == 443: protocol_counts['HTTPS (Port 443)'] = protocol_counts.get('HTTPS (Port 443)', 0) + 1
                            if dst_port == 8443 or src_port == 8443: protocol_counts['Port 8443 (TCP)'] = protocol_counts.get('Port 8443 (TCP)', 0) + 1
                        except Exception: # Catch potential errors if TLS wasn't loaded correctly
                             if dst_port == 443 or src_port == 443: protocol_counts['HTTPS (Port 443)'] = protocol_counts.get('HTTPS (Port 443)', 0) + 1
                             if dst_port == 8443 or src_port == 8443: protocol_counts['Port 8443 (TCP)'] = protocol_counts.get('Port 8443 (TCP)', 0) + 1


                    elif UDP in packet:
                        protocol_counts['UDP'] = protocol_counts.get('UDP', 0) + 1
                        src_port = packet[UDP].sport
                        dst_port = packet[UDP].dport
                        port_counts[f"{src_port}/UDP(src)"] = port_counts.get(f"{src_port}/UDP(src)", 0) + 1
                        port_counts[f"{dst_port}/UDP(dst)"] = port_counts.get(f"{dst_port}/UDP(dst)", 0) + 1
                        # Check for application layer protocols within UDP
                        if DNS in packet: protocol_counts['DNS'] = protocol_counts.get('DNS', 0) + 1
                        # Fallback check by port
                        if dst_port == 53 or src_port == 53: protocol_counts['DNS (Port 53)'] = protocol_counts.get('DNS (Port 53)', 0) + 1

                    elif ICMP in packet:
                        protocol_counts['ICMP'] = protocol_counts.get('ICMP', 0) + 1

                if Raw in packet:
                     protocol_counts['Raw Data'] = protocol_counts.get('Raw Data', 0) + 1
                # Consider packets without IP (e.g., ARP, only Ether)
                elif Ether in packet and 'Ethernet' not in protocol_counts:
                     protocol_counts['Ethernet'] = protocol_counts.get('Ethernet', 0) + 1


        if total_packets == 0:
            return json.dumps({"error": f"No packets found in {pcap_file_path}"})

        summary_data = {
            "total_packets": total_packets,
            "protocol_distribution": {k: v for k, v in sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)},
            "top_ip_pairs": [{f"{src} -> {dst}": count} for (src, dst), count in sorted(ip_pairs.items(), key=lambda item: item[1], reverse=True)[:15]],
            "top_ports": [{f"{port_info}": count} for port_info, count in sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:15]]
        }

        return json.dumps(summary_data, indent=2)

    except FileNotFoundError:
        return json.dumps({"error": f"File not found at {pcap_file_path}"})
    except Exception as e:
        return json.dumps({"error": f"Error reading PCAP file: {e}"})


@tool("PCAP Find Packets Tool")
def find_packets(pcap_file_path: str, search_criteria: str) -> str:
    """
    Searches for packets in a PCAP file matching specific criteria and returns details.
    Criteria can include: 'src_ip=X', 'dst_ip=Y', 'src_port=P', 'dst_port=Q', 'protocol=tcp/udp/icmp/http/dns/tls/ssl', 'has_layer=HTTP/DNS/Raw/TLS/etc.', 'payload_contains=string', 'tcp_flags=S/A/F/R/P/U'. Combine criteria with AND.
    Returns a list of matching packet details (limited to first 30 matches) as a JSON formatted string.
    """
    try:
        matching_packets = []
        search_criteria = search_criteria.lower() if search_criteria else ""

        def matches_criteria(packet):
            if not search_criteria: return True

            criteria_list = [c.strip() for c in search_criteria.split(' and ') if c.strip()]
            if not criteria_list: return True

            for criterion in criteria_list:
                parts = criterion.split('=')
                if len(parts) != 2: continue

                key, value = parts[0], parts[1]
                match = False

                # Handle 'has_layer' separately first as it doesn't require IP
                if key == 'has_layer':
                     try:
                         # Use haslayer method which works with string layer names
                         if packet.haslayer(value.upper()): # Scapy layer names are typically capitalized
                             match = True
                         # Handle common aliases
                         elif value.lower() in ['tls', 'ssl'] and packet.haslayer("TLS"): match = True
                         elif value.lower() == 'ethernet' and packet.haslayer("Ethernet"): match = True
                         elif value.lower() == 'ip' and packet.haslayer("IP"): match = True
                         elif value.lower() == 'tcp' and packet.haslayer("TCP"): match = True
                         elif value.lower() == 'udp' and packet.haslayer("UDP"): match = True
                         elif value.lower() == 'icmp' and packet.haslayer("ICMP"): match = True
                         elif value.lower() == 'http' and packet.haslayer("HTTP"): match = True
                         elif value.lower() == 'dns' and packet.haslayer("DNS"): match = True
                         elif value.lower() == 'raw' and packet.haslayer("Raw"): match = True
                     except Exception:
                         # Handle cases where layer might not be loaded or recognized string
                         pass


                elif key == 'protocol':
                    # Check IP protocol if IP layer exists
                    if IP in packet:
                        proto_name = IP.get_ip_proto(packet[IP].proto).lower() if packet[IP].proto in IP.services else str(packet[IP].proto)
                        if proto_name == value: match = True
                    # Also check specific layers directly if they exist
                    elif value == 'tcp' and TCP in packet: match = True
                    elif value == 'udp' and UDP in packet: match = True
                    elif value == 'icmp' and ICMP in packet: match = True
                    elif value == 'http' and HTTP in packet: match = True
                    elif value == 'dns' and DNS in packet: match = True
                    elif value in ['tls', 'ssl', 'tls/ssl']:
                         # Check for TLS layer by name string
                         try:
                            if packet.haslayer("TLS"): match = True
                         except Exception: pass

                elif IP in packet: # Criteria below this point require IP layer
                    if key == 'src_ip' and packet[IP].src.lower() == value: match = True
                    elif key == 'dst_ip' and packet[IP].dst.lower() == value: match = True

                    if TCP in packet:
                        if key == 'src_port' and str(packet[TCP].sport) == value: match = True
                        elif key == 'dst_port' and str(packet[TCP].dport) == value: match = True
                        if key.startswith('tcp_flags_') and len(key) == 11:
                             flag_char = key[-1].upper()
                             if flag_char in str(packet[TCP].flags): match = True
                        elif key == 'tcp_flags': # Allow checking for multiple flags, e.g., 'tcp_flags=SA'
                             if all(f.upper() in str(packet[TCP].flags) for f in value): match = True


                    elif UDP in packet:
                        if key == 'src_port' and str(packet[UDP].sport) == value: match = True
                        elif key == 'dst_port' and str(packet[UDP].dport) == value: match = True

                    if key == 'payload_contains' and Raw in packet:
                        try:
                            payload = bytes(packet[Raw].load)
                            # Decode search value to bytes if it's a string, handle potential encoding issues
                            search_bytes = value.encode('utf-8', errors='ignore').lower()
                            if search_bytes in payload.lower(): match = True
                        except Exception: pass

                else: # Criteria that require specific layers other than IP (should be handled by has_layer, but left here for potential protocol checks)
                     pass # Already handled by the 'protocol' and 'has_layer' checks above

                # If any criterion doesn't match, the whole packet doesn't match
                if not match: return False

            # If all criteria matched (or no criteria), return True
            return True


        packet_index = 0
        with PcapReader(pcap_file_path) as pr:
            for packet in pr:
                # Basic check if it's a packet we can potentially analyze (ethernet or higher)
                if Ether in packet or packet.layers():
                     if matches_criteria(packet):
                         matching_packets.append(format_packet_details(packet, packet_index, packet.time))
                         if len(matching_packets) >= 30: # Limit results
                             # Process the current packet before breaking
                             packet_index += 1 # Ensure index is incremented even if we break after adding
                             break
                packet_index += 1 # Increment for every packet read

        return json.dumps(matching_packets, indent=2)

    except FileNotFoundError:
        return json.dumps({"error": f"File not found at {pcap_file_path}"})
    except Exception as e:
        return json.dumps({"error": f"Error searching PCAP file with criteria '{search_criteria}': {e}"})


@tool("PCAP Get Packet Details Tool")
def get_packet_details(pcap_file_path: str, packet_index: int) -> str:
    """
    Retrieves detailed information for a specific packet by its index. Index is 0-based.
    Returns comprehensive packet details as a JSON formatted string, including Scapy's verbose output.
    """
    try:
        with PcapReader(pcap_file_path) as pr:
            for i, packet in enumerate(pr):
                if i == packet_index:
                    details = format_packet_details(packet, i, packet.time)
                    # Capture Scapy's show2 output
                    old_stdout = sys.stdout
                    sys.stdout = text_capture = io.StringIO()
                    try:
                        # Using show2(dump=True) prints to stdout, we capture it
                        packet.show2(dump=True)
                    except Exception as show_err:
                         # Handle potential errors in show2 for malformed packets
                         text_capture.write(f"Error generating verbose output: {show_err}\n")
                         text_capture.write(str(packet)) # Fallback to simple str(packet)
                    finally:
                        sys.stdout = old_stdout
                    details["scapy_verbose_output"] = text_capture.getvalue()
                    return json.dumps(details, indent=2)

            return json.dumps({"error": f"Packet with index {packet_index} not found in {pcap_file_path}"})

    except FileNotFoundError:
        return json.dumps({"error": f"File not found at {pcap_file_path}"})
    except Exception as e:
        return json.dumps({"error": f"Error retrieving packet index {packet_index}: {e}"})


@tool("PCAP Get Packet Payload Tool")
def get_packet_payload(pcap_file_path: str, packet_index: int) -> str:
    """
    Retrieves the raw payload data for a specific packet by its index. Returns the payload as a base64 encoded string in a JSON object.
    Returns an error JSON if no raw payload is found or index is invalid.
    """
    try:
        with PcapReader(pcap_file_path) as pr:
            for i, packet in enumerate(pr):
                if i == packet_index:
                    if Raw in packet:
                        payload = bytes(packet[Raw].load)
                        payload_base64 = base64.b64encode(payload).decode('ascii')
                        return json.dumps({
                            "packet_index": packet_index,
                            "payload_length": len(payload),
                            "payload_base64": payload_base64,
                            # Add a readable preview, handle potential decoding errors
                            "payload_preview_ascii": payload[:256].decode('ascii', errors='replace')
                        }, indent=2)
                    else:
                        return json.dumps({"error": f"Packet index {packet_index} has no raw payload data."}, indent=2)

            return json.dumps({"error": f"Packet with index {packet_index} not found in {pcap_file_path}"}, indent=2)

    except FileNotFoundError:
        return json.dumps({"error": f"File not found at {pcap_file_path}"})
    except Exception as e:
        return json.dumps({"error": f"Error retrieving payload for packet index {packet_index}: {e}"}, indent=2)


@tool("PCAP Extract Timeline Events Tool")
def extract_timeline_events(pcap_file_path: str, limit: int = 100) -> str:
    """
    Extracts a timeline of key events from the FIRST N packets of the PCAP file (where N is 'limit').
    Includes timestamp, index, summary, IPs/Ports, and potential event type (SYN, FIN, RST, ICMP, DNS Query/Response, HTTP Request/Response, TLS, Raw).
    Returns a list of event dictionaries as a JSON formatted string. Events are in file order (approx. timeline).
    """
    try:
        events = []
        with PcapReader(pcap_file_path) as pr:
            for packet_index, packet in enumerate(pr):
                if packet_index >= limit: break

                event = {
                    "packet_index": packet_index,
                    "timestamp": datetime.datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                    "summary": packet.summary(),
                    "event_type": "Other",
                    "src_ip": None, "dst_ip": None,
                    "src_port": None, "dst_port": None,
                }

                if IP in packet:
                    event["src_ip"] = packet[IP].src
                    event["dst_ip"] = packet[IP].dst

                    if TCP in packet:
                        event["src_port"] = packet[TCP].sport
                        event["dst_port"] = packet[TCP].dport
                        flags = str(packet[TCP].flags)
                        if 'S' in flags and 'A' not in flags: event["event_type"] = "TCP_SYN"
                        elif 'S' in flags and 'A' in flags: event["event_type"] = "TCP_SYNACK"
                        elif 'F' in flags: event["event_type"] = "TCP_FIN"
                        elif 'R' in flags: event["event_type"] = "TCP_RST"
                        elif 'P' in flags and Raw in packet: event["event_type"] = "TCP_PSH_Data"
                        elif 'A' in flags: event["event_type"] = "TCP_ACK"

                        if HTTP in packet:
                             event["event_type"] = "HTTP_Request" if hasattr(packet[HTTP], 'Method') else "HTTP_Response" if hasattr(packet[HTTP], 'Status') else "HTTP"
                             # Decode method/status safely
                             if event["event_type"] == "HTTP_Request" and hasattr(packet[HTTP], 'Method'):
                                 event["http_method"] = packet[HTTP].Method.decode(errors='ignore') if hasattr(packet[HTTP].Method, 'decode') else str(packet[HTTP].Method)
                             if event["event_type"] == "HTTP_Response" and hasattr(packet[HTTP], 'Status'):
                                  event["http_status"] = packet[HTTP].Status.decode(errors='ignore') if hasattr(packet[HTTP].Status, 'decode') else str(packet[HTTP].Status)


                        # Check for TLS layer by name string
                        try:
                            if packet.haslayer("TLS"): event["event_type"] = "TLS/SSL"
                        except Exception: pass # Catch if haslayer("TLS") fails


                    elif UDP in packet:
                        event["src_port"] = packet[UDP].sport
                        event["dst_port"] = packet[UDP].dport
                        if DNS in packet:
                             event["event_type"] = "DNS_Query" if packet[DNS].qr == 0 else "DNS_Response" if packet[DNS].qr == 1 else "DNS"
                             if event["event_type"] == "DNS_Query" and packet[DNS].qdcount > 0 and hasattr(packet[DNS], 'qd'):
                                 # Ensure qd is iterable if it's a single query
                                 qds = packet[DNS].qd if isinstance(packet[DNS].qd, list) else [packet[DNS].qd]
                                 # Just take the first query name for simplicity in the event summary
                                 if qds:
                                     q = qds[0]
                                     event["dns_qname"] = q.qname.decode(errors='ignore') if hasattr(q.qname, 'decode') else str(q.qname)
                                     event["dns_qtype"] = q.qtype # Integer code


                    elif ICMP in packet:
                        event["event_type"] = "ICMP"
                        if hasattr(packet[ICMP], 'type'):
                             # Get ICMP type name safely
                             icmp_type_name = ICMP.type.get(packet[ICMP].type, f"Type {packet[ICMP].type}")
                             event["event_type"] = f"ICMP_{icmp_type_name.replace(' ', '_')}"

                if Raw in packet and event["event_type"] == "Other":
                     event["event_type"] = "Raw_Data"
                # Consider Ethernet-only packets as events if no IP/higher layer is present
                elif Ether in packet and event["event_type"] == "Other":
                     event["event_type"] = "Ethernet"


                events.append(event)

        # Note: This timeline is based on the first 'limit' packets in file order.
        # A true timeline requires sorting all packets, potentially large memory use.

        return json.dumps(events, indent=2)

    except FileNotFoundError:
        return json.dumps({"error": f"File not found at {pcap_file_path}"})
    except Exception as e:
        return json.dumps({"error": f"Error extracting timeline events: {e}"})

# Define the list of common tools to be imported by agents
common_tools = [
    pcap_overview,
    find_packets,
    get_packet_details,
    get_packet_payload,
    extract_timeline_events
]

# Define the overview tool specifically as it's only used by one agent initially
pcap_overview_tool = pcap_overview