import os
import sys
from dotenv import load_dotenv
from crewai import Agent, Task, Crew
from crewai.tools import tool
# CrewAI uses ChatOpenAI internally, which relies on the openai library
from langchain_openai import ChatOpenAI

# Import necessary components from Scapy
# Remove HTTP from the scapy.all import
from scapy.all import rdpcap, Ether, IP, TCP, UDP, DNS, Raw, ICMP
# Import load_layer if not already available in scapy.all or explicitly load it
# Note: In recent Scapy versions, load_layer is often directly available after `import scapy.all`
# If not, you might need: from scapy.all import load_layer

# --- Load necessary layers ---
# Explicitly load the HTTP layer, as it's not in scapy.all by default
try:
    from scapy.all import load_layer
    load_layer("http")
    # Now HTTP class should be available
    from scapy.layers.http import HTTP # Or just rely on it being available in global scope after load_layer
except ImportError as e:
    print(f"Warning: Could not load HTTP layer or import necessary Scapy components: {e}")
    print("HTTP analysis might be limited.")
    # Define a dummy HTTP class if needed to prevent NameError later,
    # though the tool logic only checks ports, not the HTTP layer itself currently.
    # For this tool, just removing the `HTTP in packet` check might be simpler
    # if loading the layer fails for some reason. Let's keep the check for now,
    # assuming load_layer succeeds if Scapy is installed correctly.


# Load environment variables from .env file
load_dotenv()

# ... (rest of your code remains the same)

# --- Define Tools ---
@tool("PCAP Reader Summary Tool")
def read_pcap_summary(pcap_file_path: str) -> str:
    """Reads a PCAP file and provides a high-level summary of its contents."""
    try:
        packets = rdpcap(pcap_file_path)
        total_packets = len(packets)

        if total_packets == 0:
            return f"Error: No packets found in {pcap_file_path}"

        protocol_counts = {}
        ip_pairs = {}
        port_counts = {}

        for packet in packets:
            # Count general protocols
            if Ether in packet:
                protocol_counts['Ethernet'] = protocol_counts.get('Ethernet', 0) + 1
            if IP in packet:
                protocol_counts['IP'] = protocol_counts.get('IP', 0) + 1
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_pairs[(src_ip, dst_ip)] = ip_pairs.get((src_ip, dst_ip), 0) + 1

                if TCP in packet:
                    protocol_counts['TCP'] = protocol_counts.get('TCP', 0) + 1
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                    port_counts[(src_port, 'TCP_SRC')] = port_counts.get((src_port, 'TCP_SRC'), 0) + 1
                    port_counts[(dst_port, 'TCP_DST')] = port_counts.get((dst_port, 'TCP_DST'), 0) + 1
                    # Check for common application layers over TCP by port
                    if dst_port == 80 or src_port == 80:
                         protocol_counts['HTTP (TCP)'] = protocol_counts.get('HTTP (TCP)', 0) + 1
                    if dst_port == 443 or src_port == 443:
                         protocol_counts['HTTPS (TCP)'] = protocol_counts.get('HTTPS (TCP)', 0) + 1
                    if dst_port == 22 or src_port == 22:
                         protocol_counts['SSH (TCP)'] = protocol_counts.get('SSH (TCP)', 0) + 1
                    # --- Add check for HTTP layer itself if load_layer was successful ---
                    # This check relies on the HTTP layer being loaded.
                    # You might remove this check if load_layer("http") fails and you
                    # don't want the program to crash, but the port check is usually sufficient
                    # for a high-level summary. Let's keep it for potentially more accurate counting
                    # if the packet *actually* contains the HTTP layer structure recognized by Scapy.
                    try:
                        if HTTP in packet: # Check if the HTTP layer is present in the packet
                             # Increment the general HTTP count, maybe not specific to TCP here
                             # Or refine: protocol_counts['HTTP Layer Detected'] = protocol_counts.get('HTTP Layer Detected', 0) + 1
                             pass # The port check is usually enough for summary, avoid double counting
                    except NameError:
                        # HTTP class not available (load_layer failed or not called)
                        pass # Ignore this check if HTTP class doesn't exist

                elif UDP in packet:
                    protocol_counts['UDP'] = protocol_counts.get('UDP', 0) + 1
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                    port_counts[(src_port, 'UDP_SRC')] = port_counts.get((src_port, 'UDP_SRC'), 0) + 1
                    port_counts[(dst_port, 'UDP_DST')] = port_counts.get((dst_port, 'UDP_DST'), 0) + 1
                    # Check for common application layers over UDP by port
                    if dst_port == 53 or src_port == 53:
                         protocol_counts['DNS (UDP)'] = protocol_counts.get('DNS (UDP)', 0) + 1
                    if dst_port == 123 or src_port == 123:
                         protocol_counts['NTP (UDP)'] = protocol_counts.get('NTP (UDP)', 0) + 1
                    # --- Add check for DNS layer itself if available ---
                    try:
                        if DNS in packet: # DNS is often included in scapy.all, but good to be aware
                            # Increment DNS count based on layer presence, not just port
                            # This might be slightly more accurate than just port 53
                             protocol_counts['DNS Layer'] = protocol_counts.get('DNS Layer', 0) + 1
                    except NameError:
                         pass # Ignore if DNS class doesn't exist

                elif ICMP in packet:
                    protocol_counts['ICMP'] = protocol_counts.get('ICMP', 0) + 1

                if Raw in packet:
                     protocol_counts['Raw Data'] = protocol_counts.get('Raw Data', 0) + 1

        # ... (rest of the tool function logic remains the same)
        # Sort protocols, IPs, ports, build summary string...
        sorted_protocols = sorted(protocol_counts.items(), key=lambda item: item[1], reverse=True)
        sorted_ip_pairs = sorted(ip_pairs.items(), key=lambda item: item[1], reverse=True)[:15]
        sorted_ports = sorted(port_counts.items(), key=lambda item: item[1], reverse=True)[:15]

        summary = f"""PCAP Analysis Summary for {pcap_file_path}:

Total Packets: {total_packets}

Protocol Distribution:
{'-' * 20}
"""
        if sorted_protocols:
            for proto, count in sorted_protocols:
                summary += f"- {proto}: {count} packets ({count/total_packets:.2%})\n"
        else:
            summary += "- No recognizable protocols found.\n"

        summary += f"""
Top 15 Source -> Destination IP Pairs:
{'-' * 35}
"""
        if sorted_ip_pairs:
            for (src, dst), count in sorted_ip_pairs:
                summary += f"- {src} -> {dst}: {count} packets\n"
        else:
             summary += "- No IP traffic observed.\n"

        summary += f"""
Top 15 Source/Destination Ports (TCP/UDP):
{'-' * 45}
"""
        if sorted_ports:
            for (port, direction), count in sorted_ports:
                 summary += f"- Port {port} ({direction}): {count} packets\n"
        else:
            summary += "- No TCP/UDP ports observed.\n"


        return summary


    except FileNotFoundError:
        return f"Error: File not found at {pcap_file_path}"
    except Exception as e:
        return f"Error reading PCAP file: {e}"
    # Removed Import Error here as it's handled at the top level now


# ... (rest of your agents, tasks, crew setup, and main execution logic remains the same)

# --- Define Agents ---
# Configure the LLM for all agents using the Deepseek API
deepseek_llm = ChatOpenAI(
    model="deepseek/deepseek-chat",  # Specify the Deepseek model name here
    api_key=os.environ.get("DEEPSEEK_API_KEY"), # API key from .env
    base_url="https://api.deepseek.com/v1", # Deepseek API endpoint
    # temperature=0.7 # Optional: adjust creativity
)
# ... agents definitions ...

pcap_reader_agent = Agent(
    role='PCAP File Reader',
    goal=f'Use the available tool to read the specified PCAP file and generate a high-level summary for subsequent analysis.',
    backstory="You are an expert in using network tools like Scapy to extract foundational information from packet capture files. Your primary function is to provide a clean, structured summary for other analysts to work with.",
    verbose=True,
    allow_delegation=False,
    llm=deepseek_llm
)

network_analyst_agent = Agent(
    role='Network Traffic Analyst',
    goal='Analyze the provided PCAP summary to identify key network patterns, protocols used, traffic volume, and significant communication endpoints (IPs and Ports).',
    backstory="You are a highly experienced network engineer with deep knowledge of network protocols, traffic flows, and common network services. You excel at identifying the main components and patterns of network communication from summary data.",
    verbose=True,
    allow_delegation=True,
    llm=deepseek_llm
)

security_analyst_agent = Agent(
    role='Security Traffic Analyst',
    goal='Examine the PCAP summary generated by the reader for any signs of malicious activity, anomalies, or security concerns like unusual ports, suspicious protocols, or unexpected traffic patterns.',
    backstory="You are a skilled cybersecurity expert specialized in detecting threats, vulnerabilities, and suspicious behaviors within network traffic. You have a keen eye for the unusual and potentially malicious patterns.",
    verbose=True,
    allow_delegation=True,
    llm=deepseek_llm
)

summary_generator_agent = Agent(
    role='PCAP Analysis Report Generator',
    goal='Compile the findings from the Network Analyst and Security Analyst into a single, clear, and comprehensive executive summary report about the PCAP file contents.',
    backstory="You are a professional technical writer and report compiler. Your strength is synthesizing complex information from multiple sources into a well-structured, easy-to-understand report suitable for both technical and non-technical stakeholders.",
    verbose=True,
    allow_delegation=False,
    llm=deepseek_llm
)


# --- Define Tasks ---
# ... tasks definitions ...

read_pcap_task = Task(
    description=(
        "Use the 'PCAP Reader Summary Tool' to read the PCAP file located at '{pcap_file_path}' "
        "and generate a high-level summary. Ensure the summary includes total packet count, "
        "protocol distribution, and top source/destination IP pairs and ports."
        "The tool will return the summary text."
    ),
    expected_output="A detailed text summary of the PCAP file generated by the PCAP Reader Summary Tool.",
    agent=pcap_reader_agent,
    tools=[read_pcap_summary]
)

analyze_network_task = Task(
    description=(
        "Analyze the provided PCAP summary data from the previous 'read_pcap_task'.\n"
        "Identify the main protocols observed, the total volume of traffic, "
        "and highlight the most active source and destination IP addresses and ports.\n"
        "Explain the typical purpose of the most common protocols seen.\n"
        "Provide a structured analysis report focusing solely on network behavior and statistics."
    ),
    expected_output="A structured markdown report detailing network traffic patterns, most frequent protocols and their purpose, traffic volume, and key endpoints (IPs and Ports).",
    context=[read_pcap_task],
    agent=network_analyst_agent
)

analyze_security_task = Task(
    description=(
        "Analyze the provided PCAP summary data from the initial 'read_pcap_task'.\n"
        "Look for any indicators of suspicious activity based on the summary (e.g., unusual protocols, "
        "high traffic to/from unexpected IP addresses or ports, strange port combinations).\n"
        "Interpret what potential security issues or anomalies these observations *might* suggest (e.g., scanning, unusual service, data transfer).\n"
        "Provide a structured report highlighting potential security concerns or anomalies observed."
    ),
     expected_output="A structured markdown report outlining potential security issues, anomalies, or suspicious patterns observed based on the PCAP summary, with interpretations.",
    context=[read_pcap_task],
    agent=security_analyst_agent
)

generate_report_task = Task(
    description=(
        "Combine the network analysis report from the Network Traffic Analyst "
        "and the security analysis report from the Security Traffic Analyst "
        "into one comprehensive executive summary report.\n"
        "The report should start with an executive summary summarizing the most important findings (both network and security).\n"
        "Follow with clear sections for 'Network Analysis Findings' and 'Security Analysis Findings', incorporating the details from the previous tasks.\n"
        "Ensure the language is professional, clear, and concise, suitable for technical management or security teams.\n"
        "Conclude with a brief 'Key Takeaways' section."
    ),
    expected_output="A single, well-structured markdown report combining network and security analysis into an executive summary, detailed findings sections, and key takeaways.",
    context=[analyze_network_task, analyze_security_task],
    agent=summary_generator_agent
)


# --- Setup Crew ---
# ... crew setup ...

crew = Crew(
    agents=[pcap_reader_agent, network_analyst_agent, security_analyst_agent, summary_generator_agent],
    tasks=[read_pcap_task, analyze_network_task, analyze_security_task, generate_report_task],
    process='sequential',
    verbose=True,
)


# --- Main Execution ---
# ... main execution logic ...

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python your_script_name.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"Error: File not found at {pcap_file}")
        sys.exit(1)

    print(f"## Starting PCAP Analysis for {pcap_file} ##")
    print('------------------------------------------------')

    try:
        result = crew.kickoff(inputs={'pcap_file_path': pcap_file})

        print('\n## Analysis Complete ##')
        print('-----------------------')
        print(result)

    except Exception as e:
        print(f"\nAn error occurred during Crew execution: {e}")
        if "DEEPSEEK_API_KEY" in str(e) or "authentication" in str(e).lower():
             print("Error: Deepseek API key not found or invalid. Please check your .env file and API key.")
        elif "connection" in str(e).lower() or "network" in str(e).lower() or "requests.exceptions" in str(e):
             print("Error: Could not connect to the Deepseek API. Check your internet connection or API endpoint.")
        else:
            print("Please check your setup and inputs.")