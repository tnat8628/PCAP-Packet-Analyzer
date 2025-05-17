from crewai import Task
# Import agents
from agents import pcap_reader_agent, network_analyst_agent, security_analyst_agent, summary_generator_agent
# Import tools
from tools import (
    pcap_overview,
    find_packets,
    get_packet_details,
    get_packet_payload,
    extract_timeline_events
)

# --- Define Tasks ---

read_pcap_task = Task(
    description=(
        "Use the 'PCAP Overview Tool' to read the PCAP file located at '{pcap_file_path}' "
        "and generate a high-level summary. Ensure the summary includes total packet count, "
        "protocol distribution, and top source/destination IP pairs and ports. "
        "The tool will return the summary as a JSON string. Your output must be *only* the raw JSON string."
    ),
    expected_output="A JSON formatted string containing the high-level PCAP summary.",
    agent=pcap_reader_agent,
    tools=[pcap_overview], # Specify the tool explicitly for the task
    output_file="pcap_overview.json" # Save the tool's output to a file for context
)

analyze_network_task = Task(
    description=(
        "Analyze the provided PCAP summary data (available in context, likely from 'pcap_overview.json').\n"
        "Identify the main protocols observed, the total volume of traffic, "
        "and highlight the most active source and destination IP addresses and ports based on the summary.\n"
        "Explain the typical purpose of the most common protocols seen (HTTP, HTTPS/TLS, DNS, etc.).\n"
        "Use the 'PCAP Find Packets Tool' to investigate traffic on specific ports mentioned in the overview, like port 80, 443, or 8443. Report findings related to these ports.\n"
        "Use the 'PCAP Extract Timeline Events Tool' (with a reasonable limit, e.g., 100) to analyze the sequence of network events. Describe any interesting network sequences or patterns observed in the initial timeline.\n"
        "Provide a structured markdown report focusing on network behavior, statistics, findings from specific port investigations, and insights from the event timeline."
    ),
    expected_output="A structured markdown report detailing network traffic patterns, protocol purposes, traffic volume, key endpoints, findings from port-specific investigations (e.g., 8443), and initial observations from the network event timeline.",
    context=[read_pcap_task], # Depends on the output of read_pcap_task
    agent=network_analyst_agent,
    tools=[pcap_overview, find_packets,get_packet_details, get_packet_payload, extract_timeline_events] # This task can use any of the common tools
)

analyze_security_task = Task(
    description=(
        "Analyze the provided PCAP summary data and network analysis findings.\n"
        "Look for indicators of suspicious activity based on the overview, network analysis, and your security knowledge (e.g., unusual protocols, high traffic to/from unexpected IPs/ports, strange port combinations, specific TCP flags, presence of raw data payload).\n"
        "Use the 'PCAP Find Packets Tool' to search for security-relevant patterns (e.g., 'dst_port=445', 'has_layer=Raw', 'tcp_flags=R', 'payload_contains=string').\n"
        "For any packets with significant raw payload or identified as suspicious, use the 'PCAP Get Packet Payload Tool' to extract and examine the payload. Analyze the payload data (provided as Base64) for recognizable patterns, strings, or potential encoded data. Report findings from payload analysis.\n"
        "Analyze the timeline of events using the 'PCAP Extract Timeline Events Tool' to look for suspicious sequences (e.g., SYN scan attempts followed by specific port connections, bursts of traffic, ICMP exfiltration patterns).\n"
        "Investigate traffic on port 8443 specifically. Use 'PCAP Find Packets Tool' for 'dst_port=8443' or 'src_port=8443'. Check the details of these packets using 'PCAP Get Packet Details Tool'. Determine if it's likely HTTPS (TLS layer present) or actual HTTP (HTTP layer present) and report on any suspicious activity observed on this port.\n"
        "Interpret what potential security issues these observations might suggest (e.g., scanning, unusual service, data transfer, potential exploit attempts, C2 traffic).\n"
        "Provide a structured markdown report highlighting potential security concerns, anomalies, and evidence found via your tool usage, including references to specific packet indices or criteria."
    ),
     expected_output="A structured markdown report outlining potential security issues, anomalies, or suspicious patterns observed based on the PCAP data, with interpretations, details from specific packet investigations (including payload and app layer analysis), and insights from the event timeline.",
    context=[read_pcap_task, analyze_network_task], # Depends on overview and network analysis
    agent=security_analyst_agent,
    tools=[pcap_overview, find_packets,get_packet_details, get_packet_payload, extract_timeline_events] # This task can use any of the common tools
)

# generate_report_task Description updated for HTML output
generate_report_task = Task(
    description=(
        "Combine the network analysis report from the Network Traffic Analyst "
        "and the security analysis report from the Security Traffic Analyst "
        "into one comprehensive executive summary report.\n"
        "**Format the entire report as a single HTML document.**\n"
        "Include all necessary HTML tags (`<!DOCTYPE html>`, `<html>`, `<head>`, `<title>`, `<body>`).\n"
        "Use `<h1>` for the main report title.\n"
        "Use `<h2>` for major sections like 'Executive Summary', 'Network Analysis Findings', 'Security Analysis Findings', and 'Key Takeaways'.\n"
        "Use `<p>` for paragraphs.\n"
        "Convert bullet points or lists from the source reports into `<ul>` or `<ol>` lists with `<li>` items.\n"
        "Use `<pre><code>` tags to format any code blocks, raw data snippets, or detailed outputs from tool calls mentioned in the analysis reports.\n"
        "Ensure proper HTML escaping for any special characters within the text content.\n"
        "The report should synthesize key statistics from the overview and highlight specific findings and evidence from the detailed investigations performed by the analysts.\n"
        "Make sure the HTML is well-formed and readable in a web browser."
    ),
    expected_output="A single, well-structured HTML document combining network and security analysis findings into a comprehensive report.",
    context=[analyze_network_task, analyze_security_task], # Depends on network and security analysis reports
    agent=summary_generator_agent
    # This agent doesn't need tools
)