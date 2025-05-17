import os
from crewai import Agent
from langchain_openai import ChatOpenAI
# Import the tools defined in tools.py
from tools import (
    pcap_overview,
    find_packets,
    get_packet_details,
    get_packet_payload,
    extract_timeline_events
)

# --- LLM Setup ---
# Note: load_dotenv should be called in main.py before agents are defined
deepseek_llm = ChatOpenAI(
    model="deepseek/deepseek-chat",
    api_key=os.environ.get("DEEPSEEK_API_KEY"),
    base_url="https://api.deepseek.com/v1",
    # temperature=0.7 # Keep default or set as needed
)

# --- Define Agents ---

pcap_reader_agent = Agent(
    role='PCAP Initial Reader and Overview Generator',
    goal='Use the PCAP Overview Tool to read the specified PCAP file and generate a high-level, structured JSON summary. This summary is the starting point for all other analysis.',
    backstory="You are an expert in using network tools like Scapy to quickly scan packet capture files and produce initial statistical summaries. Your output is always a clean, structured JSON object representing the high-level view of the traffic.",
    verbose=True,
    allow_delegation=False,
    llm=deepseek_llm,
    tools=[pcap_overview] # Only needs the overview tool initially
)

network_analyst_agent = Agent(
    role='Network Traffic Analyst and Investigator',
    goal='Analyze the provided PCAP overview and perform deeper investigation using available tools. Identify network patterns, protocols, traffic volume, and endpoints. Use tools like find_packets and get_packet_details to investigate specific connections, ports (including 8443), or traffic types. Analyze the timeline of events for network sequences.',
    backstory="You are a highly experienced network engineer. You analyze overall traffic trends and use network analysis tools to drill down into interesting connections or traffic types based on initial findings. You excel at understanding typical network behavior and identifying main communication flows. You can interpret detailed packet information and network event timelines.",
    verbose=True,
    allow_delegation=True, # Allow delegation to other agents if needed (though sequential process might limit this)
    llm=deepseek_llm,
    tools=[pcap_overview, find_packets,get_packet_details, get_packet_payload, extract_timeline_events]
)

security_analyst_agent = Agent(
    role='Security Traffic Analyst and Threat Hunter',
    goal='Examine the provided PCAP overview, network analysis findings, and use available tools to hunt for security threats, anomalies, and suspicious activity. Focus on unusual ports (like 8443), strange protocol behavior, packets with raw payload, and suspicious event sequences in the timeline. Use tools like find_packets, get_packet_details, get_packet_payload, and extract_timeline_events to gather evidence.',
    backstory="You are a skilled cybersecurity expert specialized in detecting threats, vulnerabilities, and suspicious behaviors within network traffic. You have a keen eye for the unusual and potentially malicious patterns. You use specialized tools to examine packets, application layer details, payloads, and traffic timelines for indicators of compromise or attack patterns.",
    verbose=True,
    allow_delegation=True, # Allow delegation
    llm=deepseek_llm,
    tools=[pcap_overview, find_packets,get_packet_details, get_packet_payload, extract_timeline_events]
)

# summary_generator_agent Goal and Backstory updated for HTML output
summary_generator_agent = Agent(
    role='PCAP Analysis Report Compiler (HTML)',
    goal="Compile the findings from the Network Traffic Analyst and Security Traffic Analyst into one comprehensive executive summary report formatted in HTML. Ensure the report is a well-structured, single HTML document containing all analysis findings, details from investigations, and key takeaways.",
    backstory="You are a professional technical writer and report compiler skilled in creating clear, well-formatted technical reports in HTML. You synthesize complex information and detailed investigation results from multiple sources into a cohesive HTML document suitable for technical and security teams.",
    verbose=True,
    allow_delegation=False,
    llm=deepseek_llm
)