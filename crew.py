from crewai import Crew

# Import các Agent đã định nghĩa
from agents import (
    pcap_reader_agent,
    network_analyst_agent,
    security_analyst_agent,
    summary_generator_agent
)

# Import các Task đã định nghĩa
from tasks import (
    read_pcap_task,
    analyze_network_task,
    analyze_security_task,
    generate_report_task
)

# --- Cài đặt Crew ---
# Tạo một Crew bao gồm các Agent và Tasks đã định nghĩa
crew = Crew(
    agents=[
        pcap_reader_agent,
        network_analyst_agent,
        security_analyst_agent,
        summary_generator_agent
    ], # Danh sách các Agent tham gia
    tasks=[
        read_pcap_task,
        analyze_network_task,
        analyze_security_task,
        generate_report_task
    ],       # Danh sách các Tasks
    process='sequential', # Quy trình thực hiện Tasks: theo thứ tự trong danh sách tasks
    verbose=True,         # Hiển thị chi tiết quá trình làm việc của Crew
)