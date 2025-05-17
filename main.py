# main.py

import os
import sys
from dotenv import load_dotenv
# Import the crew from crew.py
from crew import crew

# Load environment variables from .env file
load_dotenv()

# --- Main Execution ---

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <path_to_pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    if not os.path.exists(pcap_file):
        print(f"Error: File not found at {pcap_file}")
        sys.exit(1)

    print(f"## Starting PCAP Analysis for {pcap_file} ##")
    print('------------------------------------------------')

    # Use absolute path for filename to avoid issues if script is run from different directory
    report_filename_base = os.path.splitext(os.path.basename(pcap_file))[0] + "_analysis_report"
    report_filename = report_filename_base + ".html"
    # Save in the same directory as the pcap file if possible, otherwise current directory
    pcap_dir = os.path.dirname(os.path.abspath(pcap_file))
    # Create the directory if it doesn't exist (especially relevant if pcap_dir is non-empty)
    if pcap_dir and not os.path.exists(pcap_dir):
        try:
            os.makedirs(pcap_dir)
        except OSError as e:
            print(f"Warning: Could not create directory {pcap_dir}. Saving report to current directory.")
            pcap_dir = "." # Fallback to current directory
    report_filepath = os.path.join(pcap_dir, report_filename)


    try:
        # Kickoff the crew with the pcap file path as input
        result = crew.kickoff(inputs={'pcap_file_path': pcap_file})

        print('\n## Analysis Complete ##')
        print('-----------------------')

        # The result is a CrewOutput object. Convert it to string to get the final output.
        final_report_content = str(result)

        print(f"Analysis report generated. Saving to {report_filepath}...")

        try:
            # Write the string content to the HTML file
            with open(report_filepath, "w", encoding="utf-8") as f:
                f.write(final_report_content)
            print(f"Report saved successfully to {report_filepath}")
            print(f"\nOpen the file '{report_filepath}' in a web browser to view the report.")
        except Exception as e:
            print(f"Error saving report to file: {e}")
            print("\n--- Report Content (Raw HTML) ---")
            # If saving failed, print the content that was supposed to be saved
            print(final_report_content)
            print("-------------------------------")


    except Exception as e:
        print(f"\nAn error occurred during Crew execution: {e}")
        if "DEEPSEEK_API_KEY" in str(e) or "authentication" in str(e).lower():
             print("Error: Deepseek API key not found or invalid. Please check your .env file and API key.")
        elif "connection" in str(e).lower() or "network" in str(e).lower() or "requests.exceptions" in str(e):
             print("Error: Could not connect to the Deepseek API. Check your internet connection, API endpoint, or firewall.")
        elif "context window" in str(e).lower() or "token limit" in str(e).lower():
            print("Error: The conversation exceeded the LLM's context window.")
            print("Try using a smaller PCAP file or adjusting agent/task complexity.")
        elif "expected string or bytes-like object" in str(e).lower() or "write() argument must be str" in str(e).lower():
             print("Error: The final report content produced by the LLM was not a string.")
             print("Review the generate_report_task description and LLM output.")
        else:
            print("An unexpected error occurred. Please check the traceback for details.")
            import traceback
            traceback.print_exc()
            print(f"\nDetailed error message: {e}")
        sys.exit(1) # Exit with an error code