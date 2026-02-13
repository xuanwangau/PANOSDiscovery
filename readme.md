PAN-OS Configuration Cleanup Tool (pacleanup)

Use Case
- This tool identifies unused address objects and address groups within Palo Alto Networks environments. It is designed to assist administrators in maintaining a "lean" configuration by cross-referencing defined objects against their actual usage in security and NAT policies.

- The script dynamically adapts its analysis based on whether it is connected to a standalone Next-Generation Firewall (NGFW) or a Panorama management server.

- This script is designed for read-only analysis of Palo Alto Networks NGFW or Panorama configurations.

[SECURITY NOTE]
This script disables SSL verification and should be used within a trusted management network only.

Key Features
- Model Awareness: Support both standalone firewall and Panorama management server.

- Panorama Support: Inspects both Shared and Device-Group objects, and pre-rulebase and post-rulebase policies.

- Multi-VSYS Iteration: For standalone firewalls, analyze all available Virtual Systems (VSYS) and generates individual reports for each.

- Recursive Group Flattening: Includes a recursive engine to "drill down" through nested address groups, ensuring that base address objects are only marked as unused if they do not appear in any parent group currently in use.

- Dynamic Group Resolution: Uses operational API commands to fetch the real-time member list of Dynamic Address Groups.

Prerequisites
The tool requires the following Python modules:

- requests: For API communication.

- xmltodict: For converting XML responses into Python dictionaries.

- urllib3: For managing SSL certificate warnings.

- pathlib & datetime: For report file management and timestamping.

Limitations
- Policy Scope: The analysis is strictly limited to Security and NAT rulebases. Usage in other sections—such as Decryption, PBF, Tunnel interfaces, or Policy Objects (like User-ID)—is not currently inspected.

- Read-Only: This tool only identifies and reports unused objects; it does not perform any deletion or modification of the configuration.

- Network Access: Requires HTTPS access to the management interface of the target device and valid administrative credentials.

Usage
1. Ensure all script modules (pa_utils.py, parse_fw.py, and parse_pano.py) are in the same directory as pacleanup.py.

2. Run the orchestrator script: python pacleanup.py.

3. Enter the device IP and credentials when prompted.

4. Reports are automatically saved as .txt files in a local \report folder.