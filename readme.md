Unused Address Object Finder (PAN-OS Local Version)


Description / Use Case

This script is designed to identify unused address objects and address groups on a Palo Alto Networks firewall. It does not make any configuration change such like deleting obsolete address objects.


The script performs the following:

Generates a dynamic API key using provided credentials.

Retrieves all defined address objects and groups from the firewall.

Identifies which objects are referenced in rules.

Recursively "flattens" groups to ensure objects nested within groups are correctly identified as "in use". Note an object in an 'unused' group is considered as used, since it is referenced by an group.

Exports a timestamped text report listing all unused groups and address objects.


Prerequisites

The following Python modules are required to run the script:

requests: For sending HTTPS API calls to the firewall.

xmltodict: For converting XML API responses into navigable Python dictionaries.

urllib3: Used to manage SSL certificate warning suppression.


Limitations

Scope of Analysis: The script currently only inspects the Security and NAT rulebases. Objects used exclusively in other areas (e.g., Decryption, PBF, or Tunnel interfaces) may be incorrectly reported as unused.

VSYS Support: The script is hardcoded to support a single vsys named vsys1.

Static vs. Dynamic: While the script handles static groups and parses tags for dynamic groups, it does not currently account for objects used in dynamic address groups based on criteria other than tags.


Usage

Ensure the requests and xmltodict modules are installed via pip.

Run the script: python unused_address.py.

Enter the Management IP, Username, and Password when prompted.

The final report will be saved in the \report directory relative to the script location.