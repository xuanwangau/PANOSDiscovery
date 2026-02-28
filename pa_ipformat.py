# pa_ipformat.py

from netaddr import IPNetwork, IPRange, IPSet, IPAddress

def convert_to_ipset(address_entry):
    """
    Converts a PAN-OS address entry (IP, Subnet, or Range) 
    into a netaddr IPSet object for matching.
    """
    if '-' in address_entry: # It's a range
        start, end = address_entry.split('-')
        return IPSet(IPRange(start.strip(), end.strip()))
    else: # It's a host or CIDR
        return IPSet(IPNetwork(address_entry))


def ip_matches_wildcard(test_ip_str, address_str):

    base_str, mask_str = address_str.split(r'/')
    base = IPAddress(base_str)
    mask = IPAddress(mask_str)
    test_ip = IPAddress(test_ip_str)

    # Perform bitwise comparison
    # We use .value to get the integer representation of the IP
    # ~mask flips 1s (ignore) to 0s (check)
    return (test_ip.value & ~mask.value) == (base.value & ~mask.value)

