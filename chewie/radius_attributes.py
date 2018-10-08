"""Radius Attributes"""


from chewie.radius_datatypes import Concat, Enum, Integer, String, Text, Vsa, Ipv6prefix, \
    Ipv4prefix, Ipv4addr, Ipv6addr, Ifid, Time


ATTRIBUTES = {
    'User-Name': Text('User-Name', 1),
    'User-Password': String('User-Password', 2),
    'CHAP-Password': String('CHAP-Password', 3),
    'NAS-IP-Address': Ipv4addr('NAS-IP-Address', 4),
    'NAS-Port': Integer('NAS-Port', 5),
    'Service-Type': Enum('Service-Type', 6),
    'Framed-Protocol': Enum('Framed-Protocol', 7),
    'Framed-IP-Address': Ipv4addr('Framed-IP-Address', 8),
    'Framed-IP-Netmask': Ipv4addr('Framed-IP-Netmask', 9),
    'Framed-Routing': Enum('Framed-Routing', 10),
    'Filter-Id': Text('Filter-Id', 11),
    'Framed-MTU': Integer('Framed-MTU', 12),
    'Framed-Compression': Enum('Framed-Compression', 13),
    'Login-IP-Host': Ipv4addr('Login-IP-Host', 14),
    'Login-Service': Enum('Login-Service', 15),
    'Login-TCP-Port': Integer('Login-TCP-Port', 16),
    'Reply-Message': Text('Reply-Message', 18),
    'Callback-Number': Text('Callback-Number', 19),
    'Callback-Id': Text('Callback-Id', 20),
    'Framed-Route': Text('Framed-Route', 22),
    'Framed-IPX-Network': Ipv4addr('Framed-IPX-Network', 23),
    'State': String('State', 24),
    'Class': String('Class', 25),
    'Vendor-Specific': Vsa('Vendor-Specific', 26),
    'Session-Timeout': Integer('Session-Timeout', 27),
    'Idle-Timeout': Integer('Idle-Timeout', 28),
    'Termination-Action': Enum('Termination-Action', 29),
    'Called-Station-Id': Text('Called-Station-Id', 30),
    'Calling-Station-Id': Text('Calling-Station-Id', 31),
    'NAS-Identifier': Text('NAS-Identifier', 32),
    'Proxy-State': String('Proxy-State', 33),
    'Login-LAT-Service': Text('Login-LAT-Service', 34),
    'Login-LAT-Node': Text('Login-LAT-Node', 35),
    'Login-LAT-Group': String('Login-LAT-Group', 36),
    'Framed-AppleTalk-Link': Integer('Framed-AppleTalk-Link', 37),
    'Framed-AppleTalk-Network': Integer('Framed-AppleTalk-Network', 38),
    'Framed-AppleTalk-Zone': Text('Framed-AppleTalk-Zone', 39),
    'Acct-Status-Type': Enum('Acct-Status-Type', 40),
    'Acct-Delay-Time': Integer('Acct-Delay-Time', 41),
    'Acct-Input-Octets': Integer('Acct-Input-Octets', 42),
    'Acct-Output-Octets': Integer('Acct-Output-Octets', 43),
    'Acct-Session-Id': Text('Acct-Session-Id', 44),
    'Acct-Authentic': Enum('Acct-Authentic', 45),
    'Acct-Session-Time': Integer('Acct-Session-Time', 46),
    'Acct-Input-Packets': Integer('Acct-Input-Packets', 47),
    'Acct-Output-Packets': Integer('Acct-Output-Packets', 48),
    'Acct-Terminate-Cause': Enum('Acct-Terminate-Cause', 49),
    'Acct-Multi-Session-Id': Text('Acct-Multi-Session-Id', 50),
    'Acct-Link-Count': Integer('Acct-Link-Count', 51),
    'Acct-Input-Gigawords': Integer('Acct-Input-Gigawords', 52),
    'Acct-Output-Gigawords': Integer('Acct-Output-Gigawords', 53),
    'Event-Timestamp': Time('Event-Timestamp', 55),
    'Egress-VLANID': Integer('Egress-VLANID', 56),
    'Ingress-Filters': Enum('Ingress-Filters', 57),
    'Egress-VLAN-Name': Text('Egress-VLAN-Name', 58),
    'User-Priority-Table': String('User-Priority-Table', 59),
    'CHAP-Challenge': String('CHAP-Challenge', 60),
    'NAS-Port-Type': Enum('NAS-Port-Type', 61),
    'Port-Limit': Integer('Port-Limit', 62),
    'Login-LAT-Port': Text('Login-LAT-Port', 63),
    'Tunnel-Type': Enum('Tunnel-Type', 64),
    'Tunnel-Medium-Type': Enum('Tunnel-Medium-Type', 65),
    'Tunnel-Client-Endpoint': Text('Tunnel-Client-Endpoint', 66),
    'Tunnel-Server-Endpoint': Text('Tunnel-Server-Endpoint', 67),
    'Acct-Tunnel-Connection': Text('Acct-Tunnel-Connection', 68),
    'Tunnel-Password': String('Tunnel-Password', 69),
    'ARAP-Password': String('ARAP-Password', 70),
    'ARAP-Features': String('ARAP-Features', 71),
    'ARAP-Zone-Access': Enum('ARAP-Zone-Access', 72),
    'ARAP-Security': Integer('ARAP-Security', 73),
    'ARAP-Security-Data': Text('ARAP-Security-Data', 74),
    'Password-Retry': Integer('Password-Retry', 75),
    'Prompt': Enum('Prompt', 76),
    'Connect-Info': Text('Connect-Info', 77),
    'Configuration-Token': Text('Configuration-Token', 78),
    'EAP-Message': Concat('EAP-Message', 79),
    'Message-Authenticator': String('Message-Authenticator', 80),
    'Tunnel-Private-Group-ID': Text('Tunnel-Private-Group-ID', 81),
    'Tunnel-Assignment-ID': Text('Tunnel-Assignment-ID', 82),
    'Tunnel-Preference': Integer('Tunnel-Preference', 83),
    'ARAP-Challenge-Response': String('ARAP-Challenge-Response', 84),
    'Acct-Interim-Interval': Integer('Acct-Interim-Interval', 85),
    'Acct-Tunnel-Packets-Lost': Integer('Acct-Tunnel-Packets-Lost', 86),
    'NAS-Port-Id': Text('NAS-Port-Id', 87),
    'Framed-Pool': Text('Framed-Pool', 88),
    'CUI': String('CUI', 89),
    'Tunnel-Client-Auth-ID': Text('Tunnel-Client-Auth-ID', 90),
    'Tunnel-Server-Auth-ID': Text('Tunnel-Server-Auth-ID', 91),
    'NAS-Filter-Rule': Text('NAS-Filter-Rule', 92),
    'Originating-Line-Info': String('Originating-Line-Info', 94),
    'NAS-IPv6-Address': Ipv6addr('NAS-IPv6-Address', 95),
    'Framed-Interface-Id': Ifid('Framed-Interface-Id', 96),
    'Framed-IPv6-Prefix': Ipv6prefix('Framed-IPv6-Prefix', 97),
    'Login-IPv6-Host': Ipv6addr('Login-IPv6-Host', 98),
    'Framed-IPv6-Route': Text('Framed-IPv6-Route', 99),
    'Framed-IPv6-Pool': Text('Framed-IPv6-Pool', 100),
    'Error-CauseAttribute': Enum('Error-CauseAttribute', 101),
    'EAP-Key-Name': String('EAP-Key-Name', 102),
    'Digest-Response': Text('Digest-Response', 103),
    'Digest-Realm': Text('Digest-Realm', 104),
    'Digest-Nonce': Text('Digest-Nonce', 105),
    'Digest-Response-Auth': Text('Digest-Response-Auth', 106),
    'Digest-Nextnonce': Text('Digest-Nextnonce', 107),
    'Digest-Method': Text('Digest-Method', 108),
    'Digest-URI': Text('Digest-URI', 109),
    'Digest-Qop': Text('Digest-Qop', 110),
    'Digest-Algorithm': Text('Digest-Algorithm', 111),
    'Digest-Entity-Body-Hash': Text('Digest-Entity-Body-Hash', 112),
    'Digest-CNonce': Text('Digest-CNonce', 113),
    'Digest-Nonce-Count': Text('Digest-Nonce-Count', 114),
    'Digest-Username': Text('Digest-Username', 115),
    'Digest-Opaque': Text('Digest-Opaque', 116),
    'Digest-Auth-Param': Text('Digest-Auth-Param', 117),
    'Digest-AKA-Auts': Text('Digest-AKA-Auts', 118),
    'Digest-Domain': Text('Digest-Domain', 119),
    'Digest-Stale': Text('Digest-Stale', 120),
    'Digest-HA1': Text('Digest-HA1', 121),
    'SIP-AOR': Text('SIP-AOR', 122),
    'Delegated-IPv6-Prefix': Ipv6prefix('Delegated-IPv6-Prefix', 123),
    'MIP6-Feature-Vector': String('MIP6-Feature-Vector', 124),
    'MIP6-Home-Link-Prefix': Ipv6prefix('MIP6-Home-Link-Prefix', 125),
    'Operator-Name': Text('Operator-Name', 126),
    'Location-Information': String('Location-Information', 127),
    'Location-Data': String('Location-Data', 128),
    'Basic-Location-Policy-Rules': String('Basic-Location-Policy-Rules', 129),
    'Extended-Location-Policy-Rules': String('Extended-Location-Policy-Rules', 130),
    'Location-Capable': Enum('Location-Capable', 131),
    'Requested-Location-Info': Enum('Requested-Location-Info', 132),
    'Framed-Management-Protocol': Enum('Framed-Management-Protocol', 133),
    'Management-Transport-Protection': Enum('Management-Transport-Protection', 134),
    'Management-Policy-Id': Text('Management-Policy-Id', 135),
    'Management-Privilege-Level': Integer('Management-Privilege-Level', 136),
    'PKM-SS-Cert': Concat('PKM-SS-Cert', 137),
    'PKM-CA-Cert': Concat('PKM-CA-Cert', 138),
    'PKM-Config-Settings': String('PKM-Config-Settings', 139),
    'PKM-Cryptosuite-List': String('PKM-Cryptosuite-List', 140),
    'PKM-SAID': Text('PKM-SAID', 141),
    'PKM-SA-Descriptor': String('PKM-SA-Descriptor', 142),
    'PKM-Auth-Key': String('PKM-Auth-Key', 143),
    'DS-Lite-Tunnel-Name': Text('DS-Lite-Tunnel-Name', 144),
    'Mobile-Node-Identifier': String('Mobile-Node-Identifier', 145),
    'Service-Selection': Text('Service-Selection', 146),
    'PMIP6-Home-LMA-IPv6-Address': Ipv6addr('PMIP6-Home-LMA-IPv6-Address', 147),
    'PMIP6-Visited-LMA-IPv6-Address': Ipv6addr('PMIP6-Visited-LMA-IPv6-Address', 148),
    'PMIP6-Home-LMA-IPv4-Address': Ipv4addr('PMIP6-Home-LMA-IPv4-Address', 149),
    'PMIP6-Visited-LMA-IPv4-Address': Ipv4addr('PMIP6-Visited-LMA-IPv4-Address', 150),
    'PMIP6-Home-HN-Prefix': Ipv6prefix('PMIP6-Home-HN-Prefix', 151),
    'PMIP6-Visited-HN-Prefix': Ipv6prefix('PMIP6-Visited-HN-Prefix', 152),
    'PMIP6-Home-Interface-ID': Ifid('PMIP6-Home-Interface-ID', 153),
    'PMIP6-Visited-Interface-ID': Ifid('PMIP6-Visited-Interface-ID', 154),
    'PMIP6-Home-IPv4-HoA': Ipv4prefix('PMIP6-Home-IPv4-HoA', 155),
    'PMIP6-Visited-IPv4-HoA': Ipv4prefix('PMIP6-Visited-IPv4-HoA', 156),
    'PMIP6-Home-DHCP4-Server-Address': Ipv4addr('PMIP6-Home-DHCP4-Server-Address', 157),
    'PMIP6-Visited-DHCP4-Server-Address': Ipv4addr('PMIP6-Visited-DHCP4-Server-Address', 158),
    'PMIP6-Home-DHCP6-Server-Address': Ipv6addr('PMIP6-Home-DHCP6-Server-Address', 159),
    'PMIP6-Visited-DHCP6-Server-Address': Ipv6addr('PMIP6-Visited-DHCP6-Server-Address', 160),
    'PMIP6-Home-IPv4-Gateway': Ipv4addr('PMIP6-Home-IPv4-Gateway', 161),
    'PMIP6-Visited-IPv4-Gateway': Ipv4addr('PMIP6-Visited-IPv4-Gateway', 162),
    'EAP-Lower-Layer': Enum('EAP-Lower-Layer', 163),
    'GSS-Acceptor-Service-Name': Text('GSS-Acceptor-Service-Name', 164),
    'GSS-Acceptor-Host-Name': Text('GSS-Acceptor-Host-Name', 165),
    'GSS-Acceptor-Service-Specifics': Text('GSS-Acceptor-Service-Specifics', 166),
    'GSS-Acceptor-Realm-Name': Text('GSS-Acceptor-Realm-Name', 167),
    'Framed-IPv6-Address': Ipv6addr('Framed-IPv6-Address', 168),
    'DNS-Server-IPv6-Address': Ipv6addr('DNS-Server-IPv6-Address', 169),
    'Route-IPv6-Information': Ipv6prefix('Route-IPv6-Information', 170),
    'Delegated-IPv6-Prefix-Pool': Text('Delegated-IPv6-Prefix-Pool', 171),
    'Stateful-IPv6-Address-Pool': Text('Stateful-IPv6-Address-Pool', 172),
    # 'IPv6-6rd-Configuration': Tlv('IPv6-6rd-Configuration', 173),
    'Allowed-Called-Station-Id': Text('Allowed-Called-Station-Id', 174),
    'EAP-Peer-Id': String('EAP-Peer-Id', 175),
    'EAP-Server-Id': String('EAP-Server-Id', 176),
    'Mobility-Domain-Id': Integer('Mobility-Domain-Id', 177),
    'Preauth-Timeout': Integer('Preauth-Timeout', 178),
    'Network-Id-Name': String('Network-Id-Name', 179),
    'EAPoL-Announcement': Concat('EAPoL-Announcement', 180),
    'WLAN-HESSID': Text('WLAN-HESSID', 181),
    'WLAN-Venue-Info': Integer('WLAN-Venue-Info', 182),
    'WLAN-Venue-Language': String('WLAN-Venue-Language', 183),
    'WLAN-Venue-Name': Text('WLAN-Venue-Name', 184),
    'WLAN-Reason-Code': Integer('WLAN-Reason-Code', 185),
    'WLAN-Pairwise-Cipher': Integer('WLAN-Pairwise-Cipher', 186),
    'WLAN-Group-Cipher': Integer('WLAN-Group-Cipher', 187),
    'WLAN-AKM-Suite': Integer('WLAN-AKM-Suite', 188),
    'WLAN-Group-Mgmt-Cipher': Integer('WLAN-Group-Mgmt-Cipher', 189),
    'WLAN-RF-Band': Integer('WLAN-RF-Band', 190),
}


def get_type(description):
    """Get the radius attribute type from description.
    Args:
        description (str): e.g. EAP-Message (case sensitive)
    Returns:
         int, 0 if cannot find the descrption"""
    return get_attribute(description).TYPE


def get_attribute(description):
    """Get the radius attribute type and datatype from description.
    Args:
        description (str): e.g. EAP-Message (case sensitive)
        Returns:
             int, DataType"""

    return ATTRIBUTES[description]


def get_attribute_by_type(_type):
    """
    Find the attribute that has the matching type
    Args:
        _type (int):
    Returns:
        Datatype with matching _type
    Raises:
        KeyError if cannot find the type.
    """
    for attribute in ATTRIBUTES.values():
        if _type == attribute.TYPE:
            return attribute
    raise KeyError('type: %s could not be found in ATTRIBUTES' % _type)


def create_attribute(description, raw_data=None, bytes_data=None):
    """
    Create an radius attribute with the value.
    Args:
        description (str): e.g. EAP-Message (case sensitive)description:
        raw_data: raw value e.g. a TTLSMessage for description EAP-Message,
        bytes_data (bytes like object):
    Returns:
        created datatype object.
    """
    datatype = get_attribute(description)
    return datatype.create(raw_data=raw_data, bytes_data=bytes_data)
