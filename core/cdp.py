import socket
import struct
from datetime import datetime

# ============================================================
# CONSTANTES E CONSTANTES DE CAPACIDADES CDP
# ============================================================

CDP_MULTICAST = "01:00:0c:cc:cc:cc"

CDP_CAPABILITIES = {
    0x0001: "Router",
    0x0002: "Trans-Bridge",
    0x0004: "Source-Route Bridge",
    0x0008: "Switch",
    0x0010: "Host",
    0x0020: "IGMP capable",
    0x0040: "Repeater",
    0x0080: "VoIP Phone",
    0x0100: "Remotely Managed Device",
}

LLDP_MULTICAST = "01:80:c2:00:00:0e"

# ============================================================
# PARSERS CDP
# ============================================================

def parse_cdp_address(data: bytes) -> str:
    try:
        number_of_addresses = struct.unpack("!I", data[:4])[0]
        offset = 4

        for _ in range(number_of_addresses):
            protocol_type = data[offset]
            offset += 1

            protocol_length = data[offset]
            offset += 1

            protocol = data[offset : offset + protocol_length]
            offset += protocol_length

            address_length = struct.unpack("!H", data[offset : offset + 2])[0]
            offset += 2

            address = data[offset : offset + address_length]
            offset += address_length

            # IPv4 protocol type
            if (
                protocol_length == 1
                and protocol == b"\xcc"
                and address_length == 4
            ):
                return socket.inet_ntoa(address)

    except Exception:
        pass

    return "unknown"


def decode_cdp_packet(raw: bytes) -> dict | None:
    try:
        if len(raw) < 26:
            return None

        # Ethernet header, including optional 802.1Q/QinQ tags.
        offset = 14
        ethertype = struct.unpack("!H", raw[12:14])[0]
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(raw) < offset + 4:
                return None
            ethertype = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            offset += 4

        # LLC
        if len(raw) < offset + 8 or raw[offset : offset + 2] != b"\xaa\xaa":
            return None

        offset += 3

        # SNAP
        pid = struct.unpack("!H", raw[offset + 3 : offset + 5])[0]
        if pid != 0x2000:
            return None

        offset += 5

        # CDP Header
        version = raw[offset]
        ttl = raw[offset + 1]
        offset += 4

        neighbor = {
            "protocol": "CDP",
            "cdp_version": version,
            "ttl": ttl,
            "timestamp": datetime.now().isoformat(),
        }

        while offset + 4 <= len(raw):
            tlv_type = struct.unpack("!H", raw[offset : offset + 2])[0]
            tlv_length = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]

            if tlv_length < 4 or offset + tlv_length > len(raw):
                break

            value = raw[offset + 4 : offset + tlv_length]
            offset += tlv_length

            def text(data):
                return data.decode("utf-8", errors="replace").strip("\x00")

            # Device ID
            if tlv_type == 0x0001:
                neighbor["hostname"] = text(value)

            # Address
            elif tlv_type == 0x0002:
                neighbor["ip"] = parse_cdp_address(value)

            # Port ID
            elif tlv_type == 0x0003:
                neighbor["remote_port"] = text(value)

            # Capabilities
            elif tlv_type == 0x0004:
                if len(value) >= 4:
                    capabilities_raw = struct.unpack("!I", value[:4])[0]
                    neighbor["capabilities_raw"] = capabilities_raw
                    neighbor["capabilities"] = [
                        name
                        for bit, name in CDP_CAPABILITIES.items()
                        if capabilities_raw & bit
                    ]

            # Software
            elif tlv_type == 0x0005:
                neighbor["software"] = text(value)

            # Platform
            elif tlv_type == 0x0006:
                neighbor["platform"] = text(value)

            # VTP Domain
            elif tlv_type == 0x0009:
                neighbor["vtp_domain"] = text(value)

            # Native VLAN
            elif tlv_type == 0x000A:
                if len(value) >= 2:
                    neighbor["native_vlan"] = struct.unpack("!H", value[:2])[0]

            # Duplex
            elif tlv_type == 0x000B and value:
                neighbor["duplex"] = "full" if value[0] == 1 else "half"

            # Power
            elif tlv_type == 0x0010:
                if len(value) >= 2:
                    neighbor["power_mw"] = struct.unpack("!H", value[:2])[0]

            # MTU
            elif tlv_type == 0x0011:
                if len(value) >= 4:
                    neighbor["mtu"] = struct.unpack("!I", value[:4])[0]

        if "hostname" not in neighbor:
            return None

        return neighbor

    except Exception:
        return None


# ============================================================
# PARSERS LLDP
# ============================================================

def decode_lldp_packet(raw: bytes) -> dict | None:
    """
    Decodifica quadros Ethernet contendo o protocolo LLDP (EtherType 0x88cc).
    """
    try:
        if len(raw) < 14:
            return None

        # LLDP can also be carried in tagged Ethernet frames.
        ethertype = struct.unpack("!H", raw[12:14])[0]
        offset = 14
        while ethertype in (0x8100, 0x88A8, 0x9100):
            if len(raw) < offset + 4:
                return None
            ethertype = struct.unpack("!H", raw[offset + 2 : offset + 4])[0]
            offset += 4
        if ethertype != 0x88CC:
            return None

        neighbor = {
            "protocol": "LLDP",
            "timestamp": datetime.now().isoformat(),
        }

        while offset + 2 <= len(raw):
            tlv_header = struct.unpack("!H", raw[offset : offset + 2])[0]
            tlv_type = (tlv_header >> 9) & 0x7F
            tlv_length = tlv_header & 0x01FF

            offset += 2

            # TLV 0 representa o fim do pacote LLDP (End of LLDPDU)
            if offset + tlv_length > len(raw) or tlv_type == 0:
                break

            value = raw[offset : offset + tlv_length]
            offset += tlv_length

            def text(data):
                return data.decode("utf-8", errors="replace").strip("\x00")

            # Chassis ID (TLV Tipo 1)
            if tlv_type == 1:
                neighbor["chassis_id"] = text(value[1:])

            # Port ID (TLV Tipo 2)
            elif tlv_type == 2:
                neighbor["remote_port"] = text(value[1:])

            # System Name / Hostname (TLV Tipo 5)
            elif tlv_type == 5:
                neighbor["hostname"] = text(value)

            # System Description / Software (TLV Tipo 6)
            elif tlv_type == 6:
                neighbor["software"] = text(value)

            # Management Address / IP (TLV Tipo 8)
            elif tlv_type == 8:
                if len(value) >= 9 and value[1] == 1:  # Subtype 1 = IPv4
                    neighbor["ip"] = socket.inet_ntoa(value[2:6])

        # Se não encontrou nem hostname nem chassis_id, ignora o pacote
        if "hostname" not in neighbor and "chassis_id" not in neighbor:
            return None

        # Fallback de segurança se o switch não enviou o System Name explicitamente
        if "hostname" not in neighbor:
            neighbor["hostname"] = neighbor.get("chassis_id", "Desconhecido")

        return neighbor

    except Exception:
        return None