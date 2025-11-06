"""
Helper function to parse and format IP packets for logging.
"""
import struct
import socket

def format_packet(packet):
    """Parses an IP packet and returns a formatted string."""
    try:
        # IP Header (first 20 bytes)
        ip_header = packet[:20]
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)

        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])

        header_info = f"IP Packet: V={version}, IHL={iph_length}, TTL={ttl}, Protocol={protocol}, From={s_addr}, To={d_addr}"

        # Transport Layer
        transport_header = packet[iph_length:iph_length+8]
        if protocol == 6: # TCP
            tcph = struct.unpack('!HHLLBBHH', transport_header)
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            tcph_length = doff_reserved >> 4
            transport_info = f"  TCP: Src Port={source_port}, Dst Port={dest_port}, Seq={sequence}, Ack={acknowledgement}"
        elif protocol == 17: # UDP
            udph = struct.unpack('!HHHH', transport_header)
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            transport_info = f"  UDP: Src Port={source_port}, Dst Port={dest_port}, Length={length}"
        elif protocol == 1: # ICMP
            icmph = struct.unpack('!BBH', transport_header[:4])
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            transport_info = f"  ICMP: Type={icmp_type}, Code={code}, Checksum={checksum}"
        else:
            transport_info = f"  Protocol: {protocol}"

        return f"{header_info}\n{transport_info}"

    except struct.error:
        return f"Malformed packet (first 64 bytes): {packet[:64].hex()}"
    except Exception as e:
        return f"Error parsing packet: {e}"
