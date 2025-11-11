package com.juaneuse.sniffx.model;

import java.time.LocalDateTime;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

/**
 *
 * @author juaneuse
 */
public class PacketInfo {
    private LocalDateTime timestamp;
    private Integer length;
    private String protocol;

    public PacketInfo(Packet packet) {
        this.timestamp = LocalDateTime.now();
        this.length = packet.length();
        this.protocol = detectarProtocolo(packet);
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public Integer getLength() {
        return length;
    }

    public String getProtocol() {
        return protocol;
    }
    
    private String detectarProtocolo(Packet packet) {
        if (packet.contains(TcpPacket.class)) return "TCP";
        if (packet.contains(UdpPacket.class)) return "UDP";
        if (packet.contains(IcmpV4CommonPacket.class)) return "ICMP";
        if (packet.contains(ArpPacket.class)) return "ARP";
        if (packet.contains(IpV6Packet.class)) return "IPv6";
        if (packet.contains(IpV4Packet.class)) return "IPv4";
        return "Desconocido";
    }
    
    
}
