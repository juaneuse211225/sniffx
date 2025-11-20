package com.juaneuse.sniffx.model;

import java.time.LocalDateTime;
import org.pcap4j.packet.ArpPacket;
import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
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
    private String srcIp;
    private String dstIp;

    public PacketInfo(Packet packet) {
        this.timestamp = LocalDateTime.now();
        this.length = packet.length();
        this.protocol = detectarProtocolo(packet);
        extraerIps(packet);
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

    public String getDstIp() {
        return dstIp;
    }

    public String getSrcIp() {
        return srcIp;
    }
    
    private String detectarProtocolo(Packet packet) {
        if (packet.contains(TcpPacket.class)) return "TCP";
        if (packet.contains(UdpPacket.class)) return "UDP";
        if (packet.contains(IcmpV4CommonPacket.class) || packet.contains(IcmpV6CommonPacket.class)) return "ICMP";
        if (packet.contains(ArpPacket.class)) return "ARP";
        if (packet.contains(IpV6Packet.class)) return "IPv6";
        if (packet.contains(IpV4Packet.class)) return "IPv4";
        return "Desconocido";
    }
    
    private void extraerIps(Packet packet) {

    // Si es IPv4
    if (packet.contains(IpV4Packet.class)) {
        IpV4Packet ip4 = packet.get(IpV4Packet.class);
        srcIp = "IPv4 -> " + ip4.getHeader().getSrcAddr().getHostAddress();
        dstIp = "IPv4 -> " + ip4.getHeader().getDstAddr().getHostAddress();
        return;
    }

    // Si es IPv6
    if (packet.contains(IpV6Packet.class)) {
        IpV6Packet ip6 = packet.get(IpV6Packet.class);
        srcIp = "IPv6 -> " + ip6.getHeader().getSrcAddr().getHostAddress();
        dstIp = "IPv6 -> " + ip6.getHeader().getDstAddr().getHostAddress();
        return;
    }

    // No es tráfico IP
    srcIp = "N/A";
    dstIp = "N/A";
}

}
