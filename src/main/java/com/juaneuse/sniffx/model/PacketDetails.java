package com.juaneuse.sniffx.model;

import com.juaneuse.sniffx.dissector.DissectorRegistry;
import org.pcap4j.packet.Packet;

import java.time.LocalDateTime;

public class PacketDetails {

    private LocalDateTime timestamp;
    private String protocol;
    private String ipVersion;

    private String srcIp;
    private String dstIp;

    private Integer srcPort;
    private Integer dstPort;

    private Integer length;
    private String tcpFlags;
    private String hexDump;

    public LocalDateTime getTimestamp() { return timestamp; }
    public String getProtocol() { return protocol; }
    public String getIpVersion() { return ipVersion; }
    public String getSrcIp() { return srcIp; }
    public String getDstIp() { return dstIp; }
    public Integer getSrcPort() { return srcPort; }
    public Integer getDstPort() { return dstPort; }
    public Integer getLength() { return length; }
    public String getTcpFlags() { return tcpFlags; }
    public String getHexDump() { return hexDump; }

    public static PacketDetails from(PacketInfo info) {

        Packet raw = info.getRawPacket(); // Packet de pcap4j

        SniffContext ctx = DissectorRegistry.getChain().dissect(raw);

        PacketDetails d = new PacketDetails();
        d.timestamp = info.getTimestamp();
        d.protocol  = ctx.protocol;
        d.ipVersion = ctx.ipVersion;
        d.srcIp     = ctx.srcIp;
        d.dstIp     = ctx.dstIp;
        d.srcPort   = ctx.srcPort;
        d.dstPort   = ctx.dstPort;
        d.tcpFlags  = (String) ctx.extras.get("tcpFlags");
        d.length    = raw.length();
        d.hexDump   = info.getHexDump();

        return d;
    }
}

