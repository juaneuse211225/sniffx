package com.juaneuse.sniffx.model;

import com.juaneuse.sniffx.parser.ParsedPacket;
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
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getIpVersion() {
        return ipVersion;
    }

    public String getSrcIp() {
        return srcIp;
    }

    public String getDstIp() {
        return dstIp;
    }

    public Integer getSrcPort() {
        return srcPort;
    }

    public Integer getDstPort() {
        return dstPort;
    }
    
    public Integer getLegth(){
        return length;
    }

    public String getTcpFlags() {
        return tcpFlags;
    }

    public String getHexDump() {
        return hexDump;
    }

    public static PacketDetails from(PacketInfo info) {
        ParsedPacket p = info.getParsed();

    PacketDetails d = new PacketDetails();
    d.timestamp = p.timestamp;
    d.protocol = p.protocol;
    d.ipVersion = p.ipVersion;
    d.srcIp = p.srcIp;
    d.dstIp = p.dstIp;
    d.srcPort = p.srcPort;
    d.dstPort = p.dstPort;
    d.tcpFlags = p.tcpFlags;
    d.length = p.length;
    d.hexDump = p.hexDump;

    return d;
}


}
