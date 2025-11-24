package com.juaneuse.sniffx.parser;

import java.time.LocalDateTime;

/**
 *
 * @author juaneuse
 */
public class ParsedPacket {
    public LocalDateTime timestamp;
    public String protocol;
    public String ipVersion;
    public String srcIp;
    public String dstIp;
    
    public Integer srcPort;
    public Integer dstPort;
    
    public String tcpFlags;
    
    public Integer length;
    
    public String hexDump;
}
