package com.juaneuse.sniffx.model;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.HashMap;

/**
 *
 * @author juaneuse
 */
public class SniffContext {
    public LocalDateTime timestamp;
    public String protocol; 
    public String srcMac;
    public String dstMac;
    public String srcIp;
    public String dstIp;
    public Integer srcPort;
    public Integer dstPort;
    public String ipVersion;
    public String tcpFlags;
    public String hexDump;
    public Map<String, Object> extras = new HashMap<>();

    // helper builder
    public static SniffContext create() {
        SniffContext c = new SniffContext();
        c.timestamp = LocalDateTime.now();
        return c;
    }
}

