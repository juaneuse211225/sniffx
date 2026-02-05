package com.juaneuse.sniffx.dissector;

/**
 *
 * @author juaneuse
 */
public class DissectorRegistry {

    private static final DissectorChain CHAIN = new DissectorChain();

    static {
        CHAIN.register(new EthernetDissector());
        CHAIN.register(new ArpDissector());
        CHAIN.register(new Ipv4Dissector());
        CHAIN.register(new Ipv6Dissector());
        CHAIN.register(new Icmpv4Dissector());
        CHAIN.register(new Icmpv6Dissector());
        CHAIN.register(new TcpDissector());
        CHAIN.register(new UdpDissector());
    }

    public static DissectorChain getChain() {
        return CHAIN;
    }
}

