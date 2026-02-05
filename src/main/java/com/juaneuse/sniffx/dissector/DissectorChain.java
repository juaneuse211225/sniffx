package com.juaneuse.sniffx.dissector;

import com.juaneuse.sniffx.model.SniffContext;
import java.util.ArrayList;
import java.util.List;
import org.pcap4j.packet.Packet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author juaneuse
 */
public class DissectorChain {
    private static final Logger logger = LoggerFactory.getLogger(DissectorChain.class);
    private final List<Dissector> dissectors = new ArrayList<>();

    public void register(Dissector d) {
        dissectors.add(d);
    }

    public SniffContext dissect(Packet p) {
        SniffContext ctx = SniffContext.create();
        for (Dissector d : dissectors) {
            try {
                if (d.supports(p)) {
                    d.dissect(p, ctx);
                }
            } catch (Exception e) {
                // no dejar que un dissector rompa el chain
                logger.error("problema en cadena disectores", e);
            }
        }
        return ctx;
    }
}
