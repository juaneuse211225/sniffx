package com.juaneuse.sniffx.runtime;

import java.util.List;
import org.pcap4j.core.PcapNetworkInterface;

/**
 *
 * @author juaneuse
 */
public record SnifferConfig(
    String interfaceName,
    List<PcapNetworkInterface> interfaces,
    String bpfFilter
) {}
