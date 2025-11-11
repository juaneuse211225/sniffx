package com.juaneuse.sniffx.sniffer;

import com.juaneuse.sniffx.model.PacketInfo;

/**
 *
 * @author juaneuse
 */
public interface PacketObserver {
    void onPacketReceived(PacketInfo packet);
}
