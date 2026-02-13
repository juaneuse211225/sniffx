package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import java.util.ArrayList;
import java.util.List;
import javafx.collections.ObservableList;

public class PacketUiDrainManager {

    private final PacketBacklogBuffer backlogBuffer;
    private final ObservableList<PacketDetails> packetList;
    private final int drainBatchSize;
    private final int maxUiPackets;
    private final int maxQueueSize;

    public PacketUiDrainManager(
            PacketBacklogBuffer backlogBuffer,
            ObservableList<PacketDetails> packetList,
            int drainBatchSize,
            int maxUiPackets,
            int maxQueueSize
    ) {
        this.backlogBuffer = backlogBuffer;
        this.packetList = packetList;
        this.drainBatchSize = drainBatchSize;
        this.maxUiPackets = maxUiPackets;
        this.maxQueueSize = maxQueueSize;
    }

    public void reset() {
        backlogBuffer.reset();
        packetList.clear();
    }

    public void enqueueFallback(PacketDetails details) {
        backlogBuffer.enqueueWithLimit(details, maxQueueSize);
    }

    public boolean drainPendingPackets() {
        List<PacketDetails> batch = new ArrayList<>(drainBatchSize);
        backlogBuffer.drainTo(batch, drainBatchSize);

        if (!batch.isEmpty()) {
            packetList.addAll(batch);
            int overflow = packetList.size() - maxUiPackets;
            if (overflow > 0) {
                packetList.remove(0, overflow);
            }
        }

        return backlogBuffer.size() > maxQueueSize / 2;
    }

    public boolean isQueueEmpty() {
        return backlogBuffer.size() == 0;
    }
}
