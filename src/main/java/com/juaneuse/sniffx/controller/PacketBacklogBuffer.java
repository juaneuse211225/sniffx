package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import java.util.List;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;

public class PacketBacklogBuffer {

    private final Queue<PacketDetails> queue = new ConcurrentLinkedQueue<>();
    private final AtomicInteger count = new AtomicInteger();

    public int enqueueWithLimit(PacketDetails details, int maxQueueSize) {
        queue.offer(details);
        int currentSize = count.incrementAndGet();

        while (currentSize > maxQueueSize) {
            PacketDetails dropped = queue.poll();
            if (dropped == null) {
                break;
            }
            currentSize = count.decrementAndGet();
        }

        return currentSize;
    }

    public void reset() {
        queue.clear();
        count.set(0);
    }

    public int drainTo(List<PacketDetails> target, int maxItems) {
        int drained = 0;
        for (int i = 0; i < maxItems; i++) {
            PacketDetails packet = queue.poll();
            if (packet == null) {
                break;
            }
            count.decrementAndGet();
            target.add(packet);
            drained++;
        }

        return drained;
    }

    public int size() {
        return count.get();
    }
}
