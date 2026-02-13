package com.juaneuse.sniffx.controller;

import com.juaneuse.sniffx.model.PacketDetails;
import com.juaneuse.sniffx.storage.CaptureStorageService;
import javafx.collections.ObservableList;

import java.io.IOException;
import java.util.List;

public class CapturePagingManager {

    private final CaptureStorageService captureStorageService;
    private final ObservableList<PacketDetails> packetList;
    private final int maxInMemory;
    private final int pageSize;

    private long memoryStartOffset = 0L;
    private boolean loadingPage = false;

    public CapturePagingManager(CaptureStorageService captureStorageService,
                                ObservableList<PacketDetails> packetList,
                                int maxInMemory,
                                int pageSize) {
        this.captureStorageService = captureStorageService;
        this.packetList = packetList;
        this.maxInMemory = maxInMemory;
        this.pageSize = pageSize;
    }

    public void resetWindow() {
        packetList.clear();
        memoryStartOffset = 0L;
    }

    public void startSession(String networkInterface, String bpfFilter) throws IOException {
        resetWindow();
        captureStorageService.startSession(networkInterface, bpfFilter);
    }

    public void append(PacketDetails details) throws IOException {
        packetList.add(details);
        captureStorageService.append(details);

        if (packetList.size() > maxInMemory) {
            packetList.remove(0);
            memoryStartOffset++;
        }
    }

    public void loadPreviousPage() throws IOException {
        if (loadingPage || memoryStartOffset <= 0) {
            return;
        }

        loadingPage = true;
        try {
            long readOffset = Math.max(0, memoryStartOffset - pageSize);
            int size = (int) (memoryStartOffset - readOffset);
            if (size <= 0) {
                return;
            }

            List<PacketDetails> packets = captureStorageService.readPage(readOffset, size);
            if (packets.isEmpty()) {
                return;
            }

            packetList.addAll(0, packets);
            memoryStartOffset = readOffset;

            while (packetList.size() > maxInMemory) {
                packetList.remove(packetList.size() - 1);
            }
        } finally {
            loadingPage = false;
        }
    }

    public void closeSession() throws IOException {
        captureStorageService.closeSession();
    }
}
