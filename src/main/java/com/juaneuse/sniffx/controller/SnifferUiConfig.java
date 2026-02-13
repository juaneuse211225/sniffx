package com.juaneuse.sniffx.controller;

public final class SnifferUiConfig {

    public static final int MAX_UI_PACKETS = 100;
    public static final int DRAIN_BATCH_SIZE = 120;
    public static final int MAX_QUEUE_SIZE = 4_000;
    public static final int DRAIN_INTERVAL_MS = 50;
    public static final int MAX_IN_MEMORY = 100;
    public static final int PAGE_SIZE = 30;

    private SnifferUiConfig() {
    }
}
