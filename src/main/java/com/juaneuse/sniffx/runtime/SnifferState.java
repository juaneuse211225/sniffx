package com.juaneuse.sniffx.runtime;

/**
 *
 * @author juaneuse
 */
public interface SnifferState {
    void start(SnifferRuntimeContext ctx);
    void stop(SnifferRuntimeContext ctx);
    String name();
}
