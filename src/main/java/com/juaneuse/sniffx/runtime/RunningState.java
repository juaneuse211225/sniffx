package com.juaneuse.sniffx.runtime;

/**
 *
 * @author juaneuse
 */
public class RunningState implements SnifferState {

    @Override
    public void start(SnifferRuntimeContext ctx) {
        //no-op
    }

    @Override
    public void stop(SnifferRuntimeContext ctx) {
        ctx.sniffer().stop();
        ctx.setState(new StoppedState());
    }

    @Override
    public String name() {
        return "RUNNING";
    }
}
