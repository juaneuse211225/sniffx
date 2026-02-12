package com.juaneuse.sniffx.runtime;

/**
 *
 * @author juaneuse
 */
public class StoppedState implements SnifferState {

    @Override
    public void start(SnifferRuntimeContext ctx) {
        SnifferConfig c = ctx.config();
        ctx.sniffer().start(
                c.interfaceName(),
                c.interfaces(),
                c.bpfFilter()
        );
        ctx.setState(new RunningState());
    }

    @Override
    public void stop(SnifferRuntimeContext ctx) {
        //  no-op
    }

    @Override
    public String name() {
        return "STOPPED";
    }
}

