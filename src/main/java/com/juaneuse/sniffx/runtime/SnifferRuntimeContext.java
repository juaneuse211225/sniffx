package com.juaneuse.sniffx.runtime;

import com.juaneuse.sniffx.sniffer.PacketSniffer;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author juaneuse
 */
public class SnifferRuntimeContext {

    private SnifferState state;
    private final PacketSniffer sniffer;
    private SnifferConfig config;
    private final List<SnifferStateObserver> observers = new ArrayList<>();

    public SnifferRuntimeContext(PacketSniffer sniffer) {
        this.sniffer = sniffer;
        this.state = new StoppedState();
    }

    public void configure(SnifferConfig config) {
        this.config = config;
    }

    SnifferConfig config() {
        if (config == null) {
            throw new IllegalStateException("Sniffer no configurado");
        }
        return config;
    }

    PacketSniffer sniffer() {
        return sniffer;
    }

    public void start() {
        try {
            state.start(this);
        } catch (Exception e) {
            setState(new ErrorState(e.getMessage()));
        }
    }

    public void stop() {
        try {
            state.stop(this);
        } catch (Exception e) {
            setState(new ErrorState(e.getMessage()));
        }
    }

    void setState(SnifferState s) {
        if (this.state.getClass() == s.getClass()) {
            return;
        }
        this.state = s;
        notifyObservers();
    }

    public void addObserver(SnifferStateObserver o) {
        observers.add(o);
    }

    private void notifyObservers() {
        for (SnifferStateObserver o : observers) {
            o.onStateChanged(state);
        }
    }

    public String getStateName() {
        return state.name();
    }
}
