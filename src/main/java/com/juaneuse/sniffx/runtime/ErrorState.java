package com.juaneuse.sniffx.runtime;

/**
 *
 * @author juaneuse
 */
public class ErrorState implements SnifferState {

    private final String message;

    public ErrorState(String message) {
        this.message = message;
    }

    @Override
    public void start(SnifferRuntimeContext ctx) {
        throw new IllegalStateException(
            "No se puede iniciar. Estado ERROR: " + message
        );
    }

    @Override
    public void stop(SnifferRuntimeContext ctx) {
        ctx.setState(new StoppedState());
    }

    @Override
    public String name() {
        return "ERROR";
    }

    public String getMessage() {
        return message;
    }
}
