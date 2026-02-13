# Máquina de estados del runtime

## Estados

El runtime (`runtime/*`) define tres estados explícitos:

- **`STOPPED`** (`StoppedState`)
  - Estado inicial del `SnifferRuntimeContext`.
  - `start(ctx)` inicia captura con la configuración actual y transiciona a `RUNNING`.
  - `stop(ctx)` es `no-op`.

- **`RUNNING`** (`RunningState`)
  - Captura activa.
  - `start(ctx)` es `no-op` (no reinicia desde dentro del estado).
  - `stop(ctx)` llama `sniffer.stop()` y transiciona a `STOPPED`.

- **`ERROR`** (`ErrorState`)
  - Estado de fallo cuando ocurre excepción en `start()` o `stop()` del contexto.
  - `start(ctx)` lanza `IllegalStateException` (no permite iniciar directamente).
  - `stop(ctx)` fuerza transición a `STOPPED` como mecanismo de recuperación.

## Transiciones válidas y disparadores

```text
STOPPED --(start + config válida)--> RUNNING
RUNNING --(stop)--------------------> STOPPED
STOPPED/RUNNING --(excepción)-------> ERROR
ERROR --(stop)----------------------> STOPPED
```

Detalle de disparadores:

1. **STOPPED -> RUNNING**
   - Disparador: `SnifferRuntimeContext.start()`.
   - Precondición: se llamó antes `configure(SnifferConfig)`.
   - Acción: `PacketSniffer.start(interface, interfaces, bpf)`.

2. **RUNNING -> STOPPED**
   - Disparador: `SnifferRuntimeContext.stop()`.
   - Acción: `PacketSniffer.stop()`.

3. **{STOPPED|RUNNING} -> ERROR**
   - Disparador: excepción durante `state.start(ctx)` o `state.stop(ctx)`.
   - Acción: `setState(new ErrorState(e.getMessage()))`.

4. **ERROR -> STOPPED**
   - Disparador: `SnifferRuntimeContext.stop()` cuando estado actual es `ERROR`.
   - Acción: `ErrorState.stop(ctx)` hace `setState(new StoppedState())`.

## Comportamiento esperado de UI ante error

Cuando el controlador recibe `onStateChanged(ErrorState)`:

1. Muestra alerta modal de error (`AlertType.ERROR`) con mensaje del runtime.
2. Fuerza el toggle de captura a estado **detenido** (`btnStatus` en falso, texto "Iniciar").
3. Debe permitir al usuario corregir interfaz/filtro y volver a intentar.

Prácticamente, la UI no debe quedarse en una falsa condición de "capturando" tras un fallo.
