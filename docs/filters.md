# Sintaxis de filtros soportada

Este documento resume la gramática implementada por `filter/BpfFilterBuilder.java`.

## Objetivo

`BpfFilterBuilder` permite dos estilos de entrada:

1. **BPF estándar** (se conserva tal cual):
   - `tcp and port 443`
   - `(tcp or udp) and src net 192.168.0.0/16`
2. **Alias amigables de SniffX** (se traducen a BPF):
   - `@8.8.8.8` -> `host 8.8.8.8`
   - `src:@10.0.0.5` -> `src host 10.0.0.5`
   - `dst:443` -> `dst port 443`

## Alias soportados

### Host

- `@IP_O_HOST` -> `host IP_O_HOST`
- `src:@IP_O_HOST` -> `src host IP_O_HOST`
- `dst:@IP_O_HOST` -> `dst host IP_O_HOST`

### Puertos

- `src:80` -> `src port 80`
- `dst:443` -> `dst port 443`
- `src:1000-2000` -> `src portrange 1000-2000`
- `dst:1000-2000` -> `dst portrange 1000-2000`
- `ports:80,443,1000-2000` -> `(port 80 or port 443 or portrange 1000-2000)`

## Operadores y expresiones avanzadas

Se admiten operadores booleanos y agrupaciones de BPF:

- `and`
- `or`
- `not`
- paréntesis: `(` `)`

También se admiten primitivas habituales de BPF como:

- `host`, `src host`, `dst host`
- `port`, `src port`, `dst port`, `portrange`
- `net`, `proto`, `ip`, `ip6`, `tcp`, `udp`, `icmp`, `icmp6`, `arp`

## Validaciones

El builder valida:

1. **Entrada vacía** -> retorna cadena vacía (`""`).
2. **Paréntesis balanceados** -> si no, lanza `IllegalArgumentException`.
3. **Tokens inválidos** -> si encuentra un token no soportado, lanza `IllegalArgumentException`.

En la UI (`SnifferController`), estos errores se muestran como alerta para evitar iniciar una captura con filtro inválido.

## Ejemplos

| Input usuario | BPF generado |
|---|---|
| `tcp and port 443` | `tcp and port 443` |
| `(tcp or udp) and src net 192.168.0.0/16` | `(tcp or udp) and src net 192.168.0.0/16` |
| `icmp and @8.8.8.8` | `icmp and host 8.8.8.8` |
| `tcp src:@192.168.1.10 dst:443` | `tcp src host 192.168.1.10 dst port 443` |
| `ports:53,80,443` | `(port 53 or port 80 or port 443)` |

## Compatibilidad

La sintaxis heredada tipo `@host` sigue siendo válida, pero ahora se pueden escribir filtros BPF completos sin perder expresividad.
