# Sintaxis de filtros soportada

Este documento resume la gramática implementada por `filter/SimpleFilterParser.java`.

## Tokens soportados

### 1) Protocolo

Reconoce (case-insensitive):

- `tcp`
- `udp`
- `icmp`
- `arp`
- `ip`

Salida BPF: se emite como el literal en minúsculas.

---

### 2) Host

- Host genérico: `@IP` -> `host IP`
- Host origen: `src:@IP` -> `src host IP`
- Host destino: `dst:@IP` -> `dst host IP`

> Nota: si se combinan varias formas de host en una misma entrada, el parser conserva la última que encuentre.

---

### 3) Puerto / rango

- Puerto simple: `80` -> `port 80`
- Rango: `1000-2000` -> `portrange 1000-2000`

> Nota: igual que host/protocolo, si aparecen varios puertos/rangos, prevalece el último token válido detectado.

## Reglas de composición

El parser construye BPF en este orden:

1. Protocolo
2. Puerto o rango
3. Host

Uniendo cada bloque con `and` cuando corresponda.

## Ejemplos de entrada y BPF resultante

| Input usuario | BPF generado |
|---|---|
| `tcp` | `tcp` |
| `udp 53` | `udp and port 53` |
| `icmp @8.8.8.8` | `icmp and host 8.8.8.8` |
| `tcp src:@192.168.1.10 443` | `tcp and port 443 and src host 192.168.1.10` |
| `udp dst:@10.0.0.5 1000-2000` | `udp and portrange 1000-2000 and dst host 10.0.0.5` |
| `arp @192.168.1.1` | `arp and host 192.168.1.1` |
| `ip 80` | `ip and port 80` |
| *(vacío o espacios)* | `` (cadena vacía) |

## Limitaciones actuales

- No hay paréntesis ni operadores `or`/`not`.
- No valida formato de IP.
- No contempla nombres de host DNS.
- No acepta formas BPF avanzadas (`src port`, `dst port`, `net`, etc.).
