# udp-watch

Monitor de sockets UDP del kernel Linux en tiempo real (C++23, zero deps).

Lee `/proc/net/udp` y `/proc/net/udp6` para listar sockets UDP con su dirección
local/remota decodificada (IPv4 e IPv6), estado (conectado / no conectado), uid,
columna `drops` (paquetes descartados por socket), inode, y el proceso propietario
resuelto vía `/proc/*/fd` → socket inode. Útil para auditar puertos UDP abiertos
y detectar sockets descartando tráfico.

## Features

- **Parse de `/proc/net/udp` + `/proc/net/udp6`**: formato estándar del kernel, IPv4 e IPv6
- **Decodificación de direcciones**: IPv4 little-endian (`0100007F` → 127.0.0.1) e IPv6
  byte-swapped por palabra (incluye `::ffff:` mapped), compresión `::` estándar
- **Estados UDP**: 0x01 → CONNECTED (socket con `connect(2)`), 0x07 → UNCONNECTED (el común)
- **Columna drops**: paquete descartados por socket (buffer lleno), marcada en rojo
- **Nombres de servicios**: `port 53 → domain`, `123 → ntp`... desde `/etc/services`
- **Resolución PID/proceso**: inode → `/proc/*/fd` → comm (tolerante a errores de permisos)
- **Modo watch (`--watch N`)**: refresh periódico con delta (sockets nuevos/cerrados, drops)
- **Salida JSON (`--json`)**: `summary` + array `sockets` validable con `python -m json.tool`
- **Demo mode (`--demo`)**: host sintético DNS/NTP/syslog con 16 sockets y drops
- **Filtros**: `--port N`, `--state CONNECTED|UNCONNECTED`, `--drops`, `--top N`
- **`--file`**: parsea un dump (tolera comentarios `#` y anotaciones)
- **`--no-color`**: paleta ANSI mutable (0 códigos en pipes)
- **Selftest**: 60+ checks (parser, direcciones, estados, filtros, JSON, `/proc` real)

## Build

```bash
g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o udp-watch
```

## Usage

```bash
# Snapshot único (host real)
./udp-watch

# Modo watch (cada 2s) con deltas entre snapshots
./udp-watch --watch 2

# Solo sockets con drops
./udp-watch --drops

# Un puerto concreto
./udp-watch --port 53

# JSON
./udp-watch --json

# Demo (host DNS/NTP/syslog sintético)
./udp-watch --demo

# Parsear un dump con comentarios
./udp-watch --file sample-udp.table --no-color

# Sin colores
./udp-watch --no-color

# Auto-tests
./udp-watch --selftest
```

## Data Source

| Archivo | Contenido |
|---------|-----------|
| `/proc/net/udp` | tabla de sockets UDP IPv4 (13 columnas hex) |
| `/proc/net/udp6` | tabla de sockets UDP IPv6 |

Columnas relevantes:

| # | Campo | Significado |
|---|--------|-------------|
| 1 | local_address | `HEX_IP:HEX_PORT` (little-endian; IPv6 byte-swapped) |
| 2 | rem_address | igual, `00000000:0000` = wildcard |
| 3 | st | estado: `01` CONNECTED, `07` UNCONNECTED |
| 4 | tx_queue:rx_queue | colas de transmisión/recepción |
| 7 | uid | uid del propietario |
| 9 | inode | inode del socket (para resolver el proceso) |
| 12 | drops | paquetes UDP descartados en ese socket |

## Example Output

```
  UDP WATCH — /proc/net/udp + udp6
  ------------------------------------------------------------------------------
  Snapshot: 1785117430  (IPv4: 13, IPv6: 3)

  16 sockets   3 connected   13 unconnected   drops 55  (3 sockets with drops)

  LOCAL ADDRESS            STATE           UID     DROPS  PROC
  ------------------------ --------------- ------ ------- --------------
  0.0.0.0:53 (domain)      UNCONNECTED    102        0  systemd-resolve
  0.0.0.0:68 (dhcpc)       UNCONNECTED      0        0  dhclient
  0.0.0.0:123 (ntp)        UNCONNECTED    104        0  systemd-timesyn
  0.0.0.0:137 (netbios-ns) UNCONNECTED     60       12  nmbd
  0.0.0.0:514 (syslog)     UNCONNECTED    101       34  rsyslogd
  ...
```

## Selftest

```bash
./udp-watch --selftest   # 60+ checks, exit 0 = todo OK
```

Zero dependencias: solo la stdlib de C++23 y `g++ -std=c++23`.