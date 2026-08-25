# udp-watch — Architecture

## Flujo

```
/proc/net/udp ─┐
               ├─ parse_udp_file() ──► std::vector<UdpSocket>
/proc/net/udp6 ┘                              │
                                              ▼
                                    resolve_procs() (inode→PID)
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                  ▼
                              render_snapshot()   render_json()
                                    │
                                    ▼
                              watch: prev vs cur
                              delta (new/closed/drops)
```

## Decisiones técnicas

- **Monolítico stdlib-only**: un solo TU, g++ -std=c++23 directo, zero dependencias.
- **Paleta ANSI mutable**: `--no-color` vacía las strings de color en runtime (no
  `constexpr`) para que selftest/watch/snapshot usen la misma configuración.
- **Decodificación IPv6**: el kernel imprime cada `__be32` con `%08X` en host
  little-endian, así que cada grupo de 8 hex es la imagen byte-swapped de la
  palabra de red. `2001:db8::1` aparece como `B80D0120 00000000 00000000 01000000`.
- **Tolerancia a comentarios**: `--file` salta líneas `#` y recorta anotaciones
  tras `#` — los dumps de demo se pueden documentar inline.
- **inode→PID**: escaneo de `/proc/[0-9]*/fd` resolviendo symlinks `socket:[INODE]`.
  Errores de permisos se limpian (`ec.clear()`) y se continúa — nunca corta el scan.
- **drops como KPI**: la columna 12 del kernel cuenta paquetes UDP descartados por
  socket (buffer RX lleno). Es el primer síntoma de presión en el stack UDP.

## Riesgos conocidos

- `/proc/net/udp` en hosts quietos tiene 1 sola línea (header) — el demo mode
  (`--demo`) y `--file` existen para entornos sin tráfico UDP.
- Los estados UDP son el enum TCP reutilizado: 01 (ESTABLISHED) = conectado,
  07 (CLOSE) = no conectado. Otros códigos → UNKNOWN.