#!/bin/sh
# Escaneo nocturno lanzado por cron. Los informes se guardan fuera del repo
# para no subir datos de la red a GitHub.
set -eu

PROYECTO="$(cd "$(dirname "$0")/.." && pwd)"
DESTINO="${HOME}/informes-escaner"
FECHA="$(date +%Y-%m-%d)"

mkdir -p "$DESTINO"
cd "$PROYECTO"

# flock evita que dos ejecuciones se solapen si una tarda más de 24 h.
exec flock -n "$DESTINO/.lock" \
    python3 -m escaner_ia 192.168.56.0/24 10.0.2.0/24 \
        --verificar-cve \
        --salida "$DESTINO/informe-$FECHA.md" \
        >> "$DESTINO/escaner.log" 2>&1
