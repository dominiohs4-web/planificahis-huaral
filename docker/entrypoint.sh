#!/bin/sh
set -eu

# Render inyecta $PORT en tiempo de ejecución. Apache no debe quedar fijo en 80.
PORT="${PORT:-80}"
case "$PORT" in
  ''|*[!0-9]*) PORT=80 ;;
esac

sed -ri "s/^Listen .*/Listen ${PORT}/" /etc/apache2/ports.conf
sed -ri "s/<VirtualHost \*:[0-9]+>/<VirtualHost *:${PORT}>/" /etc/apache2/sites-available/000-default.conf

# Evita el aviso "Could not reliably determine the server's fully qualified domain name".
if ! grep -q '^ServerName ' /etc/apache2/apache2.conf; then
  echo "ServerName localhost" >> /etc/apache2/apache2.conf
fi

exec "$@"
