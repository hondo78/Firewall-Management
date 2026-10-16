#!/bin/sh
# Barracuda CloudGen Firewall: Netzobjekte, Dienste und Weiterleitungsregeln für den Migrationsassistenten exportieren.
# Nur lesend (GET). Aufruf: BOX=10.0.0.1 TOKEN=<REST-API-Token> sh barracuda-export.sh > barracuda.json
# Voraussetzung: REST-API auf der Box aktiviert (Configuration › Administrative Settings › REST API), curl und jq.
set -eu
: "${BOX:?BOX=<Adresse der Box> setzen}" "${TOKEN:?TOKEN=<REST-API-Token> setzen}"
PORT="${PORT:-8443}"
get() { curl -fsSk -H "X-API-Token: $TOKEN" "https://$BOX:$PORT/rest/config/v1/forwarding-firewall/$1?expand=true"; }
jq -n --arg name "$BOX" --argjson networks "$(get objects/networks)" --argjson services "$(get objects/services)" \
  --argjson rules "$(get rules)" '{name: $name, networks: $networks, services: $services, rules: $rules}'
