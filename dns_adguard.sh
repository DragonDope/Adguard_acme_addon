#!/usr/bin/env bash

# File: dns_adguard.sh
# Author: DragonDope with AI support
# Description: Custom AdGuard Home DNS-01 Hook (Conditional Cache Refresh)

_adguard_clear_cache() {
  _info "Erzwinge sofortigen DNS-Cache-Refresh in AdGuard Home..."
  
  _cache_res=$(curl -sS -w "%{http_code}" --connect-timeout 20 -m 30 \
    -u "$ADGUARD_AUTH" \
    -H "Content-Type: application/json" \
    -X POST \
    -d '{}' \
    "$ADGUARD_URL/control/cache_clear")

  _http_status="${_cache_res: -3}"

  if [ "$_http_status" != "200" ]; then
    _err "Fehler beim Leeren des DNS-Caches. HTTP-Status: $_http_status"
    return 1
  fi

  _info "✓ DNS-Cache erfolgreich geleert."
  return 0
}

dns_adguard_add() {
  fulldomain=$1
  txtvalue=$2

  _info "Nutze AdGuard Home API, um TXT-Record für $fulldomain hinzuzufügen"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  _debug "Generierte Filterregel: $_rule"

  _json_status=$(curl -sS --connect-timeout 20 -m 30 -u "$ADGUARD_AUTH" "$ADGUARD_URL/control/filtering/status")
  if [ $? -ne 0 ] || [ -z "$_json_status" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi

  # Prüfe vorab in Bash, ob die Regel bereits existiert
  if echo "$_json_status" | grep -qF "$_rule"; then
    _info "Regel existiert bereits in AdGuard Home. Kein Update notwendig."
    return 0
  fi

  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    current_rules = data.get("user_rules", [])
    if current_rules is None:
        current_rules = []
    if rule not in current_rules:
        current_rules.append(rule)
    print(json.dumps({"rules": current_rules}))
except Exception as e:
    sys.exit(1)
' "$_json_status" "$_rule")

  if [ $? -ne 0 ] || [ -z "$_json_payload" ]; then
    _err "Fehler bei der JSON-Verarbeitung während des Hinzufügens."
    return 1
  fi

  _adguard_save_rules "$_json_payload" || return 1
  
  # Cache NUR leeren, wenn die neue Regel erfolgreich gespeichert wurde
  _adguard_clear_cache
}

dns_adguard_rm() {
  fulldomain=$1
  txtvalue=$2

  _info "Entferne TXT-Record für $fulldomain aus AdGuard Home"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  _debug "Zu entfernende Filterregel: $_rule"

  _json_status=$(curl -sS --connect-timeout 20 -m 30 -u "$ADGUARD_AUTH" "$ADGUARD_URL/control/filtering/status")
  if [ $? -ne 0 ] || [ -z "$_json_status" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi

  # Prüfe vorab in Bash, ob die Regel überhaupt existiert
  if ! echo "$_json_status" | grep -qF "$_rule"; then
    _info "Regel existiert nicht in AdGuard Home. Kein Löschen notwendig."
    return 0
  fi

  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    current_rules = data.get("user_rules", [])
    if current_rules is None:
        current_rules = []
    updated_rules = [r for r in current_rules if r != rule]
    print(json.dumps({"rules": updated_rules}))
except Exception as e:
    sys.exit(1)
' "$_json_status" "$_rule")

  if [ $? -ne 0 ] || [ -z "$_json_payload" ]; then
    _err "Fehler bei der JSON-Verarbeitung während des Entfernens."
    return 1
  fi

  _adguard_save_rules "$_json_payload" || return 1

  # Cache NUR leeren, wenn die Regel erfolgreich entfernt wurde
  _adguard_clear_cache
}
