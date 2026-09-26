#!/usr/bin/env bash

# File: dns_adguard.sh
# Author: Custom AdGuard Home DNS-01 Hook (API Payload Fixed)

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

  # Python liest "user_rules" aus, fügt das Token hinzu und schreibt es in das von der API erwartete "rules"-Feld
  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    # Auslesen aus "user_rules"
    current_rules = data.get("user_rules", [])
    if current_rules is None:
        current_rules = []
    if rule not in current_rules:
        current_rules.append(rule)
    # Senden als "rules" (Wichtig fuer die set_rules API!)
    print(json.dumps({"rules": current_rules}))
except Exception as e:
    sys.exit(1)
' "$_json_status" "$_rule")

  if [ $? -ne 0 ] || [ -z "$_json_payload" ]; then
    _err "Fehler bei der JSON-Verarbeitung während des Hinzufügens."
    return 1
  fi

  _adguard_save_rules "$_json_payload"
}

dns_adguard_rm() {
  fulldomain=$1
  txtvalue=$2

  _info "Entferne TXT-Record für $fulldomain aus AdGuard Home"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"

  _json_status=$(curl -sS --connect-timeout 20 -m 30 -u "$ADGUARD_AUTH" "$ADGUARD_URL/control/filtering/status")
  if [ $? -ne 0 ] || [ -z "$_json_status" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi

  # Python filtert den Eintrag heraus und mappt das Ergebnis wieder auf das "rules"-Feld
  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    current_rules = data.get("user_rules", [])
    if current_rules:
        current_rules = [r for r in current_rules if r != rule]
    print(json.dumps({"rules": current_rules}))
except Exception as e:
    sys.exit(1)
' "$_json_status" "$_rule")

  if [ $? -ne 0 ] || [ -z "$_json_payload" ]; then
    _err "Fehler bei der JSON-Verarbeitung während des Entfernens."
    return 1
  fi

  _adguard_save_rules "$_json_payload"
}

######################################################################
# Interne Hilfsfunktionen
######################################################################

_adguard_init() {
  if [ -n "$ADGUARD_AUTH" ]; then
    _saveaccountconf ADGUARD_AUTH "$ADGUARD_AUTH"
  else
    ADGUARD_AUTH=$(_readaccountconf ADGUARD_AUTH)
  fi

  if [ -n "$ADGUARD_URL" ]; then
    _saveaccountconf ADGUARD_URL "$ADGUARD_URL"
  else
    ADGUARD_URL=$(_readaccountconf ADGUARD_URL)
  fi

  if [ -z "$ADGUARD_URL" ]; then
    ADGUARD_URL="http://localhost:80"
  fi

  if [ -z "$ADGUARD_AUTH" ]; then
    _err "Bitte definiere die Umgebungsvariable ADGUARD_AUTH='user:passwort'"
    return 1
  fi
}

_adguard_save_rules() {
  _payload=$1

  _res=$(curl -sS --connect-timeout 20 -m 30 -u "$ADGUARD_AUTH" \
    -X POST \
    -H "Content-Type: application/json" \
    -d "$_payload" \
    "$ADGUARD_URL/control/filtering/set_rules")
  
  if [ $? -eq 0 ]; then
    _info "AdGuard Filterregeln erfolgreich aktualisiert."
    return 0
  else
    _err "Fehler beim Speichern der Regeln in AdGuard Home."
    return 1
  fi
}
