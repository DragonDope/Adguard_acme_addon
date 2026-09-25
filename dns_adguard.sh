#!/usr/bin/env bash

# File: dns_adguard.sh
# Author: Custom AdGuard Home DNS-01 Hook (Safe Python JSON Parser)

dns_adguard_add() {
  fulldomain=$1
  txtvalue=$2

  _info "Nutze AdGuard Home API, um TXT-Record für $fulldomain hinzuzufügen"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  _debug "Generierte Filterregel: $_rule"

  # Aktuelles JSON-Statusobjekt direkt von der API holen
  _json_status=$(curl -sS --connect-timeout 20 -m 30 -u "$ADGUARD_AUTH" "$ADGUARD_URL/control/filtering/status")
  if [ $? -ne 0 ] || [ -z "$_json_status" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi

  # Python fügt die Regel sicher in das JSON-Array ein, falls sie noch nicht existiert
  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    # Falls das Feld fehlt, initialisieren
    if "user_rules" not in data or data["user_rules"] is None:
        data["user_rules"] = []
    if rule not in data["user_rules"]:
        data["user_rules"].append(rule)
    # Nur das benötigte Objekt für set_rules zurückgeben
    print(json.dumps({"user_rules": data["user_rules"]}))
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

  # Python entfernt gezielt nur diese eine Regel aus dem Array
  _json_payload=$(python3 -c '
import sys, json
try:
    data = json.loads(sys.argv[1])
    rule = sys.argv[2]
    if "user_rules" in data and data["user_rules"]:
        data["user_rules"] = [r for r in data["user_rules"] if r != rule]
    print(json.dumps({"user_rules": data.get("user_rules", [])}))
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

  # Senden des validierten JSON-Strings an AdGuard
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
