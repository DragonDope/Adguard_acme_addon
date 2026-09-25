#!/usr/bin/env bash

# File: dns_adguard.sh
# Author: Custom AdGuard Home DNS-01 Hook for acme.sh
#
# ADGUARD_AUTH="user:password"
# ADGUARD_URL="http://127.0.0.1:80" (Optional, Standard ist http://localhost:80)

dns_adguard_add() {
  fulldomain=$1
  txtvalue=$2

  _info "Nutze AdGuard Home API, um TXT-Record für $fulldomain hinzuzufügen"

  # Konfiguration einlesen / validieren
  _adguard_init || return 1

  # AdGuard-spezifische Filterregel generieren
  # Format: ||domain^$dnstype=TXT,dnsrewrite=NOERROR;TXT;value
  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  _debug "Generierte Filterregel: $_rule"

  # Aktuelle Regeln holen, um die neue Regel anzuhängen
  _current_rules=$(_adguard_get_rules)
  
  # Neue Regel formen (mit Zeilenumbruch getrennt)
  if [ -z "$_current_rules" ]; then
    _payload="$_rule"
  else
    _payload="$_current_rules"$'\n'"$_rule"
  fi

  _adguard_save_rules "$_payload"
}

dns_adguard_rm() {
  fulldomain=$1
  txtvalue=$2

  _info "Entferne TXT-Record für $fulldomain aus AdGuard Home"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  
  # Aktuelle Regeln holen
  _current_rules=$(_adguard_get_rules)
  
  # Die spezifische Challenge-Regel herausfiltern
  _payload=$(echo "$_current_rules" | grep -F -v "$_rule")

  _adguard_save_rules "$_payload"
}

######################################################################
# Interne Hilfsfunktionen
######################################################################

_adguard_init() {
  # Zugangsdaten aus Umgebungsvariablen sichern, falls vorhanden (acme.sh speichert diese automatisch)
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

  # Fallback falls URL nicht definiert
  if [ -z "$ADGUARD_URL" ]; then
    ADGUARD_URL="http://localhost:80"
  fi

  if [ -z "$ADGUARD_AUTH" ]; then
    _err "Bitte definiere die Umgebungsvariable ADGUARD_AUTH='user:passwort'"
    return 1
  fi

  # Header für Basic-Auth vorbereiten (In acme.sh ist _base64 verfügbar)
  _encoded_auth=$(printf "%s" "$ADGUARD_AUTH" | _base64)
  _adguard_headers="Authorization: Basic $_encoded_auth"
}

_adguard_get_rules() {
  # Ruft die aktuellen benutzerdefinierten Filterregeln ab
  _res=$(_with_retry _get "$ADGUARD_URL/control/filtering/status" "" "$_adguard_headers")
  if [ $? -ne 0 ] || [ -z "$_res" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi
  # Extrahiere das Array user_rules aus dem JSON
  echo "$_res" | tr -d '\n' | grep -o '"user_rules":\[[^]*]*\]' | sed 's/"user_rules":\[//;s/\]$//' | sed 's/"//g' | tr ',' '\n'
}

_adguard_save_rules() {
  _rules_content=$1

  # JSON Payload für das Setzen der Regeln aufbereiten
  # Jede Zeile muss korrekt als JSON-String maskiert im Array landen
  _json_rules=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    # Anführungszeichen maskieren
    _escaped=$(echo "$line" | sed 's/"/\\"/g')
    if [ -z "$_json_rules" ]; then
      _json_rules="\"$_escaped\""
    else
      _json_rules="$_json_rules,\"$_escaped\""
    fi
  done <<< "$_rules_content"

  _json_payload="{\"user_rules\":[$_json_rules]}"

  # API-Aufruf zum Aktualisieren der Regeln
  _res=$(_post "$_json_payload" "$ADGUARD_URL/control/filtering/set_rules" "" "POST" "application/json" "$_adguard_headers")
  
  if [ $? -eq 0 ]; then
    _info "AdGuard Filterregeln erfolgreich aktualisiert."
    return 0
  else
    _err "Fehler beim Speichern der Regeln in AdGuard Home."
    return 1
  fi
}
