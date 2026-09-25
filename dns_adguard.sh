#!/usr/bin/env bash

# File: dns_adguard.sh
# Author: Custom AdGuard Home DNS-01 Hook for acme.sh (SAN / Multi-Domain Ready)

dns_adguard_add() {
  fulldomain=$1
  txtvalue=$2

  _info "Nutze AdGuard Home API, um TXT-Record für $fulldomain hinzuzufügen"
  _adguard_init || return 1

  _rule="||${fulldomain}^\$dnstype=TXT,dnsrewrite=NOERROR;TXT;${txtvalue}"
  _debug "Generierte Filterregel: $_rule"

  # Aktuelle Regeln holen
  _current_rules=$(_adguard_get_rules)
  
  # Prüfen, ob die exakte Regel schon existiert (Verhindert Duplikate bei SANs)
  if echo "$_current_rules" | grep -F -q "$_rule"; then
    _info "Regel existiert bereits in AdGuard. Überspringe Hinzufügen."
    return 0
  fi

  # Neue Regel sauber an das bestehende Regelwerk anhängen
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
  
  # Nur die spezifische Zeile dieser Domain/Challenge herausfiltern
  # Andere aktive Challenges (von weiteren SAN-Domains) bleiben erhalten!
  _payload=$(echo "$_current_rules" | grep -F -v "$_rule")

  _adguard_save_rules "$_payload"
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

  _encoded_auth=$(printf "%s" "$ADGUARD_AUTH" | _base64)
  _adguard_headers="Authorization: Basic $_encoded_auth"
}

_adguard_get_rules() {
  _res=$(_with_retry _get "$ADGUARD_URL/control/filtering/status" "" "$_adguard_headers")
  if [ $? -ne 0 ] || [ -z "$_res" ]; then
     _err "Fehler beim Abrufen der Filterregeln von AdGuard."
     return 1
  fi
  # Extrahiere das Array user_rules sauber, falls vorhanden
  echo "$_res" | tr -d '\n' | grep -o '"user_rules":\[[^]*]*\]' | sed 's/"user_rules":\[//;s/\]$//' | sed 's/"//g' | tr ',' '\n'
}

_adguard_save_rules() {
  _rules_content=$1

  _json_rules=""
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    _escaped=$(echo "$line" | sed 's/"/\\"/g')
    if [ -z "$_json_rules" ]; then
      _json_rules="\"$_escaped\""
    else
      _json_rules="$_json_rules,\"$_escaped\""
    fi
  done <<< "$_rules_content"

  _json_payload="{\"user_rules\":[$_json_rules]}"

  _res=$(_post "$_json_payload" "$ADGUARD_URL/control/filtering/set_rules" "" "POST" "application/json" "$_adguard_headers")
  
  if [ $? -eq 0 ]; then
    _info "AdGuard Filterregeln erfolgreich aktualisiert."
    return 0
  else
    _err "Fehler beim Speichern der Regeln in AdGuard Home."
    return 1
  fi
}
