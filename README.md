# acme.sh DNS API Addon für AdGuard Home

Dieses Addon für [acme.sh](https://github.com) ermöglicht die automatisierte Zertifikatsausstellung via **DNS-01 Challenge** über eine **AdGuard Home** Instanz. 

Es eignet sich perfekt für Umgebungen im lokalen Netzwerk (LAN), in denen Wildcard- oder Multi-Domain-Zertifikate (SAN) über eine interne Zertifizierungsstelle (z. B. Step-CA, Smallstep, Active Directory Certificate Services) ausgestellt werden sollen, falls eine ACME Challenge http-01 über Ports 80 nicht funktioniert.

## 🚀 Funktionsweise

Da AdGuard Home über keine native API für isolierte TXT-Records verfügt, nutzt dieses Skript die offizielle Filter-API (`/control/filtering/set_rules`). 
1. Es liest bestehende benutzerdefinierte Filterregeln via JSON aus.
2. Es fügt die ACME-Challenge im AdGuard-DNS-Rewrite-Format hinzu `||_acme-challenge.domain.internal^$dnstype=TXT,dnsrewrite=NOERROR;TXT;<token>`).
4. Bestehende manuelle Filterregeln werden **nicht** überschrieben oder gelöscht.
5. Es erzwingt einen sofortigen Cache-Refresh in AdGuard Home, damit auch Multi-Domain-Zertifikate (SAN) ohne DNS-Verzögerung validiert werden.
6. Nach erfolgreichem Abschluss werden die Challenges rückstandslos entfernt.

## 🛠 Voraussetzungen

- Ein installierter **acme.sh** Client
- **Python 3** auf dem ausführenden System (wird für die sichere, native JSON-Verarbeitung genutzt)
- **curl**
- Ein Admin-Konto für die AdGuard Home Weboberfläche

## 📦 Installation des Addons

Kopiere das Skript in das `dnsapi`-Verzeichnis deiner `acme.sh`-Installation (standardmäßig unter `~/.acme.sh/dnsapi/`).

```bash
# Pfad ggf. an deine acme.sh Umgebung anpassen
sudo -u acme wget -O /var/lib/acme/.acme.sh/dnsapi/dns_adguard.sh https://github.com/DragonDope/Adguard_acme_addon/blob/master/dns_adguard.sh
```
```bash
# Skript ausführbar machen
sudo chmod +x /var/lib/acme/.acme.sh/dnsapi/dns_adguard.sh
```

## 📖 Nutzung & Zertifikats-Lifecycle

Der Prozess unterteilt sich in zwei Schritte: Das **Beantragen** des Zertifikats und die anschließende **Installation** in den Webserver (z. B. Apache2).

### Schritt 1: Zertifikat beantragen (--issue)

Beim ersten Aufruf müssen die Zugangsdaten zu AdGuard Home als Umgebungsvariablen übergeben werden. `acme.sh` speichert diese nach dem ersten erfolgreichen Durchlauf automatisch in der internen `account.conf` ab. Bei zukünftigen automatischen Verlängerungen (Cronjob/Renew) müssen die Variablen **nicht** erneut angegeben werden.

```bash
sudo -u acme -H bash -c " \
  export ADGUARD_AUTH='admin:meinSicheresPasswort' \
  export ADGUARD_URL='https://yxz.io'; \
  /var/lib/acme/.acme.sh/acme.sh --issue --dns dns_adguard \
    -d 'url.internal' \
    -d 'urlmore.internal' \
    --server 'https://ca.internal' \
    --dnssleep 120"
```

### Schritt 2: Zertifikat im Webserver installieren (--install-cert)

Nachdem das Zertifikat erfolgreich ausgestellt wurde, muss es an den Zielort kopiert und der Webserver neu geladen werden. Nutze dafür **auf keinen Fall** einen manuellen `cp`-Befehl, da `acme.sh` diesen Installationsbefehl im Hintergrund speichert und bei jedem automatischen Renew exakt so wiederholt.

Hier am Beispiel für einen **Apache2** Webserver:

```bash
sudo -u acme -H /var/lib/acme/.acme.sh/acme.sh --install-cert -d testskript.internal \
  --cert-file /etc/apache2/ssl/url.cert.pem \
  --key-file /etc/apache2/ssl/url.key.pem \
  --fullchain-file /etc/apache2/ssl/url.fullchain.pem \
  --reloadcmd "sudo /usr/bin/systemctl reload apache2"
```

*Hinweis zum `--reloadcmd`:* Stelle sicher, dass der Benutzer `acme` in der `/etc/sudoers` die Rechte besitzt, den Befehl `sudo /usr/bin/systemctl reload apache2` passwortlos auszuführen, damit automatische Updates im Cronjob nicht hängen bleiben.

## 🔒 Sicherheitshinweise

- Das Skript nutzt intern Python zur JSON-Modifikation, um sicherzustellen, dass unter **keinen Umständen** bestehende DNS-Filterregeln in AdGuard Home beschädigt oder gelöscht werden.
- Sollte deine interne CA ein selbstsigniertes Stammzertifikat nutzen, stelle sicher, dass dieses im Zertifikatsspeicher des Betriebssystems hinterlegt ist (`update-ca-certificates`), da `acme.sh` standardmäßig jede HTTPS-Verbindung strikt validiert. Alternativ kann temporär der Parameter `--insecure` an `acme.sh` beim `--issue`-Befehl angehängt werden.

## 📄 Lizenz

Dieses Projekt ist unter der MIT-Lizenz lizenziert. Siehe die [LICENSE](LICENSE) Datei für Details.
