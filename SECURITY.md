# Sicherheit

## Sicherheitslücken melden

Bitte melden Sie Sicherheitslücken **nicht** als öffentliches Issue, sondern vertraulich über [GitHub Security Advisories](https://github.com/Xaner98/Ordivus/security/advisories/new). Beschreiben Sie betroffene Version, Konfiguration und einen Weg, das Problem nachzuvollziehen. Sie erhalten eine Rückmeldung, sobald die Meldung gesichtet ist.

## Unterstützte Versionen

Ordivus ist Alpha-Software (`0.x`). Sicherheitskorrekturen erscheinen nur für die jeweils neueste Version.

## Sicherheitsmodell in Kürze

Ordivus arbeitet mit administrativen Zugangsdaten. Diese Grenzen setzt es selbst durch:

- `plan` und `drift` verändern weder Zielsysteme noch Secret Stores. Zusätzlich empfohlen: eine Identität, die am Zielsystem nur lesen darf.
- Nicht deklarierte Objekte werden nur gemeldet. Löschen setzt einen positiv abgegrenzten Scope, vollständige Discovery und die Operator Policy `allowDelete: true` voraus.
- Die Konfiguration kann keine Rechte über die Operator Policy hinaus verschaffen: hochprivilegierte Rollen, Grants und ACL-Regeln (z. B. Superuser-Mitgliedschaften, `GRANT OPTION`, Admin-Kommandos) werden blockiert, solange die Operator Policy nicht `allowPrivilegedGrants: true` setzt. Systemobjekte, der eigene Admin-Login und dessen Rollen sind immer geschützt.
- Unbekannte Zustände (fehlende Rechte, Timeouts, Teilinventare) führen nie zu Löschen, Anlegen oder Passwortänderungen.
- Secrets erscheinen nicht in Reports, Logs oder Fehlermeldungen; HTTP-Clients folgen keinen Redirects und senden Tokens nur an den konfigurierten Endpunkt (bzw. über einen per `HTTP(S)_PROXY` gesetzten Proxy; das meldet Ordivus als Warnung, siehe [docs/konfiguration.md](docs/konfiguration.md#proxy)).

Außerhalb von Ordivus liegt die Verantwortung für:

- **Review der Konfiguration.** Wer die Konfiguration ändern darf, bestimmt, welche Objekte im erlaubten Rahmen angelegt werden – inklusive der Endpunkte, an die Zugangsdaten gesendet werden. Nutzen Sie TLS mit CA-Prüfung (`verify-full`) und `requireTls: true` in der Operator Policy.
- **Schutz der Operator Policy und der Zugangsdaten.** Beides gehört in getrennt verwaltete, schreibgeschützte Quellen.
- **Wer Jobs starten darf.** In Kubernetes ist jeder, der im Namespace der Apply-Vorlage Jobs oder Pods erzeugen kann, Teil der Vertrauensgrenze. Siehe [docs/kubernetes.md](docs/kubernetes.md) zu getrennten Namespaces und der optionalen Admission Policy.
- **Adapter-Plugins.** Plugins sind ausführbarer Python-Code und keine Sandbox. Installieren Sie nur vertrauenswürdige Pakete.
