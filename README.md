# Shemhamphorash - HackMyVM (Medium)
 
![Shemhamphorash.png](Shemhamphorash.png)

## Übersicht

*   **VM:** Shemhamphorash
*   **Plattform:** [https://hackmyvm.eu/machines/machine.php?vm=Shemhamphorash](https://hackmyvm.eu/machines/machine.php?vm=Shemhamphorash)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 27. Mai 2025
*   **Original-Writeup:** [https://alientec1908.github.io/Shemhamphorash_HackMyVM_Medium/](https://alientec1908.github.io/Shemhamphorash_HackMyVM_Medium/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Dieses Writeup dokumentiert den Lösungsweg für die virtuelle Maschine "Shemhamphorash" von HackMyVM. Das Ziel war es, sowohl die User- als auch die Root-Flag zu erlangen. Der Weg zum initialen Zugriff führte über die Enumeration von Webdiensten, die Identifizierung einer WordPress-Instanz und die Ausnutzung einer Stored XSS-Schwachstelle in einem Plugin, um schließlich durch geleakte Log-Informationen SSH-Zugangsdaten zu erhalten. Die Privilegienerweiterung zu Root gelang durch Ausnutzung einer unsicheren Sudo-Konfiguration mittels LD_PRELOAD.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `nikto`
*   `curl`
*   `dirb`
*   `wpscan`
*   `hydra` (versucht, aber nicht primärer Vektor)
*   `nc` (netcat)
*   `ssh`
*   `vi`/`nano`
*   `jq`
*   `python3 http.server`
*   `gcc` (zum Kompilieren des LD_PRELOAD Exploits)
*   Standard Linux-Befehle (`ls`, `cat`, `echo`, `chmod`, `sudo`, `su`, `mysql`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Shemhamphorash" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Findung mittels `arp-scan` (192.168.2.202, später auch .204 als Bot/Ziel identifiziert).
    *   Umfassende Portscans mit `nmap` identifizierten offene Ports: 80 (Apache), 8080 (Nginx), 22222 (SSH).
    *   Hinzufügen von `shemhamphorash.hmv` und später `shemhamphorash.local` zur `/etc/hosts`.

2.  **Web Enumeration & Schwachstellensuche:**
    *   `gobuster` und `dirb` auf Port 80 und 8080 zeigten diverse PHP-Dateien und Verzeichnisse (`/manual`, `/javascript` auf Port 80; `admin.php`, `info.php`, `phpinfo.php`, `xmlrpc.php` auf Port 8080).
    *   `nikto` auf Port 80 fand fehlende Security-Header, ein veraltetes Apache und Directory Indexing in `/manual/images`.
    *   `nikto` auf Port 8080/admin.php deutete auf alte phpMyAdmin-Installationen und eine XSS-Schwachstelle in OpenAutoClassifieds (CVE-2003-1145) hin.
    *   Identifizierung einer WordPress-Instanz unter `shemhamphorash.local/sitecore/`.
    *   `wpscan` enumerierte Benutzer (`trumpeter`, `blessed`) und fand eine kritische Stored XSS-Schwachstelle im Plugin "easy-cookies-policy" (CVE-2021-24405) sowie veraltete Themes/Plugins.

3.  **Initial Access (Geleakte Credentials via Log-Analyse):**
    *   Ein Brute-Force-Versuch mit `hydra` auf den WordPress XML-RPC für den Benutzer `blessed` war erfolgreich und lieferte das Passwort `yourmom`.
    *   Login als `blessed` in WordPress.
    *   Ausnutzung der Stored XSS in "easy-cookies-policy" (CVE-2021-24405), um JavaScript-Payloads (Cookie-Stealer, BeEF-Hook, interaktiver XSS-Handler) auszuführen, die von einem Bot (IP 192.168.2.203, später .204) ausgeführt wurden.
    *   Während der XSS-Ausnutzung wurden über den Listener Log-Einträge von einem Skript `/.superpass/admin.php` sichtbar, die Klartext-Zugangsdaten für Benutzer `caiaphas` und `gamaliel` (Passwort: `kx5h48jo9up97jw`) enthielten.
    *   Erfolgreicher SSH-Login als `caiaphas` auf Port 22222 mit den geleakten Zugangsdaten.

4.  **Post-Exploitation / User-Flag:**
    *   Als `caiaphas` wurde die User-Flag in `/home/caiaphas/user.txt` gefunden.
    *   `sudo -l` für `caiaphas` zeigte, dass das Skript `/root/.script/viewlog.sh` mit `SETENV:`-Option ausgeführt werden darf.
    *   Die Datei `wp-config.php` wurde im Web-Verzeichnis gefunden und enthielt Datenbank-Zugangsdaten (`enochian:f4OqtZb7`).
    *   Zugriff auf die MariaDB-Datenbank, Erstellung eines neuen WordPress-Users `dbmaster` und Vergabe von Admin-Rechten (obwohl dieser Weg nicht final zur Root-Shell führte, war er ein valider Schritt).
    *   Einrichtung einer RCE-Webshell über WordPress (nach Erlangung von Admin-Rechten durch den Datenbank-User), um als `www-data` Befehle auszuführen und eine Reverse Shell zu erhalten.

5.  **Privilege Escalation (von `caiaphas` zu root):**
    *   Die Sudo-Regel für `caiaphas` (`(ALL) SETENV: /root/.script/viewlog.sh`) wurde ausgenutzt.
    *   Ein C-Programm (`preload_shell.c`) wurde erstellt, das eine Root-Shell via `setuid(0)` und `system("/bin/bash -p")` startet.
    *   Dieses wurde zu einer Shared Library (`preload_shell.so`) kompiliert.
    *   Die Bibliothek wurde nach `/tmp` auf der Zielmaschine übertragen/kopiert.
    *   Das Skript wurde mit `sudo LD_PRELOAD=/tmp/preload_shell.so /root/.script/viewlog.sh` ausgeführt, was zur Ausführung der `init()`-Funktion in der Shared Library mit Root-Rechten und somit zu einer Root-Shell führte.

## Wichtige Schwachstellen und Konzepte

*   **Stored Cross-Site Scripting (XSS) (CVE-2021-24405):** Das Plugin "easy-cookies-policy" war anfällig für Stored XSS, was die Injektion von beliebigem JavaScript-Code ermöglichte. Dies wurde genutzt, um mit einem "Admin-Bot" zu interagieren.
*   **Klartext-Credentials in Logs/GET-Parametern:** Die Anwendung `/.superpass/admin.php` übergab Zugangsdaten per GET-Parameter, die in Logs landeten und über das Skript `viewlog.sh` einsehbar waren. Dies führte zum direkten SSH-Zugriff als `caiaphas`.
*   **Unsichere Sudo-Konfiguration (SETENV mit LD_PRELOAD):** Der Benutzer `caiaphas` durfte ein Skript als Root ausführen und dabei Umgebungsvariablen setzen. Dies erlaubte die Ausnutzung von `LD_PRELOAD` zur Privilegienerweiterung zu Root.
*   **WordPress Enumeration:** Einsatz von `wpscan` zur Identifizierung von Benutzern, Plugins, Themes und deren Schwachstellen.
*   **Datenbank-Zugriffsdaten in `wp-config.php`:** Auslesen der <code>wp-config.php</code> ermöglichte den Zugriff auf die WordPress-Datenbank.
*   **PATH-Hijacking (versucht):** Ein Versuch, durch Manipulation der PATH-Variable und Ausführung des Sudo-Skripts eigene Befehle auszuführen.
*   **LD_PRELOAD-Exploitation:** Eine kompilierte Shared Library wurde verwendet, um beim Start eines mit Sudo ausgeführten Programms eigenen Code mit Root-Rechten auszuführen.

## Flags

*   **User Flag (`/home/caiaphas/user.txt`):** `c567f59d28c51c1c4f006f67b889b986`
*   **Root Flag (`/root/root.txt`):** `2f57a1a472eff7b635ab7ccdf39afa66`

## Tags

`HackMyVM`, `Shemhamphorash`, `Medium`, `Linux`, `Web`, `WordPress`, `XSS`, `CVE-2021-24405`, `Credential Leakage`, `Sudo Exploitation`, `LD_PRELOAD`, `Privilege Escalation`
