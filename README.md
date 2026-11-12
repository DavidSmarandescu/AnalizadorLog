# log-analyzer

Analizador de logs de seguridad en Python, sin dependencias externas.
Lee logs de SSH (`auth.log`) y de servidor web (formato *combined* de
nginx/Apache) y señala comportamientos de ataque.

## Uso

```bash
python3 -m loganalyzer samples/auth.log samples/access.log
```

Opciones principales:

| Opción | Efecto |
| --- | --- |
| `--json` | Salida en JSON, para integrarla con otras herramientas |
| `--min-severity high` | Oculta los hallazgos por debajo de esa gravedad |
| `--fail-on high` | Sale con código 1 si hay hallazgos de esa gravedad o más (CI, cron) |
| `--year 2025` | Año de los logs syslog, que no lo incluyen |
| `--ssh-threshold`, `--ssh-window` | Ajustan la detección de fuerza bruta SSH |

También lee de la entrada estándar con `-`.

## Reglas

| Regla | Gravedad | Qué detecta |
| --- | --- | --- |
| `ssh_login_after_failures` | crítica | Login correcto desde una IP con muchos fallos previos |
| `ssh_brute_force` | alta | Muchos logins fallidos de una IP en poco tiempo |
| `ssh_user_enumeration` | media | Una IP probando muchos usuarios inexistentes |
| `web_sensitive_file_exposed` | crítica | El servidor respondió 200 a `.env`, `.git/`, copias de seguridad... |
| `web_sensitive_file_probe` | baja | Lo mismo, pero sin éxito |
| `web_attack_payload` | alta | Inyección SQL, XSS, path traversal, inyección de comandos, Log4Shell |
| `web_login_brute_force` | alta | Muchos `POST` a un login respondidos con 401/403 |
| `web_enumeration` | media | Ráfaga de respuestas 404 (fuzzing de directorios) |
| `web_scanner_user_agent` | media | User-Agent de sqlmap, nikto, gobuster, nuclei... |

Los umbrales están en `Config`, en `loganalyzer/detectors.py`.

## Estructura

- `loganalyzer/parsers.py`: convierte cada línea en un `Event`.
- `loganalyzer/detectors.py`: una función por regla; devuelven `Finding`.
- `loganalyzer/report.py`: salida en texto y JSON.
- `samples/generate.py`: regenera los logs de ejemplo (tráfico normal más
  cinco ataques simulados, con IPs de rangos reservados para documentación).

## Tests

```bash
python3 -m unittest discover -s tests
```

## Limitaciones

- Las reglas se basan en firmas y umbrales: un atacante lento o repartido entre
  muchas IPs pasa desapercibido, y una búsqueda legítima con texto parecido a
  SQL puede dar un falso positivo.
- Las horas del syslog clásico se toman tal cual; las de los logs web se
  convierten a UTC. Si el servidor no está en UTC, los periodos de SSH y web
  no son directamente comparables.
