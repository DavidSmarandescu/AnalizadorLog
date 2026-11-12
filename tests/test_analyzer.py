import unittest
from datetime import datetime, timedelta

from loganalyzer.detectors import Config, analyze, densest_window
from loganalyzer.parsers import parse_line, parse_lines

T0 = datetime(2026, 11, 10, 8, 0, 0)


def ssh(offset, msg):
    ts = T0 + timedelta(seconds=offset)
    return f"{ts:%b %d %H:%M:%S} host sshd[42]: {msg}"


def web(offset, ip, path, status, method="GET", ua="Mozilla/5.0"):
    ts = T0 + timedelta(seconds=offset)
    return (f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" '
            f'{status} 512 "-" "{ua}"')


def rules(lines, cfg=None):
    return {(f.rule, f.ip) for f in analyze(parse_lines(lines, 2026), cfg)}


class ParserTests(unittest.TestCase):
    def test_ssh_failed(self):
        e = parse_line(ssh(0, "Failed password for invalid user bob from 1.2.3.4 port 22 ssh2"), 2026)
        self.assertEqual((e.source, e.kind, e.user, e.ip), ("ssh", "failed", "bob", "1.2.3.4"))
        self.assertEqual(e.ts, T0)

    def test_ssh_iso_timestamp_converted_to_utc(self):
        e = parse_line("2026-11-10T10:00:00+02:00 host sshd[1]: "
                       "Accepted publickey for ana from 10.0.0.1 port 22 ssh2", 2026)
        self.assertEqual((e.kind, e.auth_method), ("accepted", "publickey"))
        self.assertEqual(e.ts, T0)

    def test_web_combined(self):
        e = parse_line(web(0, "5.6.7.8", "/a?b=1", 404), 2026)
        self.assertEqual((e.source, e.http_method, e.path, e.status),
                         ("web", "GET", "/a?b=1", 404))

    def test_web_timezone_converted_to_utc(self):
        e = parse_line('1.1.1.1 - - [10/Nov/2026:09:00:00 +0100] "GET / HTTP/1.1" 200 5', 2026)
        self.assertEqual(e.ts, T0)

    def test_irrelevant_and_garbage_lines(self):
        self.assertIsNone(parse_line(ssh(0, "Connection closed by 1.2.3.4 port 22"), 2026))
        self.assertIsNone(parse_line("esto no es un log", 2026))
        self.assertIsNone(parse_line("", 2026))

    def test_malformed_request_line_does_not_crash(self):
        e = parse_line('9.9.9.9 - - [10/Nov/2026:08:00:00 +0000] "\\x16\\x03\\x01" 400 0', 2026)
        self.assertEqual(e.status, 400)


class WindowTests(unittest.TestCase):
    def test_densest_window(self):
        times = [T0 + timedelta(seconds=s) for s in (0, 100, 101, 102, 500)]
        self.assertEqual(densest_window(times, 10), (3, 1, 3))

    def test_empty(self):
        self.assertEqual(densest_window([], 10)[0], 0)


class SshDetectorTests(unittest.TestCase):
    def test_brute_force(self):
        lines = [ssh(i, "Failed password for root from 1.2.3.4 port 22 ssh2") for i in range(6)]
        self.assertIn(("ssh_brute_force", "1.2.3.4"), rules(lines))

    def test_slow_failures_are_not_brute_force(self):
        lines = [ssh(i * 3600, "Failed password for root from 1.2.3.4 port 22 ssh2")
                 for i in range(6)]
        self.assertNotIn(("ssh_brute_force", "1.2.3.4"), rules(lines))

    def test_below_threshold(self):
        lines = [ssh(i, "Failed password for root from 1.2.3.4 port 22 ssh2") for i in range(4)]
        self.assertEqual(rules(lines), set())

    def test_login_after_failures_is_critical(self):
        lines = [ssh(i, "Failed password for root from 1.2.3.4 port 22 ssh2") for i in range(8)]
        lines.append(ssh(9, "Accepted password for root from 1.2.3.4 port 22 ssh2"))
        findings = analyze(parse_lines(lines, 2026))
        self.assertEqual(findings[0].rule, "ssh_login_after_failures")
        self.assertEqual(findings[0].severity, "critical")

    def test_typo_then_login_is_fine(self):
        lines = [ssh(0, "Failed password for ana from 10.0.0.1 port 22 ssh2"),
                 ssh(5, "Accepted password for ana from 10.0.0.1 port 22 ssh2")]
        self.assertEqual(rules(lines), set())

    def test_user_enumeration(self):
        lines = [ssh(i, f"Invalid user u{i} from 1.2.3.4 port 22") for i in range(5)]
        self.assertIn(("ssh_user_enumeration", "1.2.3.4"), rules(lines))

    def test_threshold_is_configurable(self):
        lines = [ssh(i, "Failed password for root from 1.2.3.4 port 22 ssh2") for i in range(3)]
        self.assertIn(("ssh_brute_force", "1.2.3.4"),
                      rules(lines, Config(ssh_fail_threshold=3)))


class WebDetectorTests(unittest.TestCase):
    def test_payloads(self):
        cases = {
            "/i?id=1%27%20OR%20%271%27=%271": "inyección SQL",
            "/i?id=1+UNION+SELECT+a,b+FROM+users": "inyección SQL",
            "/s?q=%3Cscript%3Ealert(1)%3C/script%3E": "XSS",
            "/d?f=../../etc/passwd": "path traversal",
            "/d?f=%252e%252e%252fetc%252fpasswd": "path traversal",
            "/p?h=1.1.1.1;cat%20/etc/hosts": "inyección de comandos",
        }
        for path, category in cases.items():
            with self.subTest(path=path):
                findings = analyze(parse_lines([web(0, "6.6.6.6", path, 200)], 2026))
                self.assertIn(f"Intento de {category}", [f.title for f in findings])

    def test_log4shell_in_user_agent(self):
        findings = analyze(parse_lines(
            [web(0, "6.6.6.6", "/", 200, ua="${jndi:ldap://x/a}")], 2026))
        self.assertEqual(findings[0].title, "Intento de Log4Shell")

    def test_scanner_user_agent(self):
        self.assertIn(("web_scanner_user_agent", "6.6.6.6"),
                      rules([web(0, "6.6.6.6", "/", 200, ua="sqlmap/1.8")]))

    def test_enumeration(self):
        lines = [web(i, "6.6.6.6", f"/x{i}", 404) for i in range(25)]
        self.assertIn(("web_enumeration", "6.6.6.6"), rules(lines))

    def test_sensitive_file_probe_vs_exposed(self):
        probe = analyze(parse_lines([web(0, "6.6.6.6", "/.env", 404)], 2026))
        self.assertEqual((probe[0].rule, probe[0].severity),
                         ("web_sensitive_file_probe", "low"))
        exposed = analyze(parse_lines([web(0, "6.6.6.6", "/.env", 200)], 2026))
        self.assertEqual((exposed[0].rule, exposed[0].severity),
                         ("web_sensitive_file_exposed", "critical"))

    def test_login_brute_force(self):
        lines = [web(i, "6.6.6.6", "/login", 401, method="POST") for i in range(12)]
        self.assertIn(("web_login_brute_force", "6.6.6.6"), rules(lines))

    def test_normal_traffic_has_no_findings(self):
        lines = [web(i * 20, f"192.168.1.{i % 9}", p, 200)
                 for i, p in enumerate(["/", "/blog/post-1", "/api/items?page=2",
                                        "/static/app.js", "/buscar?q=zapatos+rojos",
                                        "/docs/select-union-guide"] * 10)]
        lines.append(web(5, "192.168.1.3", "/no-existe", 404))
        lines.append(web(6, "192.168.1.3", "/login", 401, method="POST"))
        self.assertEqual(rules(lines), set())

    def test_findings_sorted_by_severity(self):
        lines = [web(0, "6.6.6.6", "/.git/config", 404),
                 web(1, "7.7.7.7", "/backup.sql", 200),
                 web(2, "8.8.8.8", "/", 200, ua="nikto")]
        severities = [f.severity for f in analyze(parse_lines(lines, 2026))]
        self.assertEqual(severities, ["critical", "medium", "low"])


if __name__ == "__main__":
    unittest.main()
