from __future__ import annotations

from stackscan.types import ScanReport, ServiceFinding, Technology

_DB_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    11211: "Memcached",
    5984: "CouchDB",
    9042: "Cassandra",
    7474: "Neo4j",
}

_REMOTE_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
}

_CAMERA_PORTS: dict[int, str] = {
    554: "RTSP",
    8554: "RTSP",
}

_MESSAGE_PORTS: dict[int, str] = {
    25: "SMTP",
    465: "SMTPS",
    587: "Submission",
    110: "POP3",
    995: "POP3S",
    143: "IMAP",
    993: "IMAPS",
    1883: "MQTT",
    5672: "AMQP",
}

_ADMIN_TECHS: dict[str, str] = {
    "phpmyadmin": "phpMyAdmin",
    "adminer": "Adminer",
    "webmin": "Webmin",
    "cpanel": "cPanel",
    "plesk": "Plesk",
    "directadmin": "DirectAdmin",
    "jenkins": "Jenkins",
    "gitlab": "GitLab",
    "gitea": "Gitea",
    "grafana": "Grafana",
    "zabbix": "Zabbix",
    "kibana": "Kibana",
    "kubernetes-dashboard": "Kubernetes Dashboard",
    "rabbitmq": "RabbitMQ Management",
    "solr": "Apache Solr Admin",
    "hadoop": "Hadoop Admin",
    "swagger": "Swagger UI",
    "postman": "Postman",
    "horde": "Horde Webmail",
    "roundcube": "Roundcube Webmail",
    "squirrelmail": "SquirrelMail",
    "zimbra": "Zimbra Web Client",
    "icewarp": "IceWarp WebMail",
    "mdaemon": "MDaemon Webmail",
    "atmail": "Atmail",
    "open-xchange": "Open-Xchange",
    "postfixadmin": "PostfixAdmin",
    "vestacp": "Vesta CP",
    "hestiacp": "Hestia CP",
    "cyberpanel": "CyberPanel",
    "froxlor": "Froxlor",
    "ispconfig": "ISPConfig",
    "ajenti": "Ajenti",
    "cockpit": "Cockpit",
    "portainer": "Portainer",
    "rancher": "Rancher",
    "traefik": "Traefik Dashboard",
    "nomad": "Nomad",
    "consul": "Consul",
    "vault": "Vault",
    "argocd": "Argo CD",
    "octopus deploy": "Octopus Deploy",
    "teamcity": "TeamCity",
    "bamboo": "Bamboo",
    "youtrack": "YouTrack",
    "redmine": "Redmine",
    "confluence": "Confluence",
    "jira": "Jira",
    "bitbucket": "Bitbucket",
    "nagios": "Nagios",
    "icinga": "Icinga",
    "prometheus": "Prometheus",
    "thanos": "Thanos",
    "elasticsearch": "Elasticsearch",
    "logstash": "Logstash",
    "graylog": "Graylog",
    "splunk": "Splunk",
    "nexus": "Sonatype Nexus",
    "artifactory": "JFrog Artifactory",
    "harbor": "Harbor",
    "gogs": "Gogs",
    "sourcegraph": "Sourcegraph",
    "phabricator": "Phabricator",
}

_DB_TECHS: dict[str, str] = {
    "mysql": "MySQL",
    "mariadb": "MariaDB",
    "postgresql": "PostgreSQL",
    "redis": "Redis",
    "mongodb": "MongoDB",
    "elasticsearch": "Elasticsearch",
    "microsoft sql server": "Microsoft SQL Server",
    "sqlite": "SQLite",
    "cassandra": "Cassandra",
    "couchdb": "CouchDB",
    "neo4j": "Neo4j",
}

_SECURITY_TECHS: dict[str, str] = {
    "imperva incapsula": "Imperva Incapsula",
    "sucuri": "Sucuri WAF",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai",
    "fortinet": "Fortinet",
}

_SEVERITY: dict[str, str] = {
    "database": "CRITICAL",
    "admin-panel": "HIGH",
    "remote-access": "HIGH",
    "camera": "HIGH",
    "messaging": "MEDIUM",
    "service": "INFO",
}


def _tech_name(tech: Technology) -> str:
    return tech.name.lower().strip()


def _service_from_tech(tech: Technology) -> ServiceFinding | None:
    name = _tech_name(tech)
    if name in _ADMIN_TECHS:
        return ServiceFinding(
            name=_ADMIN_TECHS[name],
            kind="admin-panel",
            evidence=" ".join(tech.evidence) or f"tech: {tech.name}",
            severity=_SEVERITY["admin-panel"],
        )
    if name in _DB_TECHS:
        return ServiceFinding(
            name=_DB_TECHS[name],
            kind="database",
            evidence=" ".join(tech.evidence) or f"tech: {tech.name}",
            severity=_SEVERITY["database"],
        )
    if name in _SECURITY_TECHS:
        return ServiceFinding(
            name=_SECURITY_TECHS[name],
            kind="service",
            evidence=" ".join(tech.evidence) or f"tech: {tech.name}",
            severity=_SEVERITY["service"],
        )
    for category in tech.categories or ():
        if category in {"database", "service", "infrastructure", "security"}:
            return ServiceFinding(
                name=tech.name,
                kind=category if category != "service" else "service",
                evidence=" ".join(tech.evidence) or f"category: {category}",
                severity=_SEVERITY.get(category, "INFO"),
            )
    return None


def _service_from_port(port: int) -> ServiceFinding | None:
    if port in _DB_PORTS:
        return ServiceFinding(
            name=_DB_PORTS[port],
            kind="database",
            evidence=f"port {port}/tcp",
            severity=_SEVERITY["database"],
        )
    if port in _REMOTE_PORTS:
        return ServiceFinding(
            name=_REMOTE_PORTS[port],
            kind="remote-access",
            evidence=f"port {port}/tcp",
            severity=_SEVERITY["remote-access"],
        )
    if port in _CAMERA_PORTS:
        return ServiceFinding(
            name=_CAMERA_PORTS[port],
            kind="camera",
            evidence=f"port {port}/tcp",
            severity=_SEVERITY["camera"],
        )
    if port in _MESSAGE_PORTS:
        return ServiceFinding(
            name=_MESSAGE_PORTS[port],
            kind="messaging",
            evidence=f"port {port}/tcp",
            severity=_SEVERITY["messaging"],
        )
    return None


_WEB_PORTS: frozenset[int] = frozenset(
    {80, 443, 3000, 2082, 2083, 631, 7547, 8000, 8080, 8081, 8443, 8888, 9000, 9200}
)
_WINDOWS_PORTS: frozenset[int] = frozenset({111, 135, 139, 445, 5985})


def port_category(port: int, service: str | None) -> tuple[str, str]:

    if port in _DB_PORTS:
        return ("database", _SEVERITY["database"])
    if port in _REMOTE_PORTS or port == 2222:
        return ("remote-access", _SEVERITY["remote-access"])
    if port in _CAMERA_PORTS:
        return ("camera", _SEVERITY["camera"])
    if port in _MESSAGE_PORTS:
        return ("mail", _SEVERITY["messaging"])
    if port in _WEB_PORTS:
        return ("web", "INFO")
    if port == 53:
        return ("dns", "INFO")
    if port == 21:
        return ("file-transfer", "MEDIUM")
    if port in _WINDOWS_PORTS:
        return ("windows/rpc", "MEDIUM")
    svc = (service or "").lower()
    if "http" in svc:
        return ("web", "INFO")
    if "ssh" in svc or "telnet" in svc or "vnc" in svc or "rdp" in svc:
        return ("remote-access", "HIGH")
    if "rtsp" in svc:
        return ("camera", "HIGH")
    if any(k in svc for k in ("smtp", "imap", "pop", "mqtt")):
        return ("mail", "MEDIUM")
    if any(k in svc for k in ("mysql", "postgres", "redis", "mongo", "sql")):
        return ("database", "CRITICAL")
    if "ftp" in svc:
        return ("file-transfer", "MEDIUM")
    return ("other", "INFO")


def classify_services(report: ScanReport) -> list[ServiceFinding]:
    seen: set[tuple[str, str]] = set()
    findings: list[ServiceFinding] = []

    for tech in report.all_technologies():
        finding = _service_from_tech(tech)
        if finding is None:
            continue
        key = (finding.name.lower(), finding.kind)
        if key in seen:
            continue
        seen.add(key)
        findings.append(finding)

    scan = report.ports
    if scan is not None:
        for port in scan.ports:
            finding = _service_from_port(port.port)
            if finding is None:
                continue
            key = (finding.name.lower(), finding.kind)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)

    findings.sort(key=lambda f: (_severity_rank(f.severity), f.kind, f.name.lower()))
    return findings


_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_RANK.get(severity.upper(), 99)
