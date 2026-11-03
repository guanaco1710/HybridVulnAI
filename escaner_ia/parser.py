"""Convierte el XML de nmap en datos normalizados (diccionarios simples)."""

import re
import xml.etree.ElementTree as ET

PATRON_CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
# Líneas de vulners: "CVE-2023-38408   9.8   https://vulners.com/..."
PATRON_VULNERS = re.compile(r"\b(CVE-\d{4}-\d{4,})\s+(\d+(?:\.\d+)?)", re.IGNORECASE)


def _cves_de_script(salida: str) -> list[dict]:
    """Extrae CVE (y su CVSS si aparece) del texto de un script NSE."""
    encontrados: dict[str, float | None] = {}
    for cve, cvss in PATRON_VULNERS.findall(salida):
        encontrados[cve.upper()] = float(cvss)
    for cve in PATRON_CVE.findall(salida):
        encontrados.setdefault(cve.upper(), None)
    return [{"id": c, "cvss": s} for c, s in encontrados.items()]


def _scripts(elemento) -> list[dict]:
    return [
        {"id": s.get("id", ""), "salida": s.get("output", "")}
        for s in elemento.findall("script")
    ]


def parsear_xml(xml_texto: str) -> dict:
    raiz = ET.fromstring(xml_texto)
    hosts = []

    for h in raiz.findall("host"):
        estado = h.find("status")
        if estado is not None and estado.get("state") != "up":
            continue

        direcciones = {a.get("addrtype"): a.get("addr") for a in h.findall("address")}
        ip = direcciones.get("ipv4") or direcciones.get("ipv6") or "desconocida"
        nombres = [n.get("name") for n in h.findall("hostnames/hostname") if n.get("name")]
        so = [
            {"nombre": m.get("name"), "precision": int(m.get("accuracy", 0))}
            for m in h.findall("os/osmatch")[:3]
        ]

        puertos = []
        for p in h.findall("ports/port"):
            estado_p = p.find("state")
            if estado_p is None or estado_p.get("state") != "open":
                continue
            serv = p.find("service")
            serv = serv if serv is not None else ET.Element("service")
            scripts = _scripts(p)
            cves = []
            for s in scripts:
                cves.extend(_cves_de_script(s["salida"]))
            puertos.append({
                "puerto": int(p.get("portid")),
                "protocolo": p.get("protocol"),
                "servicio": serv.get("name", ""),
                "producto": serv.get("product", ""),
                "version": serv.get("version", ""),
                "extra": serv.get("extrainfo", ""),
                "cpe": [c.text for c in serv.findall("cpe") if c.text],
                "scripts": scripts,
                "cves_nmap": cves,
            })

        hosts.append({
            "ip": ip,
            "mac": direcciones.get("mac", ""),
            "nombres": nombres,
            "so": so,
            "puertos": puertos,
            "scripts_host": _scripts(h.find("hostscript")) if h.find("hostscript") is not None else [],
        })

    return {
        "comando": raiz.get("args", ""),
        "inicio": raiz.get("startstr", ""),
        "version_nmap": raiz.get("version", ""),
        "hosts": hosts,
    }
