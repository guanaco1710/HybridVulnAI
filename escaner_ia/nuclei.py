"""Escaneo de vulnerabilidades con nuclei sobre los puertos abiertos que encontró nmap.

Los objetivos nunca se aceptan del usuario: salen solo de los hosts descubiertos por nmap y se
vuelven a validar (solo red local). Perfiles cerrados, sin opciones libres.
"""

import ipaddress
import json
import os
import shutil
import subprocess
import tempfile

from .objetivos import ObjetivoNoPermitido, validar_objetivo
from .parser import PATRON_CVE

# Plantillas que pueden tumbar un servicio o forzar credenciales: nunca se ejecutan.
TAGS_EXCLUIDOS = "dos,fuzz,intrusive,bruteforce,brute-force"
MAX_DESCRIPCION = 500
MAX_REFERENCIAS = 3

PERFILES = {
    "rapido": ["-severity", "high,critical"],
    "estandar": ["-severity", "medium,high,critical"],
    "completo": ["-severity", "info,low,medium,high,critical"],
}

# Opciones fijas de seguridad y de carga para la red local:
#  -ni   sin servidor OAST externo (no se contacta con terceros)
#  -duc  sin comprobar/descargar actualizaciones durante el escaneo (se actualiza a mano: nuclei -ut)
#  -dut  solo plantillas firmadas (las oficiales); las modificadas o ajenas no se ejecutan
#  -or   sin peticiones/respuestas en bruto en la salida
OPCIONES_FIJAS = ["-jsonl", "-silent", "-no-color", "-ni", "-duc", "-dut", "-or", "-ot",
                  "-etags", TAGS_EXCLUIDOS, "-rate-limit", "50", "-concurrency", "10",
                  "-bulk-size", "10", "-timeout", "10", "-retries", "1"]

SEVERIDADES = {"critical": "critica", "high": "alta", "medium": "media", "low": "baja", "info": "info"}


class ErrorNuclei(RuntimeError):
    def __init__(self, mensaje: str, parciales: dict[str, list[dict]] | None = None):
        super().__init__(mensaje)
        self.parciales = parciales  # hallazgos ya emitidos si el escaneo quedó a medias


def binario() -> str:
    ruta = shutil.which("nuclei")
    if ruta is None:
        raise ErrorNuclei("nuclei no está instalado o no está en el PATH")
    return ruta


def objetivos_de_hosts(hosts: list[dict]) -> list[str]:
    """`ip:puerto` de los puertos abiertos descubiertos por nmap, revalidados (solo red local)."""
    objetivos = []
    for host in hosts:
        if not host["puertos"]:
            continue
        try:
            ip = validar_objetivo(host["ip"])
        except ObjetivoNoPermitido:
            continue  # defensa en profundidad: nunca se pasa a nuclei algo fuera de la red local
        if "/" in ip:
            continue  # solo IPs sueltas, nunca rangos
        base = f"[{ip}]" if ipaddress.ip_address(ip).version == 6 else ip
        objetivos += [f"{base}:{int(p['puerto'])}" for p in host["puertos"]]
    return objetivos


def construir_comando(ruta_objetivos: str, perfil: str) -> list[str]:
    if perfil not in PERFILES:
        raise ErrorNuclei(f"perfil de nuclei desconocido: {perfil}")
    return [binario(), "-list", ruta_objetivos, *PERFILES[perfil], *OPCIONES_FIJAS]


def _cves(clasificacion: dict) -> list[str]:
    ids = clasificacion.get("cve-id") or []
    if isinstance(ids, str):  # según la versión, nuclei da una cadena o una lista
        ids = [ids]
    encontrados = (PATRON_CVE.search(str(i)) for i in ids)
    return sorted({m.group(0).upper() for m in encontrados if m})


def parsear_jsonl(texto: str, ips_permitidas: set[str]) -> dict[str, list[dict]]:
    """{ip: [hallazgos]}. Ignora líneas que no son JSON y resultados de IPs que no se escanearon.

    Nuclei emite una línea por cada "matcher" de una plantilla (p. ej. una por cada cabecera de
    seguridad que falta): se agrupan en un único hallazgo con la lista de `detalles`.
    """
    resultado: dict[str, list[dict]] = {}
    vistos: dict[tuple, dict] = {}
    for linea in texto.splitlines():
        try:
            r = json.loads(linea)
        except json.JSONDecodeError:
            continue
        if not isinstance(r, dict):
            continue
        info = r.get("info") or {}
        ip = str(r.get("ip") or str(r.get("host", "")).rsplit(":", 1)[0].strip("[]"))
        if ip not in ips_permitidas:
            continue
        clasificacion = info.get("classification") or {}
        try:
            puerto = int(r.get("port"))
        except (TypeError, ValueError):
            puerto = 0
        referencias = info.get("reference")
        referencias = referencias[:MAX_REFERENCIAS] if isinstance(referencias, list) else []
        id_plantilla, coincidencia = str(r.get("template-id", "")), str(r.get("matched-at", ""))
        detalle = str(r.get("matcher-name") or "")
        previo = vistos.get((ip, id_plantilla, coincidencia))
        if previo is not None:
            if detalle and detalle not in previo["detalles"]:
                previo["detalles"].append(detalle)
            continue
        hallazgo = {
            "id": id_plantilla,
            "nombre": str(info.get("name", r.get("template-id", ""))),
            "severidad": SEVERIDADES.get(str(info.get("severity", "")).lower(), "info"),
            "puerto": puerto,
            "coincidencia": coincidencia,
            "detalles": [detalle] if detalle else [],
            "tipo": str(r.get("type", "")),
            "descripcion": str(info.get("description", ""))[:MAX_DESCRIPCION],
            "cves": _cves(clasificacion),
            "cvss": clasificacion.get("cvss-score"),
            "referencias": [str(x) for x in referencias],
            "extraidos": [str(x) for x in (r.get("extracted-results") or [])[:5]],
        }
        vistos[(ip, id_plantilla, coincidencia)] = hallazgo
        resultado.setdefault(ip, []).append(hallazgo)
    return resultado


def escanear(hosts: list[dict], perfil: str = "estandar", timeout: int = 3600) -> dict[str, list[dict]]:
    """Ejecuta nuclei contra los puertos abiertos de `hosts`. Devuelve {ip: hallazgos}."""
    objetivos = objetivos_de_hosts(hosts)
    if not objetivos:
        return {}
    ips = {o.rsplit(":", 1)[0].strip("[]") for o in objetivos}
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(objetivos) + "\n")
    try:
        comando = construir_comando(f.name, perfil)
        try:
            r = subprocess.run(comando, capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as e:
            # Nuclei emite cada hallazgo según lo encuentra: lo conseguido hasta el límite no se pierde.
            salida = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
            raise ErrorNuclei(f"nuclei superó el tiempo límite de {timeout} s: resultados incompletos "
                              "(sube --timeout-nuclei o usa un perfil más rápido)",
                              parsear_jsonl(salida, ips)) from None
    finally:
        os.unlink(f.name)
    if r.returncode != 0:
        raise ErrorNuclei(f"nuclei terminó con código {r.returncode}: {r.stderr.strip()[-500:]}. "
                          "¿Plantillas sin descargar? Ejecuta: nuclei -ut")
    return parsear_jsonl(r.stdout, ips)
