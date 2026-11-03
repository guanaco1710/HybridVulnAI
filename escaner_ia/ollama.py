"""Análisis de los resultados con un modelo local servido por Ollama."""

import json
import urllib.error
import urllib.request

from .parser import PATRON_CVE

URL_POR_DEFECTO = "http://localhost:11434"
MODELO_POR_DEFECTO = "llama3.1:8b"
MAX_SALIDA_SCRIPT = 1500  # recorta salidas NSE largas para no saturar el contexto

# Ollama acepta un JSON Schema en "format" y obliga al modelo a respetarlo.
ESQUEMA = {
    "type": "object",
    "properties": {
        "resumen": {"type": "string"},
        "hallazgos": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "puerto": {"type": "integer"},
                    "tipo": {"type": "string",
                             "enum": ["cve", "vulnerabilidad", "mala_configuracion"]},
                    "titulo": {"type": "string"},
                    "severidad": {"type": "string",
                                  "enum": ["critica", "alta", "media", "baja", "info"]},
                    "cves": {"type": "array", "items": {"type": "string"}},
                    "descripcion": {"type": "string"},
                    "recomendacion": {"type": "string"},
                },
                "required": ["puerto", "tipo", "titulo", "severidad", "cves",
                             "descripcion", "recomendacion"],
            },
        },
    },
    "required": ["resumen", "hallazgos"],
}

PROMPT_SISTEMA = """Eres un auditor de seguridad de redes. Analizas resultados de nmap \
de UN host y devuelves hallazgos en español.
Reglas:
- Basa cada hallazgo en los datos recibidos (servicio, producto, versión, salida de scripts).
- Cita un CVE solo si estás seguro de que afecta a ese producto y versión. Si dudas, \
no lo cites: describe el riesgo sin ID. Nunca inventes IDs.
- Incluye malas configuraciones (servicios en claro como telnet/ftp/http sin TLS, \
SMB/RDP/bases de datos expuestos, versiones obsoletas, métodos HTTP peligrosos, etc.).
- Cada hallazgo lleva una recomendación concreta y accionable.
- Usa puerto 0 para hallazgos que afectan al host completo.
- Si no hay nada relevante, devuelve una lista vacía."""


class ErrorOllama(RuntimeError):
    pass


def _host_compacto(host: dict) -> dict:
    """Versión reducida del host para el prompt."""
    def recortar(scripts):
        return [{"id": s["id"], "salida": s["salida"][:MAX_SALIDA_SCRIPT]} for s in scripts]

    return {
        "ip": host["ip"],
        "so": host["so"],
        "scripts_host": recortar(host["scripts_host"]),
        "puertos": [
            {k: p[k] for k in ("puerto", "protocolo", "servicio", "producto", "version", "extra", "cpe")}
            | {"scripts": recortar(p["scripts"])}
            for p in host["puertos"]
        ],
    }


def _peticion(url: str, cuerpo: dict, timeout: int) -> dict:
    datos = json.dumps(cuerpo).encode()
    req = urllib.request.Request(url, data=datos, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detalle = e.read().decode(errors="replace")
        raise ErrorOllama(f"Ollama respondió {e.code}: {detalle}") from None
    except (urllib.error.URLError, TimeoutError) as e:
        raise ErrorOllama(f"no se pudo conectar con Ollama en {url} ({e}). "
                          "¿Está 'ollama serve' en marcha?") from None


def analizar_host(host: dict, modelo: str = MODELO_POR_DEFECTO,
                  url_base: str = URL_POR_DEFECTO, timeout: int = 600) -> dict:
    cuerpo = {
        "model": modelo,
        "stream": False,
        "format": ESQUEMA,
        "options": {"temperature": 0.1},
        "messages": [
            {"role": "system", "content": PROMPT_SISTEMA},
            {"role": "user", "content": "Resultados de nmap:\n"
                                        + json.dumps(_host_compacto(host), ensure_ascii=False, indent=1)},
        ],
    }
    respuesta = _peticion(url_base.rstrip("/") + "/api/chat", cuerpo, timeout)
    contenido = respuesta.get("message", {}).get("content", "")
    try:
        analisis = json.loads(contenido)
    except json.JSONDecodeError:
        raise ErrorOllama(f"el modelo no devolvió JSON válido: {contenido[:300]!r}") from None
    return clasificar_origen(analisis, host)


def clasificar_origen(analisis: dict, host: dict) -> dict:
    """Marca cada CVE como detectado por nmap o como inferencia de la IA."""
    cves_nmap = {c["id"] for p in host["puertos"] for c in p["cves_nmap"]}
    for h in analisis.get("hallazgos", []):
        cves = []
        for cve in h.get("cves", []):
            m = PATRON_CVE.search(str(cve))
            if not m:
                continue  # descarta IDs con formato inválido
            cid = m.group(0).upper()
            cves.append({"id": cid, "origen": "nmap" if cid in cves_nmap else "ia"})
        h["cves"] = cves
    return analisis


def comprobar_modelo(modelo: str, url_base: str = URL_POR_DEFECTO) -> None:
    """Falla pronto si Ollama no está activo o el modelo no está descargado."""
    req = urllib.request.Request(url_base.rstrip("/") + "/api/tags")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            modelos = {m["name"] for m in json.load(resp).get("models", [])}
    except (urllib.error.URLError, TimeoutError) as e:
        raise ErrorOllama(f"no se pudo conectar con Ollama en {url_base} ({e}). "
                          "¿Está 'ollama serve' en marcha?") from None
    if modelo not in modelos and f"{modelo}:latest" not in modelos:
        disponibles = ", ".join(sorted(modelos)) or "ninguno"
        raise ErrorOllama(f"el modelo {modelo!r} no está descargado (disponibles: {disponibles}). "
                          f"Descárgalo con: ollama pull {modelo}")
