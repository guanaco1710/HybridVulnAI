"""Verificación opcional de CVE contra la API de NVD (NIST).

Solo se envían los IDs de CVE, nunca datos de la red escaneada.
Sin API key NVD permite ~5 peticiones cada 30 s, por eso se espera entre consultas.
Con la variable de entorno NVD_API_KEY el límite es mucho mayor.
"""

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

URL_NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def verificar_cves(ids: set[str]) -> dict[str, dict]:
    clave = os.environ.get("NVD_API_KEY")
    pausa = 0.7 if clave else 6.5
    resultados = {}
    for i, cve in enumerate(sorted(ids)):
        if i:
            time.sleep(pausa)
        url = f"{URL_NVD}?{urllib.parse.urlencode({'cveId': cve})}"
        cabeceras = {"User-Agent": "escaner-ia/1.0"}
        if clave:
            cabeceras["apiKey"] = clave
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=cabeceras),
                                        timeout=30) as resp:
                datos = json.load(resp)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            resultados[cve] = {"estado": "NO VERIFICABLE", "detalle": str(e)}
            continue

        vulns = datos.get("vulnerabilities", [])
        if not vulns:
            resultados[cve] = {"estado": "NO ENCONTRADO", "detalle": "no existe en NVD"}
            continue
        info = vulns[0]["cve"]
        desc = next((d["value"] for d in info.get("descriptions", []) if d.get("lang") == "en"), "")
        resultados[cve] = {"estado": "EXISTE", "detalle": desc[:250]}
    return resultados
