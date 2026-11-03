"""Generación del informe en Markdown."""

from datetime import datetime

ORDEN = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}


def generar_informe(datos: dict, analisis: dict[str, dict], verificacion: dict[str, dict] | None,
                    modelo: str) -> str:
    L = []
    L.append("# Informe de seguridad de red")
    L.append("")
    L.append(f"- Fecha: {datetime.now():%Y-%m-%d %H:%M}")
    L.append(f"- Comando nmap: `{datos['comando']}`")
    L.append(f"- Modelo de IA: `{modelo}`")
    L.append(f"- Hosts activos: {len(datos['hosts'])}")
    L.append("")
    L.append("> **Aviso:** los datos de la sección *Datos de nmap* proceden del escaneo. "
             "Los *Hallazgos del análisis de IA* son inferencias del modelo y pueden contener "
             "errores; los CVE marcados como `ia` deben verificarse antes de darlos por buenos.")
    L.append("")

    for host in datos["hosts"]:
        ip = host["ip"]
        nombre = f" ({', '.join(host['nombres'])})" if host["nombres"] else ""
        L.append(f"## Host {ip}{nombre}")
        L.append("")
        if host["so"]:
            L.append(f"SO probable: {host['so'][0]['nombre']} ({host['so'][0]['precision']}%)")
            L.append("")

        L.append("### Datos de nmap")
        L.append("")
        if host["puertos"]:
            L.append("| Puerto | Servicio | Producto / versión | CVE (script NSE) |")
            L.append("|---|---|---|---|")
            for p in host["puertos"]:
                prod = f"{p['producto']} {p['version']}".strip() or "-"
                cves = ", ".join(c["id"] for c in p["cves_nmap"]) or "-"
                L.append(f"| {p['puerto']}/{p['protocolo']} | {p['servicio'] or '-'} | {prod} | {cves} |")
        else:
            L.append("Sin puertos abiertos detectados.")
        L.append("")

        L.append("### Hallazgos del análisis de IA")
        L.append("")
        a = analisis.get(ip)
        if a is None:
            L.append("_No se pudo analizar este host._")
        else:
            L.append(a.get("resumen", ""))
            L.append("")
            hallazgos = sorted(a.get("hallazgos", []), key=lambda h: ORDEN.get(h["severidad"], 9))
            if not hallazgos:
                L.append("_Sin hallazgos._")
            for h in hallazgos:
                puerto = f"puerto {h['puerto']}" if h["puerto"] else "host"
                L.append(f"#### [{h['severidad'].upper()}] {h['titulo']} ({puerto}, {h['tipo']})")
                L.append("")
                L.append(h["descripcion"])
                if h["cves"]:
                    partes = []
                    for c in h["cves"]:
                        txt = f"{c['id']} (origen: {c['origen']}"
                        v = (verificacion or {}).get(c["id"])
                        if v:
                            txt += f", NVD: {v['estado']}"
                        partes.append(txt + ")")
                    L.append("")
                    L.append("**CVE:** " + "; ".join(partes))
                L.append("")
                L.append(f"**Recomendación:** {h['recomendacion']}")
                L.append("")
    return "\n".join(L) + "\n"
