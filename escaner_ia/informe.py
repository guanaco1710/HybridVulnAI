"""Generación del informe en Markdown."""

from datetime import datetime
from html import escape

ORDEN = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}


def _celda(valor) -> str:
    """Texto seguro para una celda de tabla Markdown (viene de plantillas y banners)."""
    return str(valor).replace("|", "\\|").replace("\n", " ")


def generar_informe(datos: dict, analisis: dict[str, dict], verificacion: dict[str, dict] | None,
                    modelo: str) -> str:
    L = []
    L.append("# Informe de seguridad de red")
    L.append("")
    L.append("- Generado por: hybridVuln AI")
    L.append(f"- Fecha: {datetime.now():%Y-%m-%d %H:%M}")
    L.append(f"- Comando nmap: `{datos['comando']}`")
    L.append(f"- Modelo de IA: `{modelo}`")
    if datos.get("nuclei"):
        incompleto = " (**INCOMPLETO**: se agotó el tiempo límite)" if datos.get("nuclei_incompleto") else ""
        L.append(f"- Nuclei: perfil `{datos['nuclei']}`{incompleto}")
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

        if host.get("nuclei") is not None:
            L.append("### Vulnerabilidades detectadas por nuclei")
            L.append("")
            if host["nuclei"]:
                L.append("| Severidad | Plantilla | Puerto | CVE | Coincidencia |")
                L.append("|---|---|---|---|---|")
                for n in sorted(host["nuclei"], key=lambda n: ORDEN.get(n["severidad"], 9)):
                    cves = ", ".join(n["cves"]) or "-"
                    detalles = f": {_celda(', '.join(n['detalles']))}" if n["detalles"] else ""
                    L.append(f"| {n['severidad'].upper()} | {_celda(n['nombre'])} (`{_celda(n['id'])}`){detalles} "
                             f"| {n['puerto'] or '-'} | {cves} | {_celda(n['coincidencia'] or '-')} |")
            else:
                L.append("Sin vulnerabilidades detectadas por nuclei" + (
                    " **en el tiempo disponible** (escaneo incompleto)." if datos.get("nuclei_incompleto") else "."))
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


CSS = """
@page { size: A4; margin: 18mm 16mm; @bottom-right { content: counter(page) " / " counter(pages); font-size: 9pt; color: #666; } }
body { font-family: sans-serif; font-size: 10pt; color: #1b1b1b; line-height: 1.4; }
h1 { font-size: 20pt; margin: 0 0 4mm; } h2 { font-size: 14pt; border-bottom: 1px solid #999; padding-bottom: 1mm; margin-top: 8mm; }
h3 { font-size: 11.5pt; margin: 5mm 0 2mm; } ul.meta { list-style: none; padding: 0; margin: 0 0 4mm; }
.aviso { background: #f3f3f3; border-left: 3px solid #888; padding: 2mm 3mm; font-size: 9pt; }
table { border-collapse: collapse; width: 100%; font-size: 9pt; } th, td { border: 1px solid #bbb; padding: 1mm 2mm; text-align: left; }
th { background: #eee; }
.hallazgo { border: 1px solid #ccc; border-left-width: 4px; padding: 2mm 3mm; margin: 3mm 0; page-break-inside: avoid; }
.hallazgo h4 { margin: 0 0 1mm; font-size: 10.5pt; }
.sev-critica { border-left-color: #7b1fa2; } .sev-alta { border-left-color: #d32f2f; }
.sev-media { border-left-color: #f57c00; } .sev-baja { border-left-color: #fbc02d; } .sev-info { border-left-color: #1976d2; }
.etq { font-weight: bold; font-size: 8.5pt; text-transform: uppercase; }
"""


def generar_informe_html(datos: dict, analisis: dict[str, dict], verificacion: dict[str, dict] | None,
                         modelo: str) -> str:
    """Mismo contenido que generar_informe, listo para convertir a PDF. Todo el texto se escapa."""
    e = lambda v: escape(str(v))  # noqa: E731
    H = []
    H.append("<h1>Informe de seguridad de red</h1><ul class='meta'>")
    H.append("<li><b>Generado por:</b> hybridVuln AI</li>")
    H.append(f"<li><b>Fecha:</b> {datetime.now():%Y-%m-%d %H:%M}</li>")
    H.append(f"<li><b>Comando nmap:</b> <code>{e(datos['comando'])}</code></li>")
    H.append(f"<li><b>Modelo de IA:</b> <code>{e(modelo)}</code></li>")
    if datos.get("nuclei"):
        incompleto = " (<b>INCOMPLETO</b>: se agotó el tiempo límite)" if datos.get("nuclei_incompleto") else ""
        H.append(f"<li><b>Nuclei:</b> perfil <code>{e(datos['nuclei'])}</code>{incompleto}</li>")
    H.append(f"<li><b>Hosts activos:</b> {len(datos['hosts'])}</li></ul>")
    H.append("<p class='aviso'><b>Aviso:</b> los datos de la sección <i>Datos de nmap</i> proceden del "
             "escaneo. Los <i>Hallazgos del análisis de IA</i> son inferencias del modelo y pueden "
             "contener errores; los CVE marcados como <code>ia</code> deben verificarse antes de "
             "darlos por buenos.</p>")

    for host in datos["hosts"]:
        ip = host["ip"]
        nombre = f" ({e(', '.join(host['nombres']))})" if host["nombres"] else ""
        H.append(f"<h2>Host {e(ip)}{nombre}</h2>")
        if host["so"]:
            H.append(f"<p>SO probable: {e(host['so'][0]['nombre'])} ({e(host['so'][0]['precision'])}%)</p>")

        H.append("<h3>Datos de nmap</h3>")
        if host["puertos"]:
            H.append("<table><tr><th>Puerto</th><th>Servicio</th><th>Producto / versión</th>"
                     "<th>CVE (script NSE)</th></tr>")
            for pt in host["puertos"]:
                prod = f"{pt['producto']} {pt['version']}".strip() or "-"
                cves = ", ".join(c["id"] for c in pt["cves_nmap"]) or "-"
                H.append(f"<tr><td>{e(pt['puerto'])}/{e(pt['protocolo'])}</td><td>{e(pt['servicio'] or '-')}</td>"
                         f"<td>{e(prod)}</td><td>{e(cves)}</td></tr>")
            H.append("</table>")
        else:
            H.append("<p>Sin puertos abiertos detectados.</p>")

        if host.get("nuclei") is not None:
            H.append("<h3>Vulnerabilidades detectadas por nuclei</h3>")
            if host["nuclei"]:
                H.append("<table><tr><th>Severidad</th><th>Plantilla</th><th>Puerto</th><th>CVE</th>"
                         "<th>Coincidencia</th></tr>")
                for n in sorted(host["nuclei"], key=lambda n: ORDEN.get(n["severidad"], 9)):
                    H.append(f"<tr class='sev-{e(n['severidad'])}'><td><span class='etq'>{e(n['severidad'])}</span></td>"
                             f"<td>{e(n['nombre'])} (<code>{e(n['id'])}</code>){e(': ' + ', '.join(n['detalles']) if n['detalles'] else '')}</td><td>{e(n['puerto'] or '-')}</td>"
                             f"<td>{e(', '.join(n['cves']) or '-')}</td><td>{e(n['coincidencia'] or '-')}</td></tr>")
                H.append("</table>")
            else:
                H.append("<p>Sin vulnerabilidades detectadas por nuclei" + (
                    " <b>en el tiempo disponible</b> (escaneo incompleto)." if datos.get("nuclei_incompleto") else ".") + "</p>")

        H.append("<h3>Hallazgos del análisis de IA</h3>")
        a = analisis.get(ip)
        if a is None:
            H.append("<p><i>No se pudo analizar este host.</i></p>")
            continue
        H.append(f"<p>{e(a.get('resumen', ''))}</p>")
        hallazgos = sorted(a.get("hallazgos", []), key=lambda h: ORDEN.get(h["severidad"], 9))
        if not hallazgos:
            H.append("<p><i>Sin hallazgos.</i></p>")
        for h in hallazgos:
            puerto = f"puerto {h['puerto']}" if h["puerto"] else "host"
            sev = h["severidad"] if h["severidad"] in ORDEN else "info"
            H.append(f"<div class='hallazgo sev-{sev}'><h4><span class='etq'>[{e(h['severidad'])}]</span> "
                     f"{e(h['titulo'])} <small>({e(puerto)}, {e(h['tipo'])})</small></h4>")
            H.append(f"<p>{e(h['descripcion'])}</p>")
            if h["cves"]:
                partes = []
                for c in h["cves"]:
                    txt = f"{c['id']} (origen: {c['origen']}"
                    v = (verificacion or {}).get(c["id"])
                    if v:
                        txt += f", NVD: {v['estado']}"
                    partes.append(e(txt + ")"))
                H.append("<p><b>CVE:</b> " + "; ".join(partes) + "</p>")
            H.append(f"<p><b>Recomendación:</b> {e(h['recomendacion'])}</p></div>")
    return ("<!doctype html><html lang='es'><head><meta charset='utf-8'><title>Informe de seguridad de red - hybridVuln AI"
            f"</title><style>{CSS}</style></head><body>" + "\n".join(H) + "</body></html>")
