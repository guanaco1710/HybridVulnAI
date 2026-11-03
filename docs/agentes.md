# Subagentes del proyecto

Los subagentes viven en `.claude/agents/` (un `.md` por agente, con frontmatter `name`, `description`, `tools`). Claude Code los detecta al iniciar la sesión; si añades o editas uno con la sesión abierta, reiníciala o usa `/agents`.

## Decisiones de diseño

| Decisión | Valor | Motivo |
|---|---|---|
| Alcance de escaneo | Toda la red local (RFC1918 + loopback); **nunca IPs públicas** | Requisito del proyecto |
| Fuente de verificación de CVE | NVD primero, CVE Program (cve.org) como respaldo | Requisito del proyecto |
| Idioma | Español | Requisito del proyecto |
| Herramientas de los agentes | Solo lectura (+ WebFetch en `cve-verifier`) | Los agentes informan, no modifican código |

## cve-verifier

- **Fichero:** `.claude/agents/cve-verifier.md`
- **Para qué:** el modelo de Ollama puede inventar CVE. Este agente comprueba cada ID contra NVD (`services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`) y, si falla, contra `cveawg.mitre.org/api/cve/...`.
- **Cuándo usarlo:** siempre que un informe o salida de la IA cite CVE, antes de darlos por buenos.
- **Resultado:** tabla con estado por CVE (VERIFICADO / NO COINCIDE / NO ENCONTRADO / NO VERIFICABLE), fuente y justificación.
- **Ejemplo:** «Usa cve-verifier sobre `informe.md`».

## scan-safety-reviewer

- **Fichero:** `.claude/agents/scan-safety-reviewer.md`
- **Para qué:** garantizar que el script solo escanea la red local y que nada llega sin sanear a nmap o a una shell (`shell=True`, inyección de opciones con `-`, hostnames que resuelven a IP pública, salida del modelo ejecutada…).
- **Cuándo usarlo:** tras cambiar código que construya o ejecute comandos nmap o reciba objetivos.
- **Resultado:** hallazgos por gravedad con `fichero:línea` y corrección sugerida.
- **Ejemplo:** «Usa scan-safety-reviewer sobre el módulo de escaneo».

## Pendiente de definir

- Rangos no cubiertos por la política (p. ej. link-local `169.254.0.0/16`): el revisor los marca como «requiere decisión del usuario».
- Si hace falta una API key de NVD para evitar límites de peticiones (hoy se consulta sin clave y en serie).
