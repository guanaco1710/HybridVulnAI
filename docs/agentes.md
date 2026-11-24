# Subagentes del proyecto

Los subagentes viven en `.claude/agents/` (un `.md` por agente, con frontmatter `name`, `description`, `tools`). Claude Code los detecta al iniciar la sesión; si añades o editas uno con la sesión abierta, reiníciala o usa `/agents`.

## Decisiones de diseño

| Decisión | Valor | Motivo |
|---|---|---|
| Alcance de escaneo | Red local (RFC1918 + loopback) siempre. IPs públicas y nombres de host **solo con `--permitir-externos`** (declara autorización). Nunca lo no enrutable | Requisito del proyecto, ampliado con `--permitir-externos` |
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
- **Para qué:** garantizar que el script solo escanea lo que la política permite (red local; externos solo con el flag) y que nada llega sin sanear a nmap o a una shell (`shell=True`, inyección de opciones con `-`, hostnames que resuelven a IP pública, salida del modelo ejecutada…).
- **Cuándo usarlo:** tras cambiar código que construya o ejecute comandos nmap o reciba objetivos.
- **Resultado:** hallazgos por gravedad con `fichero:línea` y corrección sugerida.
- **Ejemplo:** «Usa scan-safety-reviewer sobre el módulo de escaneo».

## Pendiente de definir

- Si hace falta una API key de NVD para evitar límites de peticiones (hoy se consulta sin clave y en serie).
