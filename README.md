# hybridVuln AI

**hybridVuln AI** es un escáner de red local que combina **nmap** con una **IA online (Anthropic, OpenAI, Gemini o Groq)** o un **modelo local (Ollama)**. Escanea tus equipos, analiza los resultados en busca de CVE, vulnerabilidades y malas configuraciones, y genera un informe en Markdown con recomendaciones.

> ⚠️ **Uso responsable:** escanea solo redes propias o con autorización expresa. El script lo refuerza: solo acepta la red local (RFC1918 y loopback) y rechaza cualquier IP pública.

## Cómo funciona (paso a paso)

```
objetivos ─► validación ─► nmap (XML) ─► parseo ─► IA (online/Ollama) ─► clasificación de CVE ─► (NVD) ─► informe.md
```

1. **Validación de objetivos** ([objetivos.py](escaner_ia/objetivos.py)).
   Cada objetivo debe ser una IP o un rango CIDR dentro de `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` o `::1`. Se rechazan IPs públicas, `0.0.0.0/0`, nombres de host (podrían resolver a una IP pública), rangos con guion, rangos mayores que un /16 y cualquier valor que empiece por `-` (inyección de opciones).
2. **Escaneo con nmap** ([escaner.py](escaner_ia/escaner.py)).
   Se lanza `nmap` sin shell, con una lista de argumentos y un perfil cerrado (no se pasan opciones libres). La salida se pide en XML (`-oX -`) y los objetivos van tras `--`.
3. **Parseo** ([parser.py](escaner_ia/parser.py)).
   El XML se convierte en diccionarios: hosts activos, puertos abiertos, servicio, producto, versión, CPE, salida de scripts NSE y los CVE que estos reporten (por ejemplo `vulners`).
4. **Análisis con IA** ([proveedores.py](escaner_ia/proveedores.py), [ollama.py](escaner_ia/ollama.py)).
   - **IA online:** una **única petición** con el XML de nmap de todos los hosts (solo hosts con puertos abiertos, sin puertos cerrados ni datos de ruido, y con las salidas de scripts recortadas). La IA devuelve el análisis de todos los hosts en JSON con un esquema fijo (resumen + hallazgos con severidad, CVE, descripción y recomendación). Solo si el XML es muy grande (>24 000 caracteres, unos 6 000 tokens) se divide en lotes de hosts, para respetar los límites de tokens por minuto de las cuentas gratuitas. Si una petición falla (por ejemplo, límite de cuota), no se reintenta y se pasa a Ollama.
   - **Ollama:** al ser local y sin cuota, se analiza host a host.
   El prompt prohíbe inventar CVE y trata los banners del XML como datos, no como instrucciones.
5. **Clasificación del origen de cada CVE.**
   Los IDs con formato inválido se descartan. Cada CVE se marca como `nmap` (lo detectó el escaneo) o `ia` (lo infirió el modelo). Los marcados como `ia` son los que hay que verificar.
6. **Verificación opcional en NVD** ([nvd.py](escaner_ia/nvd.py)), con `--verificar-cve`.
   Se consulta cada CVE en la API de NVD para confirmar que existe. Solo se envían los IDs, nunca datos de tu red.
7. **Informe** ([informe.py](escaner_ia/informe.py), [pdf.py](escaner_ia/pdf.py)).
   Se genera en Markdown y también en **PDF** (mismo nombre con extensión `.pdf`, con colores por severidad). La IA solo devuelve texto estructurado; el PDF lo maqueta el script con WeasyPrint a partir de ese análisis, tanto si lo hizo una IA online como Ollama.
   Se genera un Markdown por host con dos secciones separadas: *Datos de nmap* (hechos del escaneo) y *Hallazgos del análisis de IA* (inferencias), ordenados por severidad.

## Requisitos

- Linux/macOS con **Python 3.10+** (solo biblioteca estándar, sin `pip install`).
- **nmap** instalado (`sudo apt install nmap`).
- El script NSE **vulners** (incluido en las instalaciones habituales de nmap) para el perfil por defecto.
- **WeasyPrint** para el PDF (`sudo apt install python3-weasyprint`). Opcional: sin él se genera solo el Markdown y se avisa.
- Al menos una IA: una **API key** de un proveedor online o **Ollama** en marcha con un modelo descargado. Sin ninguna, solo se guarda el XML de nmap.

## Instalación y preparación de Ollama

```bash
# 1. Instalar Ollama: https://ollama.com/download
# 2. Descargar un modelo
ollama pull llama3.1:8b
# 3. Asegurarse de que el servidor está activo (por defecto en http://localhost:11434)
ollama serve
```

## Selección de la IA

Antes de escanear se decide qué IA usar, por orden:

1. **IA online**, si el `.env` define `API_KEY_IA`. Variables del `.env`:

   | Variable | Para qué |
   |---|---|
   | `API_KEY_IA` | Tu API key (la de cualquier proveedor soportado). |
   | `PROVEEDOR_IA` | `anthropic`, `openai`, `gemini` o `groq`. Opcional: si se omite se deduce del prefijo de la clave (`sk-ant-` → anthropic, `AIza` → gemini, `gsk_` → groq, `sk-` → openai). Si no se puede deducir, defínelo. |
   | `MODELO_IA` | Modelo a usar. Opcional; por defecto `claude-haiku-5-5`, `gpt-4o-mini`, `gemini-2.5-flash` o `openai/gpt-oss-120b` según el proveedor. |

   En línea de comandos, `--proveedor` y `--modelo-online` tienen prioridad sobre el `.env`.
2. **Ollama**, si no hay API key o si la IA online falla en un host (error de red, clave inválida, respuesta no válida).
3. **Solo XML**: si no hay API key ni Ollama, se escanea igualmente y se guarda el XML de nmap (junto a `--salida`, con extensión `.xml`, o en `--guardar-xml`) sin generar informe.

Las claves se guardan en un `.env` en la raíz del proyecto (también lo encuentra cron, que no hereda tu entorno):

```bash
cp .env.example .env
chmod 600 .env
# edita .env y rellena API_KEY_IA
```

El `.env` está en `.gitignore`: **nunca lo subas a GitHub**. Si una variable no está en el `.env`, se mira como respaldo el entorno del proceso. Usa otro fichero con `--env`. Las claves nunca se aceptan por línea de comandos ni se escriben en el informe o en el log.

## Uso

Desde la raíz del proyecto:

```bash
# Escaneo + análisis con IA de una subred
python3 -m escaner_ia 192.168.1.0/24

# Varias IPs, con verificación de CVE en NVD y otro modelo
python3 -m escaner_ia 192.168.1.10 192.168.1.20 --verificar-cve --modelo qwen2.5:14b

# Con una IA online (si hay una API key en el .env, se usa en vez de Ollama)
python3 -m escaner_ia 192.168.1.0/24 --proveedor anthropic

# Con detección de sistema operativo (requiere root)
sudo python3 -m escaner_ia 192.168.1.0/24 --so

# Solo escanear, sin IA (útil para probar nmap)
python3 -m escaner_ia 127.0.0.1 --sin-ia --perfil rapido
```

El informe se guarda en `informe.md` y `informe.pdf` (cámbialo con `--salida`; `--sin-pdf` omite el PDF).

### Opciones

| Opción | Descripción |
|---|---|
| `objetivos` | Una o más IPs o rangos CIDR de la red local. |
| `--perfil {rapido,estandar,vulners}` | Perfil de escaneo (por defecto `vulners`). |
| `--so` | Detecta el sistema operativo (`-O`). Requiere root. |
| `--modelo NOMBRE` | Modelo de Ollama (por defecto `llama3.1:8b`). |
| `--proveedor {anthropic,openai,gemini,groq}` | Fuerza la IA online (por defecto, `PROVEEDOR_IA` o el deducido de `API_KEY_IA`). |
| `--env FICHERO` | Fichero `.env` a usar (por defecto, el de la raíz del proyecto). |
| `--modelo-online NOMBRE` | Modelo de la IA online (por defecto, `MODELO_IA` o uno por proveedor). |
| `--ollama-url URL` | URL del servidor Ollama (por defecto `http://localhost:11434`). |
| `--salida FICHERO` | Fichero del informe (por defecto `informe.md`). |
| `--guardar-xml FICHERO` | Guarda también el XML bruto de nmap. |
| `--verificar-cve` | Comprueba en NVD que existen los CVE citados. |
| `--sin-pdf` | No genera el PDF (solo el Markdown). |
| `--sin-ia` | No llama a ninguna IA; escanea y genera el informe solo con datos de nmap. |

### Perfiles de escaneo

| Perfil | Argumentos de nmap | Para qué |
|---|---|---|
| `rapido` | `-sV --top-ports 100 -T4` | Vistazo rápido a los puertos más comunes. |
| `estandar` | `-sV -sC -T4` | Versiones y scripts NSE por defecto. |
| `vulners` | `-sV -sC --script vulners -T4` | Además busca CVE conocidos por versión. |

## Cómo leer el informe

- **Datos de nmap:** hechos del escaneo (puertos, versiones, CVE del script `vulners`). Son fiables en la medida en que lo es la detección de versiones de nmap.
- **Hallazgos del análisis de IA:** opiniones del modelo. Cada CVE indica su `origen`:
  - `nmap`: lo detectó el escaneo.
  - `ia`: lo citó el modelo; **puede ser una alucinación**, verifícalo.
- Con `--verificar-cve` aparece además el estado en NVD (`EXISTE`, `NO ENCONTRADO`, `NO VERIFICABLE`). Que un CVE exista no garantiza que afecte a tu versión: comprueba también el producto afectado.

## Notas

- **NVD y límites de peticiones:** sin clave son ~5 consultas cada 30 s (el script espera 6,5 s entre ellas). Define `NVD_API_KEY` en el `.env` para ir más rápido.
- **Privacidad:** con Ollama el análisis es local y los datos no salen de tu máquina. **Con una IA online se envían a ese proveedor las IPs, puertos, versiones y salidas de scripts de tus equipos** (el programa lo avisa por pantalla); si no quieres eso, no definas la API key. Con `--verificar-cve` solo se envían a NVD los IDs de CVE.
- **Calidad del análisis:** depende del modelo. Los modelos pequeños (7-8B) pasan por alto cosas y se equivocan más; uno mayor mejora los resultados.
- **Errores típicos:**
  - *«no se pudo conectar con Ollama»*: arranca `ollama serve` (si no hay API key tampoco, solo se guardará el XML).
  - *«anthropic/openai/gemini/groq respondió 401/403»*: la API key es inválida; se usa Ollama como respaldo.
  - *«el modelo … no está descargado»*: ejecuta `ollama pull <modelo>`.
  - *«la detección de SO (-O) requiere ejecutar como root»*: usa `sudo`.
  - *«fuera de la red local permitida»*: el objetivo no es una IP privada o de loopback.

## Estructura

```
escaner_ia/
├── __main__.py   # CLI y orquestación del pipeline
├── objetivos.py  # validación de objetivos (solo red local)
├── escaner.py    # ejecución segura de nmap
├── parser.py     # XML de nmap -> datos normalizados
├── ollama.py     # prompt, llamada a Ollama y clasificación de CVE
├── proveedores.py # IA online (Anthropic, OpenAI, Gemini, Groq) por API key
├── nvd.py        # verificación opcional de CVE en NVD
├── informe.py    # generación del informe (Markdown y HTML)
└── pdf.py        # HTML -> PDF con WeasyPrint
tests/            # pruebas unitarias
docs/agentes.md   # subagentes de Claude Code del proyecto
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```
