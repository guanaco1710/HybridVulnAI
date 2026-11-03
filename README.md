# escaner_ia

Escáner de red local que combina **nmap** con un **modelo de IA local (Ollama)**. Escanea tus equipos, analiza los resultados en busca de CVE, vulnerabilidades y malas configuraciones, y genera un informe en Markdown con recomendaciones.

> ⚠️ **Uso responsable:** escanea solo redes propias o con autorización expresa. El script lo refuerza: solo acepta la red local (RFC1918 y loopback) y rechaza cualquier IP pública.

## Cómo funciona (paso a paso)

```
objetivos ─► validación ─► nmap (XML) ─► parseo ─► Ollama ─► clasificación de CVE ─► (NVD) ─► informe.md
```

1. **Validación de objetivos** ([objetivos.py](escaner_ia/objetivos.py)).
   Cada objetivo debe ser una IP o un rango CIDR dentro de `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8` o `::1`. Se rechazan IPs públicas, `0.0.0.0/0`, nombres de host (podrían resolver a una IP pública), rangos con guion, rangos mayores que un /16 y cualquier valor que empiece por `-` (inyección de opciones).
2. **Escaneo con nmap** ([escaner.py](escaner_ia/escaner.py)).
   Se lanza `nmap` sin shell, con una lista de argumentos y un perfil cerrado (no se pasan opciones libres). La salida se pide en XML (`-oX -`) y los objetivos van tras `--`.
3. **Parseo** ([parser.py](escaner_ia/parser.py)).
   El XML se convierte en diccionarios: hosts activos, puertos abiertos, servicio, producto, versión, CPE, salida de scripts NSE y los CVE que estos reporten (por ejemplo `vulners`).
4. **Análisis con IA** ([ollama.py](escaner_ia/ollama.py)).
   Por cada host con puertos abiertos se envía un resumen a la API de Ollama (`/api/chat`). Se fuerza una respuesta JSON con un esquema fijo (resumen + lista de hallazgos con severidad, CVE, descripción y recomendación). El prompt prohíbe inventar CVE.
5. **Clasificación del origen de cada CVE.**
   Los IDs con formato inválido se descartan. Cada CVE se marca como `nmap` (lo detectó el escaneo) o `ia` (lo infirió el modelo). Los marcados como `ia` son los que hay que verificar.
6. **Verificación opcional en NVD** ([nvd.py](escaner_ia/nvd.py)), con `--verificar-cve`.
   Se consulta cada CVE en la API de NVD para confirmar que existe. Solo se envían los IDs, nunca datos de tu red.
7. **Informe** ([informe.py](escaner_ia/informe.py)).
   Se genera un Markdown por host con dos secciones separadas: *Datos de nmap* (hechos del escaneo) y *Hallazgos del análisis de IA* (inferencias), ordenados por severidad.

## Requisitos

- Linux/macOS con **Python 3.10+** (solo biblioteca estándar, sin `pip install`).
- **nmap** instalado (`sudo apt install nmap`).
- El script NSE **vulners** (incluido en las instalaciones habituales de nmap) para el perfil por defecto.
- **Ollama** en marcha con un modelo descargado (solo si usas la IA).

## Instalación y preparación de Ollama

```bash
# 1. Instalar Ollama: https://ollama.com/download
# 2. Descargar un modelo
ollama pull llama3.1:8b
# 3. Asegurarse de que el servidor está activo (por defecto en http://localhost:11434)
ollama serve
```

## Uso

Desde la raíz del proyecto:

```bash
# Escaneo + análisis con IA de una subred
python3 -m escaner_ia 192.168.1.0/24

# Varias IPs, con verificación de CVE en NVD y otro modelo
python3 -m escaner_ia 192.168.1.10 192.168.1.20 --verificar-cve --modelo qwen2.5:14b

# Con detección de sistema operativo (requiere root)
sudo python3 -m escaner_ia 192.168.1.0/24 --so

# Solo escanear, sin IA (útil para probar nmap)
python3 -m escaner_ia 127.0.0.1 --sin-ia --perfil rapido
```

El informe se guarda en `informe.md` (cámbialo con `--salida`).

### Opciones

| Opción | Descripción |
|---|---|
| `objetivos` | Una o más IPs o rangos CIDR de la red local. |
| `--perfil {rapido,estandar,vulners}` | Perfil de escaneo (por defecto `vulners`). |
| `--so` | Detecta el sistema operativo (`-O`). Requiere root. |
| `--modelo NOMBRE` | Modelo de Ollama (por defecto `llama3.1:8b`). |
| `--ollama-url URL` | URL del servidor Ollama (por defecto `http://localhost:11434`). |
| `--salida FICHERO` | Fichero del informe (por defecto `informe.md`). |
| `--guardar-xml FICHERO` | Guarda también el XML bruto de nmap. |
| `--verificar-cve` | Comprueba en NVD que existen los CVE citados. |
| `--sin-ia` | No llama a Ollama; solo escanea. |

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

- **NVD y límites de peticiones:** sin clave son ~5 consultas cada 30 s (el script espera 6,5 s entre ellas). Define `NVD_API_KEY` en el entorno para ir más rápido.
- **Privacidad:** el análisis con IA es local; los datos del escaneo no salen de tu máquina. Con `--verificar-cve` solo se envían a NVD los IDs de CVE.
- **Calidad del análisis:** depende del modelo. Los modelos pequeños (7-8B) pasan por alto cosas y se equivocan más; uno mayor mejora los resultados.
- **Errores típicos:**
  - *«no se pudo conectar con Ollama»*: arranca `ollama serve`.
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
├── nvd.py        # verificación opcional de CVE en NVD
└── informe.py    # generación del informe Markdown
tests/            # pruebas unitarias
docs/agentes.md   # subagentes de Claude Code del proyecto
```

## Tests

```bash
python3 -m unittest discover -s tests -t .
```
