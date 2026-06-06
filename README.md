# MCP OSINT Server

Servidor MCP para agentes IA que permite ejecutar tareas OSINT de forma **controlada, trazable y segura** sobre una imagen Docker de Kali Linux.

Compatible con **Claude Code**, **Gemini CLI** y **ChatGPT** (mediante GPT Actions o function calling).

---

## Arquitectura

```
[Claude Code / Gemini CLI / ChatGPT]
         |
         | MCP: stdio (local) / HTTP+SSE (remoto)
         v
[mcp_server/server.py]          Python, Anthropic MCP SDK
         |
         | HTTP → localhost:8001
         v
[osint_api/main.py]             FastAPI
         |
         v
[Docker Kali OSINT Sandbox]
    ├── whois, dig, subfinder, theHarvester, httpx, whatweb
    ├── sherlock, maigret, holehe, phoneinfoga
    ├── exiftool, mat2, pdfinfo, file, strings
    ├── gitleaks, trufflehog, git (clonado de repos)
    └── Conectores: AbuseIPDB, HIBP, EmailRep, VirusTotal, Shodan
```

---

## Workflows OSINT disponibles

| Workflow | Descripción |
|---|---|
| `domain_recon` | WHOIS, DNS, subdominios (subfinder), theHarvester, Shodan pasivo. Con `passive_only=false`: sondeo HTTP (httpx) y fingerprinting web (whatweb) |
| `ip_reputation` | ASN, reputación, abuse reports, Shodan pasivo |
| `email_reputation` | Servicios registrados, reputación, brechas (no passwords) |
| `phone_reputation` | Carrier, país, tipo de línea, spam signals |
| `username_recon` | Cuentas activas en 300+ plataformas (Sherlock + Maigret), enriquecimiento PDL/FullContact |
| `person_recon` | Búsqueda por nombre completo: empleo, educación, perfiles sociales, ubicación (PDL, FullContact, IntelX) |
| `reverse_image_search` | Búsqueda inversa por imagen, hash perceptual, TinEye |
| `metadata_analysis` | Metadatos EXIF/GPS, autor, software, hash SHA256 de imágenes y documentos |
| `breach_exposure_check` | Exposición en brechas conocidas, VirusTotal (sin passwords) |
| `vehicle_recon` | Matrícula española o VIN → marca, modelo, motor, emisiones, historial ITV |
| `secret_scan` | Escaneo de secretos/credenciales filtrados en un repositorio git público (github, gitlab, bitbucket, codeberg) o fichero subido, con gitleaks + trufflehog. Secretos siempre redactados |

## Herramientas de soporte MCP

| Herramienta | Descripción |
|---|---|
| `list_osint_tools` | Lista el catálogo de herramientas disponibles |
| `recommend_osint_workflow` | Auto-detecta tipo de indicador y recomienda workflows |
| `run_osint_workflow` | Ejecuta cualquier workflow por nombre |
| `get_task_result` | Consulta estado y resultado de una tarea (soporta long-polling con `?wait=N`) |
| `export_report` | Exporta informe en Markdown / JSON / HTML |

## API de archivos

Permite analizar imágenes y documentos para extraer metadatos EXIF/GPS y datos del autor.

| Endpoint | Descripción |
|---|---|
| `POST /files/upload` | Sube un archivo binario directamente (curl, API clients). Valida MIME por magic bytes. |
| `POST /files/fetch` | Descarga un archivo desde URL pública y lo prepara para análisis. Uso obligatorio desde GPT Actions (no puede enviar binarios). |

Formatos soportados: JPEG, PNG, WebP, GIF, TIFF, BMP, HEIC, PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP. Límite: 20 MB.

> **Nota para ChatGPT:** usar siempre `fetchFile` con la URL del archivo. Servicios que preservan metadatos EXIF: `0x0.st`, `catbox.moe`, `transfer.sh`. Evitar Imgur, WhatsApp y CDNs de redes sociales (eliminan metadatos).

---

## Inicio rápido

### Desarrollo local

```bash
# 1. Clonar y configurar
git clone <repo> mcp-osint-server
cd mcp-osint-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configurar variables de entorno
cp config/.env.example config/.env
# Editar config/.env (al menos OSINT_INTERNAL_API_KEY)

# 3. Levantar la OSINT API
uvicorn osint_api.main:app --host 127.0.0.1 --port 8001 --reload

# 4. (En otra terminal) Probar el servidor MCP
source .venv/bin/activate
python -m mcp_server.server --transport stdio
```

### Docker Compose (producción)

```bash
cp config/.env.example config/.env
# Editar config/.env

docker compose -f docker/docker-compose.yml up -d
# OSINT API en http://localhost:8001
# MCP Server (SSE) en http://localhost:3000/sse
```

---

## Conectar a clientes IA

| Cliente | Documentación |
|---|---|
| Claude Code | [docs/connect-claude-code.md](docs/connect-claude-code.md) |
| Gemini CLI | [docs/connect-gemini.md](docs/connect-gemini.md) |
| ChatGPT | [docs/connect-chatgpt.md](docs/connect-chatgpt.md) |

### Ejemplo rápido — Claude Code (stdio)

Añade a `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "osint": {
      "command": "/ruta/al/proyecto/.venv/bin/python",
      "args": ["-m", "mcp_server.server", "--transport", "stdio"],
      "cwd": "/ruta/al/proyecto",
      "env": {
        "OSINT_API_URL": "http://127.0.0.1:8001",
        "OSINT_INTERNAL_API_KEY": "tu-clave",
        "OSINT_MODE": "safe"
      }
    }
  }
}
```

---

## Tests

```bash
source .venv/bin/activate
pip install pytest pytest-asyncio
pytest tests/ -v
```

---

## Variables de entorno

### Configuración del sistema

| Variable | Descripción | Por defecto |
|---|---|---|
| `OSINT_MODE` | Modo de operación: `safe`, `analyst`, `lab` | `safe` |
| `OSINT_INTERNAL_API_KEY` | Clave compartida MCP server ↔ OSINT API ([cómo generarla](#generar-osint_internal_api_key)) | `changeme` |
| `LOG_LEVEL` | Nivel de log: DEBUG, INFO, WARNING, ERROR | `INFO` |
| `MAX_TASK_TIME_SECONDS` | Timeout máximo por tarea | `300` |
| `MAX_CONCURRENT_TASKS` | Tareas concurrentes máximas | `3` |

#### Generar `OSINT_INTERNAL_API_KEY`

No se obtiene de ningún proveedor externo: es un **secreto compartido** que tú generas y que autentica al servidor MCP frente a la OSINT API (cabecera `X-OSINT-API-Key`). Debe ser idéntico en ambos lados (el `.env` de la API y la config del cliente MCP). Genera un valor aleatorio con cualquiera de estos comandos:

```bash
# Opción A — UUID
uuidgen

# Opción B — 32 bytes aleatorios en hex (Python, siempre disponible)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Opción C — OpenSSL
openssl rand -hex 32
```

Copia el valor en `config/.env`:

```bash
OSINT_INTERNAL_API_KEY=el-valor-generado
```

Y usa **el mismo valor** en la config del cliente MCP (campo `OSINT_INTERNAL_API_KEY` del ejemplo de Claude Code más abajo) y al ejecutar el check en modo `--live`. No lo dejes en `changeme` fuera de desarrollo.

### Modelos LLM (para el cliente)

| Variable | Descripción | Dónde obtener la key |
|---|---|---|
| `OLLAMA_URL` | URL del servidor Ollama | — (local) |
| `OLLAMA_MODEL` | Modelo por defecto | — |
| `DEEPSEEK_API_KEY` | DeepSeek API (deepseek-chat / deepseek-reasoner) | [platform.deepseek.com](https://platform.deepseek.com/) |
| `OPENAI_API_KEY` | OpenAI API (GPT-4o, GPT-4o-mini...) | [platform.openai.com/api-keys](https://platform.openai.com/api-keys) |

### APIs externas OSINT

Todas son opcionales. El sistema funciona con las que estén configuradas y degrada graciosamente las que faltan.

| Variable | Servicio | Plan gratuito | Dónde obtener la key |
|---|---|---|---|
| `SHODAN_API_KEY` | Shodan — passive service discovery por IP | No (desde $49/mes) | [account.shodan.io](https://account.shodan.io/) |
| `CENSYS_API_TOKEN` | Censys — hosts, certificados, dominios | Sí (250 req/mes) | [search.censys.io/account](https://search.censys.io/account) |
| `VIRUSTOTAL_API_KEY` | VirusTotal — reputación de URLs, dominios, IPs, hashes | Sí (500 req/día) | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| `ABUSEIPDB_API_KEY` | AbuseIPDB — reportes de abuso por IP | Sí (1000 req/día) | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |
| `HIBP_API_KEY` | Have I Been Pwned — brechas por email | No (desde £3.50/mes) | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| `EMAILREP_API_KEY` | EmailRep — reputación de email | Sí (limitado) | [emailrep.io/key](https://emailrep.io/key) |
| `IPQUALITYSCORE_API_KEY` | IPQualityScore — fraud scoring para email, teléfono e IP | Sí (5000 req/mes) | [ipqualityscore.com/user/settings](https://www.ipqualityscore.com/user/settings) |
| `FULLCONTACT_API_KEY` | FullContact — enriquecimiento de persona (nombre, empleo, perfiles sociales) | Sí (500 req/mes) | [dashboard.fullcontact.com](https://dashboard.fullcontact.com/) |
| `INTELX_API_KEY` | Intelligence X — búsqueda en leaks, pastes, darkweb, Telegram | Sí (limitado) | [intelx.io](https://intelx.io/) → Account → API |
| `PEOPLEDATALABS_API_KEY` | People Data Labs — enriquecimiento de persona: historial laboral, educación, skills, perfiles sociales, dominios email | Sí (100 req/mes free) | [peopledatalabs.com](https://www.peopledatalabs.com/) → API Keys |
| `SECURITYTRAILS_API_KEY` | SecurityTrails — DNS histórico, subdominios | Sí (50 req/mes) | [securitytrails.com/app/account/credentials](https://securitytrails.com/app/account/credentials) |
| `TINEYE_API_KEY` | TinEye — búsqueda inversa de imágenes | No (desde $200/mes) | [api.tineye.com](https://api.tineye.com/) |
| `NUMVERIFY_API_KEY` | Numverify — validación de teléfonos | Sí (100 req/mes) | [numverify.com/dashboard](https://numverify.com/dashboard) |
| `TWILIO_ACCOUNT_SID` + `TWILIO_AUTH_TOKEN` | Twilio Lookup — carrier, tipo de línea | Pago por uso ($0.005/req) | [console.twilio.com](https://console.twilio.com/) |
| `RAPIDAPI_KEY` | RapidAPI (Autoways/DGT) — matrícula o VIN → marca, modelo, motor, emisiones, fechas | Según plan | [rapidapi.com — Autoways](https://rapidapi.com/autoways/api/api-license-plate-spain-matricula-api-espana) |

---

## Seguridad

- **Sin ejecución de comandos raw** en modo `safe`.
- **Allowlist estricta** de binarios y argumentos CLI.
- **Validación** de todos los inputs antes de cualquier ejecución.
- **Enmascarado** de PII y API keys en outputs.
- **Docker sandbox**: `no-new-privileges`, `cap_drop: ALL`, `read_only`.
- **Rate limiting** por cliente y por API externa.
- **Tool poisoning**: resultados de internet se tratan como datos no confiables.

---

## Estructura del proyecto

```
mcp-osint-server/
├── mcp_server/         # Servidor MCP (stdio + SSE)
│   ├── server.py       # Entry point, 15 herramientas MCP
│   └── schemas/        # Pydantic models compartidos
├── osint_api/          # FastAPI backend
│   ├── main.py
│   ├── runners/        # Ejecución segura de CLIs
│   ├── parsers/        # Parsers de output por herramienta
│   ├── connectors/     # APIs externas (AbuseIPDB, HIBP, etc.)
│   ├── workflows/      # 11 workflows OSINT
│   ├── catalog/        # Catálogo de herramientas
│   ├── security/       # Allowlist, validator, sanitizer, rate limiter
│   └── reports/        # Generadores Markdown/JSON/HTML
├── docker/             # Dockerfile.kali + docker-compose.yml
├── config/             # tools.yml, policies.yml, .env.example
├── docs/               # Documentación de conexión por cliente
└── tests/              # Tests unitarios
```

---

## Roadmap

- **Fase 1 (actual):** MVP — 11 workflows, Docker Kali, catálogo, informes, API archivos, long-polling
- **Fase 2:** Autenticación, políticas por rol, cola de tareas, auditoría avanzada
- **Fase 3:** Correlación de entidades, grafo OSINT, scoring avanzado, STIX/TAXII

---

## Licencia

Para uso en OSINT defensivo y autorizado únicamente. No usar para:
doxxing, stalking, fuerza bruta, explotación activa o cualquier actividad ilegal.
