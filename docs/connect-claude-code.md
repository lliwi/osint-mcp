# Conectar el MCP OSINT Server a Claude Code

## Requisitos previos

- Claude Code instalado (`npm install -g @anthropic-ai/claude-code` o desde el instalador oficial)
- Python 3.11+ en el sistema o el stack corriendo vía Docker
- El servidor MCP OSINT clonado y configurado

## Opción A — Conexión local (stdio, recomendada para desarrollo)

En este modo, Claude Code lanza el proceso MCP directamente mediante stdio.

### 1. Instalar dependencias Python

```bash
cd /ruta/a/mcp-osint-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configurar las variables de entorno

```bash
cp config/.env.example config/.env
# Editar config/.env con tus API keys opcionales
```

### 3. Levantar la OSINT API

```bash
# En una terminal:
source .venv/bin/activate
uvicorn osint_api.main:app --host 127.0.0.1 --port 8001 --reload
```

### 4. Registrar el servidor MCP en Claude Code

Añade esto a `~/.claude/settings.json` (global) o `.claude/settings.json` (solo proyecto):

```json
{
  "mcpServers": {
    "osint": {
      "command": "/ruta/a/mcp-osint-server/.venv/bin/python",
      "args": ["-m", "mcp_server.server", "--transport", "stdio"],
      "cwd": "/ruta/a/mcp-osint-server",
      "env": {
        "OSINT_API_URL": "http://127.0.0.1:8001",
        "OSINT_INTERNAL_API_KEY": "tu-clave-interna",
        "OSINT_MODE": "safe"
      }
    }
  }
}
```

### 5. Reiniciar Claude Code

Ejecuta `/mcp` en Claude Code para verificar que el servidor `osint` aparece disponible.

---

## Opción B — Conexión remota (HTTP)

Usa esta opción si el servidor corre en Docker o en un host remoto.

El servidor expone dos transportes HTTP: `streamable-http` (el actual de la spec
MCP, en `/mcp`) y `sse` (deprecado, en `/sse`). `docker-compose.yml` arranca
`sse` por defecto; para el transporte actual cambia el `command` del servicio
`mcp-server` a `--transport streamable-http` y registra la URL `/mcp`:

```json
{
  "mcpServers": {
    "osint": {
      "url": "http://localhost:3000/mcp"
    }
  }
}
```

Si accedes al servidor por un dominio o IP de LAN en lugar de `localhost`,
declara ese nombre en `MCP_ALLOWED_HOSTS` al levantar el compose — si no, la
protección anti DNS-rebinding rechaza la conexión con `421 Invalid Host header`:

```bash
MCP_ALLOWED_HOSTS=osint.example.com docker compose -f docker/docker-compose.yml up -d
```

El resto de esta sección describe la variante SSE.

### 1. Levantar con Docker Compose

```bash
cd /ruta/a/mcp-osint-server
cp config/.env.example config/.env
# Editar config/.env

docker compose -f docker/docker-compose.yml up -d
```

El MCP server escuchará en `http://localhost:3000/sse`.

### 2. Registrar en Claude Code (modo SSE)

```json
{
  "mcpServers": {
    "osint": {
      "url": "http://localhost:3000/sse"
    }
  }
}
```

> Si el servidor está en una máquina remota, sustituye `localhost` por la IP o dominio del servidor.

---

## Verificación

En Claude Code, escribe:

```
Usa la herramienta list_osint_tools para mostrar las herramientas disponibles
```

O directamente:

```
Analiza el dominio example.com con domain_recon
```

---

## Herramientas disponibles

| Herramienta | Descripción |
|---|---|
| `domain_recon` | WHOIS, DNS, subdominios, tecnologías web |
| `ip_reputation` | Reputación IP, ASN, abuse reports |
| `email_reputation` | Servicios registrados, reputación, brechas |
| `phone_reputation` | Carrier, país, tipo de línea, spam |
| `username_recon` | Perfiles públicos en redes sociales |
| `reverse_image_search` | Metadatos EXIF, búsqueda inversa |
| `metadata_analysis` | Metadatos de archivos, riesgos de privacidad |
| `breach_exposure_check` | Brechas conocidas, VirusTotal |
| `list_osint_tools` | Lista el catálogo |
| `recommend_osint_workflow` | Detecta tipo y recomienda workflows |
| `run_osint_workflow` | Ejecuta cualquier workflow |
| `get_task_result` | Consulta resultado de una tarea |
| `export_report` | Genera informe en Markdown/JSON/HTML |

---

## Modo de operación

Controla el modo con la variable `OSINT_MODE`:

| Modo | Descripción |
|---|---|
| `safe` | Por defecto. OSINT pasivo, sin raw commands |
| `analyst` | Más APIs y fuentes, requiere autenticación |
| `lab` | Interno, testing controlado |
