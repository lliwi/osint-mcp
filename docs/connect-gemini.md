# Conectar el MCP OSINT Server a Gemini CLI

Gemini CLI soporta servidores MCP de forma nativa desde la versión 1.0.0.

## Requisitos previos

- [Gemini CLI](https://github.com/google-gemini/gemini-cli) instalado
- Python 3.11+ y dependencias del proyecto instaladas
- (Opcional) Docker para el modo contenedor

---

## Opción A — Modo stdio (local, recomendada)

### 1. Instalar y configurar el proyecto

```bash
cd /ruta/a/mcp-osint-server
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp config/.env.example config/.env
# Editar config/.env con tus API keys
```

### 2. Levantar la OSINT API

```bash
source .venv/bin/activate
uvicorn osint_api.main:app --host 127.0.0.1 --port 8001
```

### 3. Registrar en Gemini CLI

Edita (o crea) `~/.gemini/settings.json`:

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

### 4. Verificar

```bash
gemini
# En el prompt de Gemini:
# ¿Qué herramientas OSINT tienes disponibles?
```

---

## Opción B — Modo HTTP/SSE (Docker, remoto)

### 1. Levantar con Docker Compose

```bash
cd /ruta/a/mcp-osint-server
cp config/.env.example config/.env
docker compose -f docker/docker-compose.yml up -d
```

### 2. Registrar en Gemini CLI (SSE)

```json
{
  "mcpServers": {
    "osint": {
      "httpUrl": "http://localhost:3000/sse"
    }
  }
}
```

> Si usas Gemini CLI en Google AI Studio o Vertex AI, el servidor MCP debe ser accesible desde internet. Se recomienda desplegar con un proxy NGINX + TLS.

---

## Ejemplos de uso

```
Analiza el dominio phishing-example.com y dime qué riesgo tiene
```

```
¿Este email user@example.com aparece en alguna brecha de datos?
```

```
Busca el username "alice123" en redes sociales
```

---

## Gemini API (sin CLI)

Si usas la API de Gemini directamente, puedes integrar las herramientas MCP mediante **function calling**. Consulta la [guía de function calling de Gemini](https://ai.google.dev/gemini-api/docs/function-calling) y mapea los schemas JSON de las herramientas OSINT (disponibles en el endpoint `GET /tools` de la API) a las definiciones de función de Gemini.

```python
import google.generativeai as genai
import httpx

# Obtener schemas de herramientas desde la OSINT API
tools_data = httpx.get("http://localhost:8001/tools",
                        headers={"X-OSINT-API-Key": "tu-clave"}).json()
# Convertir al formato de Gemini function declarations
# ... (ver docs de Gemini function calling)
```
