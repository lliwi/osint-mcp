# Conectar el MCP OSINT Server a ChatGPT

ChatGPT no tiene soporte nativo de MCP como protocolo, pero ofrece tres vías de integración:

---

## Opción A — GPT Actions (ChatGPT Plus/Teams/Enterprise)

GPT Actions permite exponer una API REST como herramientas en un Custom GPT.
La OSINT API genera automáticamente un schema OpenAPI en `/openapi.json`.

### 1. Levantar la OSINT API

```bash
cd /ruta/a/mcp-osint-server
source .venv/bin/activate
uvicorn osint_api.main:app --host 0.0.0.0 --port 8001
```

O con Docker:

```bash
docker compose -f docker/docker-compose.yml up -d osint-api
```

> Para que ChatGPT pueda acceder, la API debe ser accesible desde internet.
> Usa un proxy NGINX con TLS o un servicio como ngrok para exposición temporal:
> ```bash
> ngrok http 8001
> ```

### 2. Crear un Custom GPT

1. Ir a [chat.openai.com](https://chat.openai.com) → **Explore GPTs** → **Create**
2. En la sección **Actions**, haz clic en **Create new action**
3. En **Schema**, pega la URL del OpenAPI spec:
   ```
   https://tu-dominio.com/openapi.json
   ```
   O pega el contenido JSON directamente (disponible en `http://localhost:8001/openapi.json`)
4. En **Authentication**, selecciona **API Key** y configura:
   - Auth Type: `Custom`
   - Header name: `X-OSINT-API-Key`
   - API Key: el valor de `OSINT_INTERNAL_API_KEY` de tu `.env`
5. Guarda y prueba el GPT

### 3. Prompt de sistema recomendado

```
Eres un asistente de análisis OSINT. Cuando el usuario te pida analizar un dominio,
IP, email, teléfono o usuario, usa las herramientas OSINT disponibles para obtener
información pública. Siempre indica las fuentes y el nivel de confianza.
Solo accedes a información pública y no realizas actividades invasivas.
```

---

## Opción B — API de OpenAI con Function Calling

Integra la OSINT API directamente en código Python usando la API de OpenAI.

```python
import json
import httpx
from openai import OpenAI

OSINT_API = "http://localhost:8001"
OSINT_KEY = "tu-clave-interna"
openai_client = OpenAI(api_key="tu-openai-key")

# 1. Cargar herramientas OSINT como funciones de OpenAI
def get_osint_tools():
    resp = httpx.get(f"{OSINT_API}/tools",
                     headers={"X-OSINT-API-Key": OSINT_KEY})
    tools = resp.json()
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"].replace("-", "_"),
                "description": t["description"],
                "parameters": {
                    "type": "object",
                    "properties": {
                        inp: {"type": "string"} for inp in t["inputs"]
                    },
                    "required": t["inputs"][:1],  # first input is required
                },
            }
        }
        for t in tools if t["enabled"]
    ]


# 2. Ejecutar una herramienta OSINT
def call_osint_tool(tool_name: str, arguments: dict) -> str:
    # Map tool name to workflow
    payload = {
        "workflow": tool_name,
        "target": next(iter(arguments.values()), ""),
        "mode": "safe",
        "output_format": "json",
        "options": arguments,
    }
    resp = httpx.post(f"{OSINT_API}/workflow/run",
                      json=payload,
                      headers={"X-OSINT-API-Key": OSINT_KEY},
                      timeout=30)
    task_id = resp.json()["task_id"]

    # Poll until complete
    import time
    for _ in range(60):
        time.sleep(5)
        result = httpx.get(f"{OSINT_API}/tasks/{task_id}",
                           headers={"X-OSINT-API-Key": OSINT_KEY})
        data = result.json()
        if data["status"] in ("completed", "failed"):
            return json.dumps(data.get("result", {}), indent=2)

    return '{"error": "timeout"}'


# 3. Loop de conversación con tool use
def chat_with_osint(user_message: str):
    tools = get_osint_tools()
    messages = [{"role": "user", "content": user_message}]

    while True:
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=messages,
            tools=tools,
            tool_choice="auto",
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            return msg.content

        for tool_call in msg.tool_calls:
            result = call_osint_tool(
                tool_call.function.name,
                json.loads(tool_call.function.arguments),
            )
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": result,
            })


# Uso:
# print(chat_with_osint("Analiza el dominio example.com y dime si tiene riesgos"))
```

---

## Opción C — Bridge MCP → OpenAI (mcp-bridge)

Existe la herramienta [`mcp-bridge`](https://github.com/SecureAI-Tools/mcp-bridge) que actúa como proxy entre el protocolo MCP y la API de OpenAI.

```bash
pip install mcp-bridge

mcp-bridge \
  --mcp-server "python -m mcp_server.server --transport stdio" \
  --mcp-cwd /ruta/a/mcp-osint-server \
  --openai-api-key tu-openai-key \
  --model gpt-4o
```

Esto levanta una interfaz de chat en el terminal que conecta GPT-4 con el servidor MCP OSINT.

---

## Seguridad importante

- **Nunca expongas la OSINT API directamente a internet sin autenticación TLS**.
- Usa el header `X-OSINT-API-Key` en todas las llamadas.
- En producción, coloca un proxy NGINX con certificado TLS delante de la API.
- La variable `OSINT_MODE=safe` garantiza que no se ejecutan comandos raw.

### Nginx proxy de ejemplo

```nginx
server {
    listen 443 ssl;
    server_name osint-api.tudominio.com;

    ssl_certificate /etc/letsencrypt/live/osint-api.tudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/osint-api.tudominio.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```
