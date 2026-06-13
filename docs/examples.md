# Ejemplos de uso — Workflows OSINT

Ejemplos de consulta para cada uno de los **12 workflows**, en lenguaje natural
(lo que le dirías al GPT/asistente) y como payload directo a la API.

## Básico

- **Base URL:** `https://osint-mcp.playingwith.info`
- **Auth:** cabecera `X-OSINT-API-Key: <tu-clave>` en todas las rutas (excepto `/health` y `/privacy`).
- **Ciclo de una tarea:**
  1. `POST /workflow/run` → devuelve `{ "task_id": "...", "status": "running" }`
  2. `GET /tasks/{task_id}?wait=20` → repetir hasta `status: completed | failed | partial`

```bash
# 1) lanzar
TASK=$(curl -s -X POST https://osint-mcp.playingwith.info/workflow/run \
  -H "X-OSINT-API-Key: $OSINT_KEY" -H "Content-Type: application/json" \
  -d '{"workflow":"ip_reputation","target":"8.8.8.8"}' | jq -r .task_id)

# 2) consultar (long-polling 20s)
curl -s "https://osint-mcp.playingwith.info/tasks/$TASK?wait=20" \
  -H "X-OSINT-API-Key: $OSINT_KEY" | jq
```

---

## 1. `domain_recon` — reconocimiento de dominio
> *"Hazme un recon del dominio example.com"*

```json
{ "workflow": "domain_recon", "target": "example.com",
  "options": { "depth": "standard", "passive_only": true } }
```
Sondeo activo (httpx + whatweb): `"passive_only": false`. `depth`: `basic | standard | deep`.

```bash
curl -s -X POST https://osint-mcp.playingwith.info/workflow/run \
  -H "X-OSINT-API-Key: $OSINT_KEY" -H "Content-Type: application/json" \
  -d '{"workflow":"domain_recon","target":"example.com","options":{"depth":"standard","passive_only":true}}'
```

## 2. `ip_reputation` — reputación de IP
> *"¿Qué reputación tiene la IP 8.8.8.8?"*

```json
{ "workflow": "ip_reputation", "target": "8.8.8.8" }
```

## 3. `email_reputation` — análisis de email
> *"Analiza el email test@example.com"*

```json
{ "workflow": "email_reputation", "target": "test@example.com" }
```

## 4. `phone_reputation` — análisis de teléfono
> *"Investiga el número +34600111222"*

```json
{ "workflow": "phone_reputation", "target": "+34600111222",
  "options": { "country_hint": "ES" } }
```

## 5. `person_recon` — investigación de persona
> *"Busca a Jordi Garcia, que trabaja en Seat en Barcelona"*

```json
{ "workflow": "person_recon", "target": "Jordi Garcia",
  "company": "Seat", "location": "Barcelona" }
```
Requiere al menos `company` o `location`; mejor aún `email` o `phone` (campos **top-level**).

## 6. `username_recon` — rastreo de username
> *"Busca el usuario johndoe en redes sociales"*

```json
{ "workflow": "username_recon", "target": "johndoe",
  "options": { "platform_scope": "all" } }
```

## 7. `reverse_image_search` — búsqueda inversa de imagen
> *"Busca esta imagen"* (adjuntando el archivo)

Primero subir el fichero, luego usar el `path` devuelto como `target`:

```bash
# subir por URL pública (recomendado desde ChatGPT)
PATH=$(curl -s -X POST https://osint-mcp.playingwith.info/files/fetch \
  -H "X-OSINT-API-Key: $OSINT_KEY" -H "Content-Type: application/json" \
  -d '{"url":"https://0x0.st/ejemplo.jpg"}' | jq -r .path)
```
```json
{ "workflow": "reverse_image_search", "target": "<path>",
  "options": { "search_scope": "basic" } }
```

## 8. `metadata_analysis` — metadatos de fichero
> *"Extrae los metadatos de este PDF"* (adjuntando el archivo)

```bash
# subir binario directo (curl / clientes API)
PATH=$(curl -s -X POST https://osint-mcp.playingwith.info/files/upload \
  -H "X-OSINT-API-Key: $OSINT_KEY" -F "file=@documento.pdf" | jq -r .path)
```
```json
{ "workflow": "metadata_analysis", "target": "<path>" }
```
Soporta: JPEG, PNG, WebP, GIF, TIFF, BMP, HEIC, PDF, DOC/DOCX, XLS/XLSX, PPT/PPTX, ODT/ODS/ODP (máx. 20 MB).

## 9. `breach_exposure_check` — exposición en brechas
> *"¿El email user@empresa.com aparece en alguna brecha?"*

```json
{ "workflow": "breach_exposure_check", "target": "user@empresa.com",
  "options": { "indicator_type": "auto" } }
```
`indicator_type`: `auto | email | domain | url | hash`.

## 10. `vehicle_recon` — matrícula / VIN español
> *"Datos del vehículo con matrícula 1234BCD"*

```json
{ "workflow": "vehicle_recon", "target": "1234BCD",
  "options": { "country": "ES" } }
```
También acepta VIN de 17 caracteres. Datos del titular suprimidos por defecto (requiere base legal RGPD).

## 11. `secret_scan` — secretos en repo git / fichero
> *"Escanea secretos en https://github.com/usuario/repo"*

```json
{ "workflow": "secret_scan", "target": "https://github.com/usuario/repo",
  "options": { "scan_type": "git" } }
```
Hosts permitidos: github.com, gitlab.com, bitbucket.org, codeberg.org. Clona el repo y escanea **todo el historial** con gitleaks + trufflehog. Secretos siempre redactados.

Para fichero subido: `"target": "<path>"`, `"scan_type": "file"`.

## 12. `company_recon` — due-diligence de entidad (Cala.ai)
> *Overview general:* *"Dame información de Italdesign Barcelona"*

```json
{ "workflow": "company_recon", "target": "Italdesign Barcelona",
  "options": { "entity_type": "company" } }
```

> *Dato concreto:* *"¿Cuántos empleados tiene Italdesign Barcelona?"*

```json
{ "workflow": "company_recon", "target": "Italdesign Barcelona",
  "query": "Italdesign Barcelona.employees" }
```
`query` es campo **top-level** (no va en `options`): para una pregunta concreta usa
dot-notation `<entidad>.<atributo>` (`.employees`, `.revenue`, `.founded`...).
`entity_type`: `auto | company | person | product | law | place | research`.

---

## Generar informe

Tras completar una tarea, puedes formatear el resultado:

```bash
curl -s -X POST "https://osint-mcp.playingwith.info/reports/$TASK" \
  -H "X-OSINT-API-Key: $OSINT_KEY" -H "Content-Type: application/json" \
  -d '{"format":"markdown"}'
```
Formatos: `markdown | json | html`.

## Recomendador de workflow

¿No sabes qué workflow usar? El servidor MCP expone `recommend_osint_workflow`, que
autodetecta el tipo de indicador y sugiere los workflows aplicables.
