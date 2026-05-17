# Requisitos — Servidor MCP OSINT sobre Kali/Docker

## 1. Objetivo

Desarrollar un servidor MCP que permita a agentes IA ejecutar tareas OSINT de forma controlada, trazable y segura, facilitando a analistas y personas no técnicas la obtención de información pública e inteligencia.

El sistema se basará en una imagen Docker de Kali Linux y podrá inspirarse en el enfoque de `MCP-Kali-Server`, pero adaptado a OSINT seguro, con herramientas de alto nivel y sin ejecución arbitraria de comandos por defecto.

También debe permitir complementar el catálogo de herramientas usando fuentes externas como:

```text
https://raw.githubusercontent.com/lliwi/osint-resources/refs/heads/main/data/osintToolsData.json
```

No es necesario importar todas las herramientas del repositorio. El sistema debe seleccionar algunas herramientas representativas por categoría y permitir ampliar el catálogo posteriormente.

---

## 2. Alcance

### Incluido

- Servidor MCP compatible con clientes MCP.
- Backend API ejecutándose en contenedor Docker basado en Kali Linux.
- Catálogo controlado de herramientas OSINT.
- Workflows de alto nivel para usuarios no técnicos.
- Ejecución segura y auditada de herramientas.
- Normalización de resultados en JSON y Markdown.
- Informes OSINT exportables.
- Integración opcional con APIs externas.
- Soporte para análisis de dominios, IPs, emails, teléfonos, usernames, imágenes, metadatos, leaks públicos y reputación.

### Excluido inicialmente

- Explotación activa de vulnerabilidades.
- Fuerza bruta, cracking o intrusión.
- Phishing o ingeniería social activa.
- Acceso a información privada sin autorización.
- Doxxing, stalking o vigilancia abusiva.
- Uso ofensivo de herramientas.
- Persistencia, evasión o malware.

---

## 3. Arquitectura propuesta

```text
[Cliente MCP / Agente IA]
          |
          | MCP
          v
[Servidor MCP OSINT]
          |
          | HTTP / IPC
          v
[API OSINT Controller]
          |
          v
[Docker Kali OSINT Sandbox]
          |
          +--> [Herramientas CLI OSINT]
          +--> [Conectores API externas]
          +--> [Catálogo osintToolsData.json]
          +--> [Parsers / Normalizadores]
          +--> [Evidencias / Logs / Informes]
```

---

## 4. Componentes principales

### 4.1 Servidor MCP

Debe exponer herramientas MCP de alto nivel, por ejemplo:

- `domain_recon`
- `ip_reputation`
- `email_reputation`
- `phone_reputation`
- `username_recon`
- `reverse_image_search`
- `metadata_analysis`
- `breach_exposure_check`
- `social_profile_discovery`
- `run_osint_workflow`
- `get_task_result`
- `export_report`
- `list_osint_tools`

No debe exponer directamente una función pública tipo `run_raw_command`, salvo en modo laboratorio.

### 4.2 API OSINT Controller

Responsable de:

- Validar entradas.
- Traducir peticiones MCP a comandos o APIs seguras.
- Ejecutar herramientas dentro del contenedor.
- Aplicar allowlist de comandos.
- Gestionar timeouts.
- Controlar concurrencia.
- Parsear resultados.
- Guardar evidencias.
- Generar logs de auditoría.
- Normalizar la salida para agentes IA.

### 4.3 Contenedor Kali OSINT

Imagen Docker basada en Kali Linux con herramientas OSINT instaladas.

Debe ejecutarse con:

- Sistema de archivos limitado.
- Red controlada.
- Límites de CPU, RAM y tiempo.
- Directorio temporal por tarea.

---

## 5. Catálogo de herramientas OSINT

El sistema debe tener un catálogo interno de herramientas, ampliable desde fuentes como `osintToolsData.json`.

### Requisitos del catálogo

Cada herramienta debe tener metadatos:

```json
{
  "name": "Sherlock",
  "category": "username",
  "type": "cli",
  "source": "local",
  "requires_api_key": false,
  "enabled": true,
  "risk_level": "low",
  "inputs": ["username"],
  "outputs": ["profiles", "urls", "confidence"]
}
```

### Campos requeridos

- `name`
- `category`
- `type`: `cli`, `api`, `web`, `manual`
- `enabled`
- `requires_api_key`
- `risk_level`
- `description`
- `inputs`
- `outputs`
- `parser`
- `timeout`
- `allowed_args`

---

## 6. Categorías y herramientas representativas

No se pretende instalar todas las herramientas posibles. La primera versión debe incluir una selección equilibrada por categoría.

### 6.1 Dominios, DNS y superficie web

Objetivo: obtener inteligencia pública sobre dominios, subdominios, DNS, certificados y tecnologías web.

Herramientas recomendadas:

- `whois`
- `dig`
- `subfinder`
- `amass`
- `theHarvester`
- `httpx`
- `whatweb`
- `waybackurls`

APIs opcionales:

- SecurityTrails
- Shodan
- Censys
- VirusTotal
- URLScan

Workflow MCP:

```text
domain_recon(domain, depth, passive_only)
```

Salida esperada:

- WHOIS.
- Registros DNS.
- Subdominios.
- Certificados relacionados.
- Tecnologías detectadas.
- URLs históricas.
- Riesgos observados.

---

### 6.2 IP, ASN y reputación

Objetivo: analizar IPs públicas, ASN, reputación y abuso reportado.

Herramientas recomendadas:

- `whois`
- `dig`
- `nmap`, solo en modo autorizado y limitado
- `ipinfo`, vía API o CLI
- `abuseipdb`, vía API
- `greynoise`, vía API
- `shodan`, vía API

Workflow MCP:

```text
ip_reputation(ip_address)
```

Salida esperada:

```json
{
  "ip": "8.8.8.8",
  "asn": "string",
  "organization": "string",
  "country": "string",
  "reputation": "low|medium|high|unknown",
  "abuse_reports": [],
  "open_services_from_passive_sources": [],
  "sources": []
}
```

---

### 6.3 Email intelligence y reputación

Objetivo: analizar emails usando fuentes públicas, señales de exposición y reputación.

Herramientas recomendadas:

- `holehe`
- `theHarvester`
- EmailRep
- Have I Been Pwned
- Hunter.io
- Intelligence X, opcional
- LeakCheck, opcional

Workflow MCP:

```text
email_reputation(email)
```

Salida esperada:

- Dominio del email.
- MX records.
- Exposición en brechas, si está permitido.
- Reputación.
- Señales de presencia en servicios.
- Fuentes consultadas.
- Confianza del resultado.

Controles obligatorios:

- No intentar login.
- No enviar emails.
- No hacer recuperación de contraseña.
- No mostrar contraseñas filtradas.
- Enmascarar información sensible.

---

### 6.4 Teléfono y reputación

Objetivo: obtener información pública y reputación de números telefónicos.

Herramientas recomendadas:

- `phoneinfoga`
- Numverify
- Twilio Lookup
- Google dorks controlados
- Directorios públicos permitidos según jurisdicción

Workflow MCP:

```text
phone_reputation(phone_number, country_hint)
```

Salida esperada:

```json
{
  "phone_number": "+34123456789",
  "valid": true,
  "country": "ES",
  "carrier": "unknown",
  "line_type": "mobile|fixed|voip|unknown",
  "spam_signals": [],
  "public_mentions": [],
  "confidence": "low|medium|high"
}
```

Controles obligatorios:

- No usar para acoso, stalking o doxxing.
- No automatizar scraping agresivo.
- Respetar privacidad y jurisdicción.
- Mostrar advertencia cuando haya datos personales.

---

### 6.5 Usernames e identidad digital

Objetivo: localizar perfiles públicos asociados a un alias.

Herramientas recomendadas:

- `sherlock`
- `maigret`
- `whatsmyname`
- `socialscan`

Workflow MCP:

```text
username_recon(username, platform_scope)
```

Salida esperada:

- Plataformas encontradas.
- URLs.
- Estado: encontrado, no encontrado, incierto.
- Tipo de plataforma.
- Nivel de confianza.

---

### 6.6 Búsqueda inversa de imágenes

Objetivo: identificar origen, reutilización, copias, contexto o manipulación potencial de imágenes.

Herramientas recomendadas:

- TinEye
- Google Lens, como enlace/manual si no existe API autorizada
- Bing Visual Search
- Yandex Images
- ExifTool
- FotoForensics, uso manual
- InVID / WeVerify

Workflow MCP:

```text
reverse_image_search(image_path, search_scope)
```

Salida esperada:

```json
{
  "image_hash": "string",
  "metadata": {},
  "reverse_matches": [
    {
      "source": "TinEye",
      "url": "https://example.com",
      "title": "string",
      "first_seen": "unknown",
      "confidence": "low|medium|high"
    }
  ],
  "visual_similarity_notes": [],
  "manipulation_indicators": [],
  "recommendations": []
}
```

Controles obligatorios:

- No hacer reconocimiento facial sensible por defecto.
- Separar búsqueda inversa de identificación biométrica.
- No identificar personas privadas sin base legal.
- Guardar solo evidencias necesarias.

---

### 6.7 Metadatos de imágenes y documentos

Objetivo: extraer y analizar metadatos de archivos.

Herramientas recomendadas:

- `exiftool`
- `mat2`
- `pdfinfo`
- `file`
- `strings`

Workflow MCP:

```text
metadata_analysis(file_path)
```

Salida esperada:

- Tipo de archivo.
- Hash SHA256.
- Fechas.
- Software de creación.
- Autor, si existe.
- Coordenadas GPS, si existen.
- Riesgos de privacidad.
- Versión sanitizada opcional.

---

### 6.8 Leaks, brechas y pastes públicos

Objetivo: detectar exposición pública de emails, dominios o secretos en fuentes permitidas.

Herramientas recomendadas:

- Have I Been Pwned
- Intelligence X
- LeakCheck
- GitHub Search
- `gitleaks`
- `trufflehog`

Workflow MCP:

```text
breach_exposure_check(indicator, indicator_type)
```

Salida esperada:

- Brechas conocidas.
- Apariciones públicas.
- Repositorios con posibles secretos.
- Fecha de exposición.
- Fuente.
- Riesgo.
- Recomendaciones.

Controles obligatorios:

- No mostrar contraseñas completas.
- No descargar dumps.
- No facilitar abuso de credenciales.
- Enmascarar secretos.
- Registrar base legal cuando aplique.

---

### 6.9 Redes sociales y SOCMINT

Objetivo: descubrir perfiles públicos y contexto de entidades.

Herramientas recomendadas:

- `sherlock`
- `maigret`
- `whatsmyname`
- Social Analyzer
- Motores de búsqueda con dorks controlados

Workflow MCP:

```text
social_profile_discovery(entity, entity_type)
```

Controles obligatorios:

- Solo información pública.
- Sin interacción con perfiles.
- Sin scraping agresivo.
- Sin vigilancia continua sin autorización.

---

### 6.10 Geolocalización y mapas

Objetivo: ayudar en análisis geográfico usando fuentes abiertas.

Herramientas recomendadas:

- OpenStreetMap
- Overpass Turbo
- Mapillary
- SunCalc
- ExifTool
- Geohints

Workflow MCP:

```text
geolocation_recon(query_or_coordinates)
```

Salida esperada:

- Coordenadas.
- Lugares candidatos.
- Evidencias.
- Fuentes.
- Nivel de confianza.
- Notas de incertidumbre.

---

### 6.11 Criptomonedas y wallets

Objetivo: analizar direcciones públicas de blockchain.

Herramientas recomendadas:

- Blockchair
- Etherscan
- Blockchain.com Explorer
- Chainabuse
- WalletExplorer

Workflow MCP:

```text
crypto_wallet_recon(wallet_address, blockchain)
```

Salida esperada:

- Blockchain.
- Balance público.
- Transacciones relevantes.
- Etiquetas públicas.
- Abuso reportado.
- Fuentes.

---

### 6.12 Verificación de noticias, URLs y contenido

Objetivo: validar contexto, cronología, fuentes y reputación de URLs.

Herramientas recomendadas:

- Wayback Machine
- Archive.today
- URLScan
- VirusTotal
- Google Fact Check Tools
- GDELT
- InVID / WeVerify

Workflow MCP:

```text
news_media_verification(claim_or_url)
```

Salida esperada:

- Primera aparición conocida.
- Capturas archivadas.
- Reputación de URL.
- Fuentes primarias y secundarias.
- Contradicciones.
- Nivel de confianza.

---

## 7. Herramientas MCP requeridas

### 7.1 `list_osint_tools`

Lista herramientas disponibles.

Entrada:

```json
{
  "category": "email|phone|image|domain|ip|username|social|metadata|leaks|geo|crypto|all",
  "enabled_only": true
}
```

### 7.2 `recommend_osint_workflow`

Recomienda workflows según el indicador.

Entrada:

```json
{
  "indicator": "user@example.com"
}
```

Salida:

```json
{
  "detected_type": "email",
  "recommended_workflows": [
    "email_reputation",
    "breach_exposure_check"
  ],
  "safety_notes": []
}
```

### 7.3 `run_osint_workflow`

Ejecuta un workflow completo.

Entrada:

```json
{
  "workflow": "email_reputation",
  "target": "user@example.com",
  "mode": "safe",
  "output_format": "json"
}
```

### 7.4 `export_report`

Genera un informe.

Entrada:

```json
{
  "task_id": "string",
  "format": "markdown|json|html|pdf"
}
```

---

## 8. Normalización de resultados

Todas las herramientas deben devolver una estructura común:

```json
{
  "task_id": "string",
  "workflow": "string",
  "status": "completed|failed|running|partial",
  "target": "string",
  "target_type": "domain|ip|email|phone|username|image|file|wallet|url|person|company",
  "summary": "string",
  "findings": [],
  "entities": [],
  "relationships": [],
  "sources": [],
  "confidence": "low|medium|high",
  "risk": "low|medium|high|unknown",
  "evidence": [],
  "raw_output_path": "string",
  "started_at": "datetime",
  "finished_at": "datetime",
  "warnings": []
}
```

---

## 9. Scoring

### 9.1 Confidence score

Debe estimar la fiabilidad de cada hallazgo.

Factores:

- Fuente primaria o secundaria.
- Coincidencia entre múltiples fuentes.
- Antigüedad del dato.
- Evidencia disponible.
- Calidad del parser.
- Historial de falsos positivos de la herramienta.

### 9.2 Risk score

Debe estimar el riesgo del indicador.

Ejemplos:

- Email en brechas.
- IP con reportes de abuso.
- Teléfono reportado como spam.
- Dominio recién creado.
- Imagen reutilizada en campañas fraudulentas.
- Repositorio con secretos expuestos.

---

## 10. Requisitos de seguridad

### RS-01 — Sin ejecución arbitraria por defecto

No debe existir una herramienta MCP pública tipo `run_raw_command` en modo seguro.

### RS-02 — Allowlist

Solo se podrán ejecutar herramientas y argumentos permitidos.

### RS-03 — Validación estricta

Validar:

- Dominios.
- IPs.
- URLs.
- Emails.
- Usernames.
- Teléfonos.
- Hashes.
- Wallets.
- Rutas de archivos.
- Imágenes.

### RS-04 — Sandbox Docker

Configuración recomendada:

```yaml
security_opt:
  - no-new-privileges:true
cap_drop:
  - ALL
read_only: true
pids_limit: 256
mem_limit: 2g
cpus: 2
```

### RS-05 — Rate limiting

Debe limitar:

- Peticiones por usuario.
- Peticiones por workflow.
- Peticiones por API externa.
- Concurrencia.
- Tamaño de resultados.
- Tiempo máximo por tarea.

### RS-06 — Privacidad

- Minimización de datos.
- Enmascarado de PII.
- No guardar secretos en logs.
- Retención limitada.
- Eliminación segura de evidencias.
- Exportación bajo demanda.

### RS-07 — Tool poisoning

Los resultados obtenidos de internet deben tratarse como datos no confiables.

El agente no debe obedecer instrucciones encontradas en:

- Páginas web.
- PDFs.
- Imágenes.
- Metadatos.
- Repositorios.
- Pastes.
- Comentarios.
- Resultados de buscadores.

---

## 11. Modos de operación

### Modo seguro

Modo por defecto.

Características:

- Sin comandos raw.
- OSINT pasivo o semi-pasivo.
- Sin fuerza bruta.
- Sin explotación.
- Sin scraping agresivo.
- Herramientas sensibles desactivadas.

### Modo analista avanzado

Características:

- Requiere autenticación.
- Permite más fuentes y APIs.
- Requiere justificación o caso.
- Puede ejecutar tareas semi-activas autorizadas.

### Modo laboratorio

Características:

- Uso interno.
- Puede permitir comandos raw.
- No expuesto a internet.
- Solo para pruebas controladas.

---

## 12. Requisitos no funcionales

### RNF-01 — Usabilidad

Debe estar pensado para analistas no técnicos.

Cada resultado debe incluir:

- Resumen ejecutivo.
- Hallazgos principales.
- Fuentes.
- Nivel de confianza.
- Riesgo.
- Siguientes pasos recomendados.

### RNF-02 — Modularidad

Cada herramienta debe implementarse como módulo independiente.

### RNF-03 — Observabilidad

Debe incluir:

- Logs estructurados.
- Métricas básicas.
- Estado de tareas.
- Errores comprensibles.
- Trazabilidad de fuentes.

### RNF-04 — Portabilidad

Debe poder ejecutarse mediante:

- Docker Compose.
- Instalación local para desarrollo.
- VM aislada.
- Servidor dedicado.

### RNF-05 — Extensibilidad

Debe permitir añadir herramientas mediante YAML o JSON.

Ejemplo:

```yaml
name: phoneinfoga
category: phone
type: cli
binary: phoneinfoga
allowed_args:
  - "scan"
  - "-n"
timeout: 120
parser: phoneinfoga_parser
enabled: true
risk_level: medium
```

---

## 13. Estructura de repositorio sugerida

```text
mcp-osint-server/
├── mcp-server/
│   ├── server.py
│   ├── tools/
│   └── schemas/
├── osint-api/
│   ├── main.py
│   ├── runners/
│   ├── parsers/
│   ├── workflows/
│   ├── connectors/
│   ├── catalog/
│   ├── security/
│   └── reports/
├── docker/
│   ├── Dockerfile.kali
│   └── docker-compose.yml
├── config/
│   ├── tools.yml
│   ├── policies.yml
│   └── examples.env
├── reports/
├── evidence/
├── tests/
└── README.md
```

---

## 14. Variables de entorno

Ejemplo:

```env
OSINT_MODE=safe
LOG_LEVEL=INFO
MAX_TASK_TIME_SECONDS=300
MAX_CONCURRENT_TASKS=3

SHODAN_API_KEY=
CENSYS_API_ID=
CENSYS_API_SECRET=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
HIBP_API_KEY=
SECURITYTRAILS_API_KEY=
EMAILREP_API_KEY=
TWILIO_ACCOUNT_SID=
TWILIO_AUTH_TOKEN=
```

---

## 15. Informes

El sistema debe poder generar informes en:

- Markdown.
- JSON.
- HTML.
- PDF opcional.

Estructura de informe:

```text
1. Resumen ejecutivo
2. Objetivo analizado
3. Metodología
4. Herramientas usadas
5. Hallazgos
6. Evidencias
7. Nivel de confianza
8. Riesgo
9. Limitaciones
10. Recomendaciones
11. Anexos técnicos
```

---


## 16. Criterios de aceptación

- El servidor MCP se conecta correctamente desde al menos un cliente MCP.
- El contenedor Kali ejecuta herramientas OSINT sin privilegios elevados.
- Existen workflows funcionales para:
  - Dominio.
  - IP.
  - Email.
  - Teléfono.
  - Username.
  - Imagen.
  - Metadatos.
  - Leaks.
- No existe ejecución raw en modo seguro.
- Todas las tareas generan `task_id`.
- Todas las salidas se normalizan.
- Los resultados incluyen fuentes y confianza.
- Se puede generar informe Markdown.
- Las entradas maliciosas son rechazadas.
- Los timeouts funcionan.
- Las API keys no aparecen en logs ni outputs.
- Se puede listar el catálogo de herramientas.
- Se puede importar una selección desde `osintToolsData.json`.

---

## 17. Roadmap

### Fase 1 — MVP

- Servidor MCP básico.
- Docker Kali.
- Catálogo inicial de herramientas.
- Workflows:
  - Dominio.
  - Email.
  - Teléfono.
  - Username.
  - Imagen.
  - IP.
- Output JSON/Markdown.
- Allowlist de comandos.

### Fase 2 — Seguridad y UX

- Autenticación.
- Políticas por rol.
- Informes enriquecidos.
- Auditoría avanzada.
- Cola de tareas.
- Gestión de evidencias.

### Fase 3 — Inteligencia avanzada

- Correlación de entidades.
- Grafo OSINT.
- Scoring de confianza.
- Scoring de riesgo.
- Integración con APIs externas.
- Exportación STIX/TAXII opcional.

---

## 18. Referencias

- MCP-Kali-Server: `https://github.com/Wh0am123/MCP-Kali-Server`
- Catálogo OSINT Resources: `https://raw.githubusercontent.com/lliwi/osint-resources/refs/heads/main/data/osintToolsData.json`
