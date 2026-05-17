#!/usr/bin/env bash
# Arrancar el cliente OSINT
# Uso: ./run.sh [proveedor] [modelo] [args...]
# Ejemplos:
#   ./run.sh                              # Ollama, modelo por defecto
#   ./run.sh deepseek                     # DeepSeek-V3
#   ./run.sh deepseek deepseek-reasoner   # DeepSeek-R1
#   ./run.sh openai gpt-4o-mini           # OpenAI
#   ./run.sh ollama qwen3.5:2b            # Ollama modelo específico
#   ./run.sh --check                      # verificar servicios

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$SCRIPT_DIR/.venv"
ENV_FILE="$SCRIPT_DIR/../config/.env"

# Cargar variables de entorno
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

# Crear venv si no existe
if [[ ! -f "$VENV/bin/python" ]]; then
  echo "Creando entorno virtual del cliente..."
  python3 -m venv "$VENV"
  "$VENV/bin/pip" install -q --upgrade pip
  "$VENV/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"
  echo ""
fi

# Parsear argumentos: primer arg no-flag es proveedor, segundo es modelo
PROVIDER=""
MODEL=""
EXTRA=()

for arg in "$@"; do
  case "$arg" in
    --*|-*)
      EXTRA+=("$arg")
      ;;
    ollama|deepseek|openai)
      if [[ -z "$PROVIDER" ]]; then
        PROVIDER="$arg"
      else
        MODEL="$arg"
      fi
      ;;
    *)
      if [[ -z "$PROVIDER" ]]; then
        # Podría ser un modelo de Ollama directamente
        MODEL="$arg"
      else
        MODEL="$arg"
      fi
      ;;
  esac
done

CMD=("$VENV/bin/python" "$SCRIPT_DIR/osint_client.py")
[[ -n "$PROVIDER" ]] && CMD+=("-p" "$PROVIDER")
[[ -n "$MODEL" ]]    && CMD+=("-m" "$MODEL")
CMD+=("${EXTRA[@]+"${EXTRA[@]}"}")

exec "${CMD[@]}"
