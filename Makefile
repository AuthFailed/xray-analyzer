.PHONY: help up down build rebuild logs logs-checker restart serve analyze scan check status shell

.DEFAULT_GOAL := help

# ── Overridable variables ──────────────────────────────────────────────────────
DOMAIN         ?= meduza.io
PORT           ?= 443
PROXY          ?=
DOMAINS        ?=
LIST           ?=
METRICS_PORT   ?= 9090
INTERVAL       ?= 300

# ── Internal helpers ───────────────────────────────────────────────────────────

# Run a one-shot xray-analyzer command (starts xray-checker if needed)
define run
	docker compose run --rm xray-analyzer uv run xray-analyzer $(1)
endef

# ── Targets ────────────────────────────────────────────────────────────────────

help: ## Show available commands
	@printf "\nUsage: make <target> [VAR=value ...]\n\n"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / \
	    {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@printf "\nVariables:\n"
	@printf "  \033[33m%-18s\033[0m Domain to diagnose (default: meduza.io)\n" "DOMAIN"
	@printf "  \033[33m%-18s\033[0m Port for check command (default: 443)\n" "PORT"
	@printf "  \033[33m%-18s\033[0m Proxy URL, e.g. socks5://127.0.0.1:1080\n" "PROXY"
	@printf "  \033[33m%-18s\033[0m Space-separated domains for scan\n" "DOMAINS"
	@printf "  \033[33m%-18s\033[0m Domain list name for scan (whitelist / russia-inside / ...)\n\n" "LIST"

up: ## Start xray-checker + analyzer (continuous watch mode)
	docker compose up -d
	@printf "\n  Logs:    make logs\n  Stop:    make down\n  Restart: make restart\n\n"

down: ## Stop and remove all containers
	docker compose down

build: ## Build the analyzer Docker image
	docker compose build xray-analyzer

rebuild: ## Force-rebuild the image without cache
	docker compose build --no-cache xray-analyzer

logs: ## Tail logs from all services (Ctrl+C to stop)
	docker compose logs -f

logs-checker: ## Tail only xray-checker logs
	docker compose logs -f xray-checker

restart: ## Restart only the analyzer (keeps xray-checker running)
	docker compose restart xray-analyzer

# ── One-shot diagnostic commands (start xray-checker automatically) ──────────

status: ## Show proxy status summary from xray-checker API
	$(call run,status)

serve: ## Start metrics daemon locally  [LIST=...] [DOMAINS="..."] [INTERVAL=300] [PROXY=...]
	$(call run,serve $(DOMAINS) \
	  $(if $(filter-out default,$(LIST)),--list $(LIST),) \
	  $(if $(PROXY),--proxy $(PROXY),) \
	  --interval $(INTERVAL) \
	  --port $(METRICS_PORT))

analyze: ## Run one-shot full proxy analysis (no continuous watch)
	$(call run,analyze)

scan: ## Bulk censorship scan  [DOMAINS="g.com y.com"] [LIST=whitelist] [PROXY=...]
	$(call run,scan $(DOMAINS) $(if $(LIST),--list $(LIST),) $(if $(PROXY),--proxy $(PROXY),))

check: ## Step-by-step domain diagnosis  [DOMAIN=meduza.io] [PORT=443] [PROXY=...]
	$(call run,check $(DOMAIN) --port $(PORT) $(if $(PROXY),--proxy $(PROXY),))

shell: ## Open a shell inside the analyzer container
	docker compose run --rm --entrypoint /bin/sh xray-analyzer
