SHELL := /bin/bash
STACK_ROOT ?= /opt/ai-stack

.PHONY: lint apply verify 	up-core up-observability up-knowledge up-rnd up-ai 	down-core down-observability down-knowledge down-rnd down-ai

lint:
	ansible-lint -v playbooks/site.yml || true

apply:
	ansible-playbook -i inventory/localhost.yml playbooks/site.yml

verify:
	bash scripts/verify/verify_all.sh

up-core:
	cd $(STACK_ROOT)/core && docker compose up -d

down-core:
	cd $(STACK_ROOT)/core && docker compose down

up-observability:
	cd $(STACK_ROOT)/observability && docker compose up -d

down-observability:
	cd $(STACK_ROOT)/observability && docker compose down

up-knowledge:
	cd $(STACK_ROOT)/knowledge && docker compose up -d

down-knowledge:
	cd $(STACK_ROOT)/knowledge && docker compose down

up-rnd:
	cd $(STACK_ROOT)/rnd && docker compose up -d

down-rnd:
	cd $(STACK_ROOT)/rnd && docker compose down

up-ai:
	cd $(STACK_ROOT)/ai && docker compose up -d

down-ai:
	cd $(STACK_ROOT)/ai && docker compose down
