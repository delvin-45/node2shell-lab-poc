PYTHON ?= python
PLATFORM ?= linux/amd64
REF_IMAGE ?= node2shell-lab:ref-24.22.0
WP_IMAGE ?= node2shell-lab:wp-24.22.0
UNFURL_IMAGE ?= node2shell-lab:unfurl-24.22.0
REF_PATCHED ?= node2shell-lab:ref-24.22.1
WP_PATCHED ?= node2shell-lab:wp-24.22.1
UNFURL_PATCHED ?= node2shell-lab:unfurl-24.22.1

.DEFAULT_GOAL := help

.PHONY: help self-test build-a build-b build-ref build-patched lab-a lab-a-rce lab-b lab-ref poc-a poc-a-rce poc-b poc-ref patched verify demo clean

help:
	@echo Node2Shell Lab
	@echo   make lab-a       start the CMS on 127.0.0.1:3000 (DoS shape)
	@echo   make lab-a-rce   start the CMS with the restart supervisor
	@echo   make lab-b       start the unfurl API on 127.0.0.1:3000
	@echo   make lab-ref     start the reference Express lab with supervisor
	@echo   make poc-a       run the CMS DoS check
	@echo   make poc-a-rce   run the CMS exact-profile RCE attempt
	@echo   make poc-b       run the unfurl DoS check
	@echo   make poc-ref     run the reference RCE attempt
	@echo   make patched     build all three patched controls
	@echo   make verify      clean, build, run deterministic checks and controls
	@echo   make demo        render the passive scan demo with VHS
	@echo   make clean       remove lab containers, images, and Python cache

self-test:
	$(PYTHON) poc.py --self-test

build-a:
	docker build --pull --platform $(PLATFORM) -t $(WP_IMAGE) -f lab/wp-cms/Dockerfile lab/wp-cms

build-b:
	docker build --pull --platform $(PLATFORM) -t $(UNFURL_IMAGE) -f lab/unfurl-api/Dockerfile lab/unfurl-api

build-ref:
	docker build --pull --platform $(PLATFORM) -t $(REF_IMAGE) -f lab/reference-express/Dockerfile lab/reference-express

build-patched:
	docker build --pull --platform $(PLATFORM) -t $(REF_PATCHED) -f lab/reference-express/Dockerfile.patched lab/reference-express
	docker build --pull --platform $(PLATFORM) -t $(WP_PATCHED) -f lab/wp-cms/Dockerfile.patched lab/wp-cms
	docker build --pull --platform $(PLATFORM) -t $(UNFURL_PATCHED) -f lab/unfurl-api/Dockerfile.patched lab/unfurl-api

lab-a: build-a
	-docker rm -f n2s-wp
	docker run --rm -d --name n2s-wp -p 127.0.0.1:3000:3000 $(WP_IMAGE)
	$(PYTHON) -c "import time; time.sleep(2)"

lab-a-rce: build-a
	-docker rm -f n2s-wp
	docker run --rm -d --name n2s-wp -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 -p 127.0.0.1:3000:3000 $(WP_IMAGE)
	$(PYTHON) -c "import time; time.sleep(2)"

lab-b: build-b
	-docker rm -f n2s-unfurl
	docker run --rm -d --name n2s-unfurl -p 127.0.0.1:3000:3000 $(UNFURL_IMAGE)
	$(PYTHON) -c "import time; time.sleep(2)"

lab-ref: build-ref
	-docker rm -f n2s-ref
	docker run --rm -d --name n2s-ref -e N2S_SUPERVISE=1 -e UV_THREADPOOL_SIZE=1 -p 127.0.0.1:3000:3000 $(REF_IMAGE)
	$(PYTHON) -c "import time; time.sleep(2)"

poc-a:
	$(PYTHON) -u poc.py --profile n2s-wp-24.22.0-x86_64 --mode dos --timeout 30

poc-a-rce:
	$(PYTHON) -u poc.py --profile n2s-wp-24.22.0-x86_64 --mode rce --timeout 30

poc-b:
	$(PYTHON) -u poc.py --profile n2s-unfurl-24.22.0-x86_64 --mode dos --timeout 30

poc-ref:
	$(PYTHON) -u poc.py --profile n2s-ref-express-24.22.0-x86_64 --mode rce --timeout 30

patched: build-patched

verify: clean
	$(PYTHON) poc.py --self-test
	$(MAKE) build-ref
	$(MAKE) build-a
	$(MAKE) build-b
	$(MAKE) build-patched
	$(MAKE) lab-a
	$(PYTHON) -u poc.py --profile n2s-wp-24.22.0-x86_64 --mode dos --timeout 30
	-docker rm -f n2s-wp
	$(MAKE) lab-b
	$(PYTHON) -u poc.py --profile n2s-unfurl-24.22.0-x86_64 --mode dos --timeout 30
	-docker rm -f n2s-unfurl
	-docker run --rm -d --name n2s-patched-ref -p 127.0.0.1:3000:3000 $(REF_PATCHED)
	$(PYTHON) -c "import time; time.sleep(2)"
	$(PYTHON) -u poc.py --profile n2s-ref-express-patched-24.22.1-x86_64 --timeout 30
	-docker rm -f n2s-patched-ref
	-docker run --rm -d --name n2s-patched-wp -p 127.0.0.1:3000:3000 $(WP_PATCHED)
	$(PYTHON) -c "import time; time.sleep(2)"
	$(PYTHON) -u poc.py --profile n2s-wp-patched-24.22.1-x86_64 --timeout 30
	-docker rm -f n2s-patched-wp
	-docker run --rm -d --name n2s-patched-unfurl -p 127.0.0.1:3000:3000 $(UNFURL_PATCHED)
	$(PYTHON) -c "import time; time.sleep(2)"
	$(PYTHON) -u poc.py --profile n2s-unfurl-patched-24.22.1-x86_64 --timeout 30
	-docker rm -f n2s-patched-unfurl
	@echo VERIFY PASS: self-test, DoS labs, and patched controls

demo:
	docker compose -f compose.scan.yaml up -d --build
	vhs docs/demo/scan.tape
	-docker compose -f compose.scan.yaml down -v --remove-orphans
	@echo DEMO PASS: docs/demo/scan.gif

clean:
	-docker rm -f n2s-wp n2s-unfurl n2s-ref n2s-patched-ref n2s-patched-wp n2s-patched-unfurl
	-docker compose -f compose.scan.yaml down -v --remove-orphans
	-docker image rm $(REF_IMAGE) $(WP_IMAGE) $(UNFURL_IMAGE) $(REF_PATCHED) $(WP_PATCHED) $(UNFURL_PATCHED)
	-docker image rm node2shell-lab-scan-wp-cms node2shell-lab-scan-unfurl-api node2shell-lab-scan-reference-express
	-$(PYTHON) -c "import shutil; shutil.rmtree('__pycache__', ignore_errors=True)"
	@echo CLEAN PASS
