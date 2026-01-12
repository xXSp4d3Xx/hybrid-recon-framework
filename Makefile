.PHONY: help lint setup docker-build docker-shell

help:
    @echo "Targets:"
    @echo "  lint          Run shellcheck on repository scripts"
    @echo "  setup         Check for required tooling (prints TODOs)"
    @echo "  docker-build  Build the minimal runtime Docker image"
    @echo "  docker-shell  Run a shell inside the built Docker image"

lint:
    @which shellcheck >/dev/null || (echo "shellcheck not installed; install and retry"; exit 1)
    @git ls-files '*.sh' | xargs -r shellcheck -S info

setup:
    @echo "Ensure the following are installed if you plan to run the full framework:"
    @echo "  sudo apt install arp-scan p0f nmap enum4linux smbclient snmp rustscan jq curl"

docker-build:
    docker build -t hybrid-recon:latest .

docker-shell:
    docker run --rm -it --network host hybrid-recon:latest /bin/bash
