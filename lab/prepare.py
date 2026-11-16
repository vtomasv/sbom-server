#!/usr/bin/env python3
"""Generate the Docker lab's private configuration once."""
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile

LAB = Path(__file__).resolve().parent
LOCAL = LAB / ".local"
PKI = LAB.parent / "scripts" / "pki.sh"


def write(path, value):
    with path.open("x", encoding="utf-8") as file:
        file.write(value + "\n")


def write_json(path, value):
    write(path, json.dumps(value, ensure_ascii=False, indent=2))


def generate(base):
    machines = json.loads((LAB / "machines.json").read_text(encoding="utf-8"))
    clients = {name: secrets.token_hex(32) for name in sorted({m["client_id"] for m in machines.values()})}
    admin = secrets.token_hex(32)

    def pki(*args):
        subprocess.run([str(PKI), *map(str, args)], check=True)

    ca_dir = base / "ca"
    server = base / "server"
    operator = base / "operator"
    pki("init-ca", ca_dir, "sbom-lab")
    pki("issue-server", ca_dir, server, "DNS:server", "DNS:localhost", "IP:127.0.0.1")
    pki("issue-client", ca_dir, operator, "sbom-lab-operator")
    shutil.copyfile(ca_dir / "ca.crt", server / "ca.crt")
    shutil.copyfile(ca_dir / "ca.crt", operator / "ca.crt")

    write_json(server / "config.json", {
        "listen": ":8443",
        "data_dir": "/var/lib/sbom-server",
        "tls_cert": "/etc/sbom/server.crt",
        "tls_key": "/etc/sbom/server.key",
        "client_ca": "/etc/sbom/ca.crt",
        "admin_token": admin,
        "clients": clients,
    })
    write(operator / "admin.token", admin)
    for name, token in clients.items():
        write(operator / f"{name}.token", token)

    for name, machine in machines.items():
        device = base / name
        pki("issue-client", ca_dir, device, name)
        shutil.copyfile(ca_dir / "ca.crt", device / "ca.crt")
        write(device / "tenant.token", clients[machine["client_id"]])
        write_json(device / "config.json", {
            "server_url": "https://server:8443",
            "client_id": machine["client_id"],
            "token_file": "tenant.token",
            "ca_file": "ca.crt",
            "client_cert_file": "client.crt",
            "client_key_file": "client.key",
            "state_dir": "/var/lib/sbom-probe",
            "scan_path": "/",
            "scan_excludes": [
                "./proc/**", "./sys/**", "./dev/**", "./etc/sbom/**",
                "./var/lib/sbom-probe/**", "./tmp/**", "./run/**",
            ],
            "scan_timeout": "5m",
            "request_timeout": "15s",
            "interval": "30s",
            "metadata": {key: machine[key] for key in ("group", "zone", "department", "tags")},
        })


def main():
    os.umask(0o077)
    if LOCAL.exists():
        if not (LOCAL / "server" / "config.json").is_file():
            raise SystemExit(f"Falta la configuración de servidor dentro de {LOCAL}")
        print(f"Usando la configuración existente en {LOCAL}")
        return
    staging = Path(tempfile.mkdtemp(prefix=".local.tmp-", dir=LAB))
    try:
        generate(staging)
        staging.rename(LOCAL)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    print(f"Configuración del laboratorio en {LOCAL}")


if __name__ == "__main__":
    main()
