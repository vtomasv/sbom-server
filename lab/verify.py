#!/usr/bin/env python3
"""Verify real Syft reports, tenant isolation, and mTLS in the Compose lab."""
import argparse
import base64
import json
from pathlib import Path
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from uuid import UUID

LAB = Path(__file__).resolve().parent
OPERATOR = LAB / ".local" / "operator"
MACHINES = json.loads((LAB / "machines.json").read_text(encoding="utf-8"))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


class Lab:
    def __init__(self, url):
        self.url = url.rstrip("/")
        self.without_cert = ssl.create_default_context(cafile=OPERATOR / "ca.crt")
        self.context = ssl.create_default_context(cafile=OPERATOR / "ca.crt")
        self.context.load_cert_chain(OPERATOR / "client.crt", OPERATOR / "client.key")
        self.admin = self.token("admin")

    @staticmethod
    def token(identity):
        return (OPERATOR / f"{identity}.token").read_text(encoding="utf-8").strip()

    def get(self, path, token, query=None, expected=200, json_response=True, basic=False, cert=True):
        url = self.url + path
        if query:
            url += "?" + urlencode(query)
        request = Request(url)
        if token:
            authorization = f"Bearer {token}"
            if basic:
                encoded = base64.b64encode(f"admin:{token}".encode()).decode()
                authorization = f"Basic {encoded}"
            request.add_header("Authorization", authorization)
        try:
            response = urlopen(request, context=self.context if cert else self.without_cert, timeout=5)
        except HTTPError as error:
            response = error
        with response:
            require(response.status == expected, f"{path} respondió {response.status}. Se esperaba {expected}.")
            return json.load(response) if json_response else response.read()

    def wait(self, seconds, after):
        last_error = "sin conexión"
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                items = self.get("/v1/machines", self.admin)["items"]
                machines = {machine["hostname"]: machine for machine in items}
                if set(machines) == set(MACHINES) and all(
                    machines[name]["report_id"] != after.get(name) for name in machines
                ):
                    return machines
                last_error = f"inventarios vistos: {', '.join(sorted(machines))}"
            except (URLError, OSError, RuntimeError) as error:
                last_error = str(error)
            time.sleep(2)
        raise RuntimeError(f"No llegaron los tres inventarios esperados en {seconds} s ({last_error})")

    def verify(self, current):
        require(self.get("/healthz", None) == {"status": "ok"}, "Health check fallido")
        try:
            self.get("/healthz", None, cert=False)
        except (ssl.SSLError, URLError, ConnectionError):
            pass
        else:
            raise RuntimeError("El servidor permitió TLS sin certificado de cliente")
        self.get("/v1/machines", None, expected=401)
        ids = set()
        for hostname, machine in current.items():
            expected = MACHINES[hostname]
            require(UUID(machine["machine_id"]).version == 4, f"UUID inválido para {hostname}")
            ids.add(machine["machine_id"])
            require(machine["client_id"] == expected["client_id"], f"Cliente incorrecto en {hostname}")
            require(machine["os"] == "linux", f"SO incorrecto en {hostname}")
            for field in ("group", "zone", "department", "tags"):
                require(machine["metadata"][field] == expected[field], f"{hostname}: {field} incorrecto")
            report = "/v1/reports/" + machine["report_id"]
            query = {"client_id": machine["client_id"]}
            document = self.get(report + "/sbom", self.admin, query)
            require(document["bomFormat"] == "CycloneDX", f"SBOM inválido para {hostname}")
            components = self.get(report + "/packages", self.admin, {**query, "name": expected["package"]})
            require(any(part["name"] == expected["package"] for part in components["items"]),
                    f"Falta {expected['package']} en el inventario de {hostname}")
        require(len(ids) == len(current), "Hay máquinas con UUID duplicado")
        acme = self.get("/v1/machines", self.token("acme"))
        require({machine["hostname"] for machine in acme["items"]} == {"alpine-ops", "debian-dev"},
                "El token acme no está aislado")
        self.get("/v1/reports/" + current["ubuntu-ops"]["report_id"], self.token("acme"), expected=404)
        group = self.get("/v1/machines", self.admin, {
            "client_id": "acme", "group": "desarrollo", "zone": "valparaiso",
            "department": "ingenieria", "tag": "tipo=desarrollo",
        })
        require([machine["hostname"] for machine in group["items"]] == ["debian-dev"],
                "La consulta por cliente y metadatos no coincide")
        page = self.get("/", self.admin, json_response=False, basic=True)
        require(all(name.encode() in page for name in MACHINES), "Faltan máquinas en el panel")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://localhost:8443")
    parser.add_argument("--wait", type=int, default=180)
    parser.add_argument("--snapshot", type=Path, help="Guardar UUID e ID de informe para comparar tras reinicio.")
    parser.add_argument("--compare", type=Path, help="Esperar un informe posterior y comprobar UUID estable.")
    args = parser.parse_args()
    previous = json.loads(args.compare.read_text(encoding="utf-8")) if args.compare else {}
    lab = Lab(args.url)
    machines = lab.wait(args.wait, {name: item["report_id"] for name, item in previous.items()})
    lab.verify(machines)
    snapshot = {name: {key: item[key] for key in ("report_id", "machine_id")}
                for name, item in machines.items()}
    if args.compare:
        require(set(previous) == set(snapshot) and all(
            snapshot[name]["machine_id"] == item["machine_id"] for name, item in previous.items()
        ), "Cambió el UUID de alguna máquina después del reinicio")
    if args.snapshot:
        args.snapshot.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
    print("Verificados Alpine, Debian y Ubuntu, dos clientes, metadatos, paquetes CycloneDX y mTLS.")
    if args.compare:
        print("Verificada la persistencia del UUID de las tres sondas tras el reinicio.")


if __name__ == "__main__":
    main()
