# Servidor SBOM

Recibe inventarios CycloneDX JSON de sondas Syft por HTTPS. El panel permite filtrar máquinas por cliente, grupo, zona, departamento y etiquetas, consultar los componentes del último inventario y descargar el documento completo. La API también da acceso al historial de inventarios.

Un token de cliente autoriza el envío y la consulta de los inventarios de ese cliente. El token de administrador permite consultar todos los clientes. Si configuras TLS mutuo, todas las conexiones también requieren un certificado cliente firmado por una CA autorizada.

## Iniciar el servidor

Para desplegar con certificados propios, usa un certificado de servidor cuyo SAN incluya el nombre DNS o la IP que usarán las sondas. Distribuye el certificado público de la CA a las sondas y navegadores. Para una prueba local de HTTPS sin TLS mutuo puedes usar un certificado de servidor autofirmado:

```sh
umask 077
mkdir -p secrets runtime
openssl req -x509 -newkey rsa:3072 -nodes -days 30 \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout secrets/server.key -out secrets/server.crt
cp config.example.json config.json
openssl rand -hex 32
```

Genera un token distinto para el administrador y para cada cliente. Completa `config.json` con los tokens y las rutas adecuadas. Los valores de `listen` y `data_dir` de la tabla son los predeterminados.

| Campo | Valor |
| --- | --- |
| `listen` | `:8443`. Usa `127.0.0.1:8443` si el servidor debe escuchar solo en la máquina local. |
| `data_dir` | `/var/lib/sbom-server`. Usa `./runtime` para la prueba nativa. |
| `tls_cert` | Archivo PEM del certificado de servidor y su cadena. Usa `./secrets/server.crt` para la prueba nativa. |
| `tls_key` | Clave privada PEM del certificado de servidor. Usa `./secrets/server.key` para la prueba nativa. |
| `client_ca` | Archivo PEM con las CA autorizadas para firmar certificados cliente. Usa `""` en la prueba sin TLS mutuo. |
| `admin_token` | Token de lectura para todos los clientes. |
| `clients` | Mapa de identificadores a tokens. Cada identificador comienza con un alfanumérico ASCII y puede contener hasta 64 caracteres, incluidos `-`, `_` y `.`. `admin` está reservado. |
| `max_report_bytes` | Tamaño máximo del reporte completo. Predeterminado `67108864` (64 MiB), rango de 1 KiB a 128 MiB. |

Los tokens admiten entre 24 y 512 bytes sin espacios ni caracteres de control. Protege `config.json` y `server.key` con permisos del sistema de archivos. Reinicia el proceso tras modificar la configuración o los certificados.

### Ejecución nativa

Con Go 1.27, desde este repositorio:

```sh
go run ./cmd/sbom-server -config ./config.json
curl --cacert ./secrets/server.crt https://localhost:8443/healthz
```

### Ejecución en Docker

Para Docker, configura `listen` como `:8443`, usa `/var/lib/sbom-server` para el volumen y referencia los certificados mediante `/secrets`. Entrega la configuración en `/etc/sbom/config.json`. El proceso dentro de la imagen usa UID y GID `65532`. Dale acceso de lectura a ese usuario para los archivos montados y acceso de escritura al volumen de datos.

```sh
docker build --tag sbom-server:local .
docker run --rm --name sbom-server -p 127.0.0.1:8443:8443 \
  --mount type=bind,source="$PWD/config.json",target=/etc/sbom/config.json,readonly \
  --mount type=bind,source="$PWD/secrets",target=/secrets,readonly \
  --mount type=volume,source=sbom-reports,target=/var/lib/sbom-server \
  sbom-server:local
```

Los reportes se guardan en el volumen de forma persistente. Cada cliente tiene su espacio de almacenamiento y cada reporte contiene un manifiesto con el inventario original. Ejecuta una instancia del servidor por volumen de datos. Para una copia coherente del historial, toma un snapshot del volumen o detén el proceso antes de copiarlo. El historial se conserva hasta que el operador lo archive o elimine del almacenamiento con el servidor detenido.

## Consultar el inventario

Abre `https://localhost:8443/` en un navegador que confíe en el certificado de servidor. Ingresa `admin` o el identificador del cliente como usuario y el token correspondiente como contraseña. Con TLS mutuo, importa además en el navegador un certificado de cliente aceptado por `client_ca`.

Por API, envía `Authorization: Bearer <token>`. Con TLS mutuo, añade las opciones `--cert <cliente.crt> --key <cliente.key>` a los comandos de `curl`, incluida la consulta de `/healthz`.

```sh
curl --cacert ./secrets/server.crt \
  --header "Authorization: Bearer $SBOM_ADMIN_TOKEN" \
  'https://localhost:8443/v1/machines?client_id=cliente-a&tag=tipo%3Ddesarrollo'
```

| Método y ruta | Respuesta |
| --- | --- |
| `GET /healthz` | Estado del proceso. |
| `POST /v1/reports` | Registra un reporte usando el token de su cliente. |
| `GET /v1/machines` | Un registro por cliente y máquina, con el reporte más reciente por fecha de recolección. |
| `GET /v1/reports` | Historial de reportes. |
| `GET /v1/reports/{report_id}` | Metadatos de un reporte. |
| `GET /v1/reports/{report_id}/packages` | Componentes CycloneDX, incluidos los anidados. `name` busca coincidencias parciales. |
| `GET /v1/reports/{report_id}/sbom` | Descarga el CycloneDX JSON original. |

`/v1/machines` y `/v1/reports` aceptan `client_id`, `machine_id`, `group`, `zone`, `department` y uno o más filtros `tag=clave%3Dvalor`. Los filtros de máquinas se aplican después de elegir el reporte más reciente. Las listas devuelven `items`, `total`, `limit` y `offset`. `limit` vale 100 por defecto y admite hasta 500. En las rutas de detalle puedes incluir `?client_id=<id>` para seleccionar el cliente si el mismo `report_id` aparece en dos clientes.

## Formato de envío

El encabezado `Content-Type` debe ser `application/json`. `client_id` debe coincidir con el token. Los identificadores de máquina y reporte son UUID en minúsculas. `collected_at` usa RFC 3339. `hostname`, `os`, `arch` y `source` son obligatorios. Grupo, zona y departamento admiten hasta 128 bytes. Puedes registrar hasta 32 etiquetas de texto. Sus claves siguen las mismas reglas que los identificadores de cliente y sus valores tienen hasta 256 bytes.

```json
{
  "schema_version": 1,
  "report_id": "7ba124f0-98f7-48d8-a1da-3604d171277a",
  "machine_id": "5f99021c-bd52-49b2-89ee-2eeba1bb7704",
  "client_id": "cliente-a",
  "collected_at": "2026-11-16T20:00:00Z",
  "hostname": "equipo-01",
  "os": "linux",
  "arch": "amd64",
  "source": "/",
  "metadata": {
    "group": "servidores-web",
    "zone": "santiago",
    "department": "plataforma",
    "tags": {"tipo": "desarrollo", "ambiente": "qa"}
  },
  "sbom": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.6",
    "version": 1,
    "components": [{"type": "library", "name": "openssl", "version": "3.5.0"}]
  }
}
```

Un alta responde `201`. Reenviar el mismo cuerpo con el mismo identificador responde `200` y conserva el reporte original. Reutilizar el identificador con otro cuerpo responde `409` para ese cliente. Cada nuevo inventario debe usar un `report_id` nuevo y conservar el `machine_id` de la sonda instalada.

Las pruebas cubren aislamiento entre clientes, persistencia tras reinicio, envíos concurrentes, filtros y validación de TLS mutuo.

```sh
go test -race ./...
go vet ./...
```

## Laboratorio Docker

[Ejecuta el laboratorio local](lab/README.md) con Alpine, Debian, Ubuntu, dos clientes y mTLS. La prueba comprueba el inventario real, los filtros y la persistencia del UUID.
