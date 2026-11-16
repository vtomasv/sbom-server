# Laboratorio local de SBOM

El laboratorio levanta un servidor HTTPS y tres instancias Linux en Docker Compose. Cada sonda escanea el sistema de archivos de su contenedor y conserva su UUID en un volumen propio. El servidor guarda el historial de informes en otro volumen. Los certificados, las claves y los tokens se generan localmente.

| Contenedor | Distribución | Cliente | Grupo | Zona | Departamento | Etiqueta `tipo` | Paquete de prueba |
|---|---|---|---|---|---|---|---|
| `alpine-ops` | Alpine 3.22 | `acme` | servidores | santiago | plataforma | operaciones | jq |
| `debian-dev` | Debian 13 | `acme` | desarrollo | valparaiso | ingenieria | desarrollo | git |
| `ubuntu-ops` | Ubuntu 24.04 | `globex` | servidores | concepcion | seguridad | operaciones | curl |

## Arranque

Requiere Docker con Compose v2, Python 3, OpenSSL y acceso a los registros de contenedores y paquetes durante la construcción. Coloca ambos repositorios como directorios hermanos o define `SBOM_PROBE_CONTEXT` con la ruta absoluta de la sonda.

```sh
cd sbom-server/lab
python3 prepare.py
docker compose up -d --build
python3 verify.py --snapshot .local/identidades.json
```

El servidor queda disponible en [localhost:8443](https://localhost:8443/). Cambia `SBOM_LAB_PORT` y pasa la URL correspondiente a `verify.py --url` si el puerto está ocupado.

El laboratorio exige certificado de cliente incluso en la ruta de salud. Para entrar con un navegador, confía explícitamente en `.local/operator/ca.crt` e importa el certificado y la clave del operador. Puedes convertirlos a un archivo PKCS#12 con contraseña interactiva.

```sh
openssl pkcs12 -export \
  -in .local/operator/client.crt -inkey .local/operator/client.key \
  -name sbom-lab-operator -out .local/operator/operator.p12
```

En el panel usa el usuario `admin` y el token de `.local/operator/admin.token` como contraseña. Curl permite consultar la API directamente con certificados PEM.

```sh
curl --fail --silent --show-error \
  --cacert .local/operator/ca.crt \
  --cert .local/operator/client.crt --key .local/operator/client.key \
  -H "Authorization: Bearer $(cat .local/operator/admin.token)" \
  'https://localhost:8443/v1/machines?client_id=acme&tag=tipo%3Ddesarrollo'
```

## Verificación y parada

La prueba comprueba los tres UUID, el contenido CycloneDX y sus paquetes, los filtros de metadatos, el aislamiento entre clientes y el certificado de cliente. Para probar la persistencia del UUID después de recrear los contenedores, conserva los volúmenes.

```sh
docker compose up -d --force-recreate --no-deps alpine-ops debian-dev ubuntu-ops
python3 verify.py --compare .local/identidades.json
docker compose down
```

`docker compose down` conserva informes e identidades. Añade `--volumes` solamente para borrar los datos de este laboratorio. `prepare.py` conserva el material de la CA para próximos arranques. El directorio `.local` contiene material privado y se excluye de Git y de las construcciones.

Los contenedores del laboratorio usan UID 0 para leer los archivos privados montados desde el host. Escanean sus propios sistemas de archivos sobre una red local de Compose. Para despliegue en clientes usa los instaladores de la sonda o los pasos del [servidor](../README.md) según corresponda.
