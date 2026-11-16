# Alta de clientes y certificados

El servidor expone HTTPS con una CA privada autofirmada. Cada cliente recibe un token propio. La sonda valida la cadena y el nombre del servidor usando `ca_file`. Al configurar `client_ca` en el servidor, cada conexión también necesita un certificado cliente válido. El token determina qué cliente puede enviar y consultar información.

## Crear las autoridades y certificados

Ejecutar desde la raíz de este repositorio con OpenSSL disponible. Los directorios de salida deben ser nuevos y su directorio padre debe existir.

```sh
umask 077
mkdir -p provision
./scripts/pki.sh init-ca provision/server-ca sbom-server-root
./scripts/pki.sh init-ca provision/client-ca sbom-client-root
./scripts/pki.sh issue-server provision/server-ca provision/server DNS:sbom.example.com
./scripts/pki.sh issue-client provision/client-ca provision/equipo-001 equipo-001
```

Para el laboratorio, agregar los nombres e IP utilizados por Docker y por el navegador a la emisión del servidor, por ejemplo `DNS:server DNS:localhost IP:127.0.0.1`. La URL que use la sonda debe coincidir con uno de los SAN emitidos.

Los directorios se crean con modo `0700`, las claves con `0600` y los certificados públicos con `0644`. El usuario del proceso debe poder recorrer el directorio y leer sus archivos. En contenedores, ajustar el propietario del directorio desplegado al UID del servicio y montar los archivos como solo lectura.

La validez predeterminada es de diez años para la CA, un año para el servidor y noventa días para las sondas. Se puede cambiar mediante `SBOM_PKI_CA_DAYS`, `SBOM_PKI_SERVER_DAYS` y `SBOM_PKI_CLIENT_DAYS`. El script exige que la CA siga vigente durante toda la vida solicitada del certificado.

Las claves `ca.key` se mantienen en el equipo emisor con acceso restringido. El servidor recibe su propia clave y la CA pública de clientes. Cada sonda recibe su propia clave y la CA pública del servidor.

## Configurar el servidor

Ejemplo de `/etc/sbom/config.json` con mTLS activado. Generar un secreto distinto para administración y para cada cliente mediante `openssl rand -hex 32` y colocar sus valores en los campos correspondientes.

```json
{
  "listen": ":8443",
  "data_dir": "/var/lib/sbom-server",
  "tls_cert": "/etc/sbom/tls/server.crt",
  "tls_key": "/etc/sbom/tls/server.key",
  "client_ca": "/etc/sbom/tls/client-ca.crt",
  "admin_token": "REEMPLAZAR_POR_SECRETO_ALEATORIO_DE_ADMINISTRACION",
  "clients": {
    "cliente-a": "REEMPLAZAR_POR_SECRETO_ALEATORIO_DEL_CLIENTE_A"
  },
  "max_report_bytes": 67108864
}
```

Copiar `provision/server/server.crt`, `provision/server/server.key` y `provision/client-ca/ca.crt` a las rutas indicadas. Proteger también el archivo de configuración porque contiene tokens. Iniciar con `sbom-server -config /etc/sbom/config.json`.

Para agregar un cliente, crear su token, añadir una entrada con un identificador estable en `clients` y reiniciar el servidor. Entregar ese mismo identificador como `client_id` a sus sondas. Los grupos, zonas, departamentos y etiquetas permiten clasificar las máquinas dentro de cada cliente.

## Preparar un despliegue de sonda

Crear un directorio por despliegue con estos archivos.

| Archivo | Contenido |
| --- | --- |
| `config.json` | Configuración de la sonda |
| `client.token` | Token del cliente, con acceso restringido |
| `ca.crt` | CA pública que emitió el certificado del servidor |
| `client.crt` | Certificado de esta sonda emitido por la CA de clientes |
| `client.key` | Clave privada de esta sonda |

Ejemplo de `config.json` para un paquete instalable.

```json
{
  "server_url": "https://sbom.example.com:8443",
  "client_id": "cliente-a",
  "token_file": "client.token",
  "ca_file": "ca.crt",
  "client_cert_file": "client.crt",
  "client_key_file": "client.key",
  "scan_path": "/",
  "scan_timeout": "45m",
  "request_timeout": "2m",
  "interval": "24h",
  "metadata": {
    "group": "servidores",
    "zone": "santiago",
    "department": "tecnologia",
    "tags": {
      "ambiente": "produccion",
      "funcion": "operaciones"
    }
  }
}
```

En Windows, ajustar `scan_path` a una ruta local como `C:\\`. Los instaladores administran las rutas de estado y del Syft incluido. Para autenticar únicamente con token sobre HTTPS, omitir `client_ca` del servidor y los dos campos de certificado cliente de la sonda.

Instalar desde el paquete de la plataforma correspondiente.

```sh
sudo sh ./install.sh --deployment /ruta/al/despliegue
```

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Deployment C:\ruta\despliegue
```

Cada instalación genera su identificador de máquina en el directorio de estado. Para imágenes maestras, instalar o inicializar la sonda después de clonar, de modo que cada máquina genere su propio identificador. Conservar el estado durante las actualizaciones para mantener la identidad y los reportes pendientes.

## Rotación

Emitir los nuevos certificados en directorios nuevos, sustituir el par de archivos correspondiente y reiniciar el servicio que los carga. Cada renovación conserva el identificador de máquina almacenado por la sonda.

Para reemplazar una CA, distribuir primero un PEM de confianza que contenga las CA anterior y nueva. Después renovar los certificados de las máquinas y retirar la CA anterior una vez completado el despliegue. La CA de clientes y la CA del servidor se pueden rotar de forma independiente.

Para rotar un token, coordinar el cambio del servidor y las sondas del cliente. El archivo de configuración contiene un token activo por cliente. La sustitución requiere una ventana de actualización y las sondas conservan sus reportes pendientes para reintentar el envío.

Los certificados de cliente emitidos por una CA confiable se aceptan hasta su vencimiento. La implementación usa validación de cadena y vigencia. Una retirada urgente requiere cambiar la confianza de la CA de clientes y desplegar certificados nuevos a los equipos autorizados. Usar autoridades separadas por entorno reduce el alcance de esa operación.

## Comprobar certificados

```sh
openssl verify -CAfile provision/server-ca/ca.crt -purpose sslserver -verify_hostname sbom.example.com provision/server/server.crt
openssl verify -CAfile provision/client-ca/ca.crt -purpose sslclient provision/equipo-001/client.crt
openssl x509 -in provision/equipo-001/client.crt -noout -dates
```

Para acceder al panel con mTLS desde un navegador, importar un certificado de operador y su clave en el almacén de certificados del navegador. Importar también la CA pública del servidor como autoridad de confianza. Crear para el operador un certificado cliente diferente del utilizado por las sondas.
