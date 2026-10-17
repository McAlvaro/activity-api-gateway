# Activity API Gateway

API gateway reactivo que autentica con JWT y reenvía solicitudes de usuarios y publicaciones a JSONPlaceholder.

## Stack

- Java 21
- Spring Boot
- Spring Cloud Gateway
- Docker y Docker Compose
- Caddy

## Requisitos

Necesitas una de estas opciones:

- Docker y Docker Compose.
- Java 21 para ejecutar Maven localmente.

No se necesita base de datos: las credenciales son estáticas y los datos de usuarios/publicaciones se obtienen de JSONPlaceholder. Las credenciales y el secreto incluidos son exclusivamente de demostración; no los uses en producción.

## Ejecutar con Docker Compose

```bash
docker compose up --build
```

El servicio queda disponible en `http://localhost:8080`. Para detenerlo y eliminar recursos creados:

```bash
docker compose down --remove-orphans
```

## Despliegue

La instancia publicada está disponible en [https://gateway.codedocs.tech](https://gateway.codedocs.tech). El despliegue usa Caddy como proxy inverso con HTTPS y el archivo `docker-compose.dev.yml`.

### Configuración de demostración

| Variable              | Valor predeterminado                                 |
| --------------------- | ---------------------------------------------------- |
| `GATEWAY_USERNAME`    | `student`                                            |
| `GATEWAY_PASSWORD`    | `gateway123`                                         |
| `JSONPLACEHOLDER_URL` | `https://jsonplaceholder.typicode.com`               |
| `JWT_SECRET`          | secreto hexadecimal de demostración de 64 caracteres |

El secreto debe tener exactamente 64 caracteres hexadecimales (32 bytes). Antes de ejecutar fuera de la demostración, genera uno propio y pásalo sólo mediante una variable de entorno segura:

```bash
JWT_SECRET=$(openssl rand -hex 32) docker compose up --build
```

## Endpoints

| Método | Endpoint     | Autenticación | Descripción                                                 |
| ------ | ------------ | ------------- | ----------------------------------------------------------- |
| `POST` | `/api/login` | No            | Genera un JWT para las credenciales estáticas configuradas. |
| `GET`  | `/api/users` | Bearer JWT    | Proxy autenticado de `/users` en JSONPlaceholder.           |
| `GET`  | `/api/posts` | Bearer JWT    | Proxy autenticado de `/posts` en JSONPlaceholder.           |

### Iniciar sesión

```bash
curl --request POST http://localhost:8080/api/login \
  --header 'Content-Type: application/json' \
  --data '{"username":"student","password":"gateway123"}'
```

La respuesta contiene un `token`. Guárdalo para las solicitudes autenticadas:

```bash
TOKEN=$(curl --silent --request POST http://localhost:8080/api/login \
  --header 'Content-Type: application/json' \
  --data '{"username":"student","password":"gateway123"}' | jq --raw-output .token)
```

### Consultar usuarios

```bash
curl --header "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/users
```

### Consultar publicaciones

```bash
curl --header "Authorization: Bearer $TOKEN" \
  http://localhost:8080/api/posts
```

Las rutas `/api/users` y `/api/posts` dependen de JSONPlaceholder. Si ese servicio externo no está disponible, un error de proxy no indica un defecto de Docker ni de autorización: el login y una respuesta `401` sin credenciales siguen validando el contenedor y la protección JWT.
