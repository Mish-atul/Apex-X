# Docker Deployment

APEX-X ships as two containers defined in `docker-compose.prod.yml`:

| Service | Image (built locally) | Port | Contents |
|---|---|---|---|
| `backend` | `apex-x-backend` | 8080 | FastAPI, OpenJDK 17, APKTool, JADX, Androguard, YARA, APKiD, Quark-Engine (rules baked in), adb client |
| `frontend` | `apex-x-frontend` | 3000 | Next.js production server; proxies `/api/v1` to the backend |

Case files and the SQLite database live in the named volume `apex_data` (`/app/data`).

## Build and run

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

- Frontend: http://localhost:3000
- API docs: http://localhost:8080/docs

The first backend build takes roughly 10–15 minutes (dependency resolution and Quark rule download). Later builds use the layer cache.

Secrets are read from an optional `.env` in the repository root (`SECRET_KEY`, `VIRUSTOTAL_API_KEY`, `IPINFO_API_TOKEN`, `SARVAM_API_KEY`, …). `.env` is excluded from the build context, so keys are never baked into images.

## Dynamic analysis from containers

Android emulators need hardware virtualization and cannot run inside Docker Desktop on Windows. The backend container therefore uses the **host's** adb server:

- `ADB_SERVER_SOCKET=tcp:host.docker.internal:5037` (set in the image)
- `host.docker.internal` is mapped to the host gateway in the compose file

Before running dynamic analysis, start the emulator on the host (`launch_emulator.bat`, or `emulator -avd ApexX_Sandbox`) and make sure `adb devices` lists it. Static analysis, intelligence, scoring and reporting work without the emulator.

## Frontend API routing

The browser calls the API on the frontend's own origin (`/api/v1`), and Next.js rewrites those requests to `BACKEND_INTERNAL_URL` (default `http://backend:8080`). Both values are build arguments, because rewrites are resolved when the frontend is built:

```bash
docker compose -f docker-compose.prod.yml build \
  --build-arg BACKEND_INTERNAL_URL=http://my-backend:8080 frontend
```

Because the API is same-origin, one public URL (for example a Cloudflare Tunnel to port 3000) serves the whole application.

## Publishing images

```bash
docker login
docker tag apex-x-backend:latest  <dockerhub-user>/apex-x-backend:latest
docker tag apex-x-frontend:latest <dockerhub-user>/apex-x-frontend:latest
docker push <dockerhub-user>/apex-x-backend:latest
docker push <dockerhub-user>/apex-x-frontend:latest
```

## Housekeeping

```bash
docker compose -f docker-compose.prod.yml down        # stop
docker compose -f docker-compose.prod.yml down -v     # stop and DELETE case data
docker builder prune -f                               # clear build cache
```
