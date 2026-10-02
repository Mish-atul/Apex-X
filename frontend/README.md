# APEX-X Frontend

Next.js 16 (React 19) web interface for the APEX-X platform: dashboard, APK upload, per-case analysis tabs, reports and threat map.

## Development

```bash
npm install
echo NEXT_PUBLIC_API_URL=http://localhost:8080/api/v1 > .env.local
npm run dev        # http://localhost:3000
```

## Quality checks

```bash
npx tsc --noEmit   # type check
npx eslint src     # lint
npm run build      # production build
```

## Structure

| Path | Purpose |
|---|---|
| `src/app/dashboard` | Case overview and activity feed |
| `src/app/upload` | APK / split-APK upload |
| `src/app/cases/[id]` | Overview, Static, Dynamic, C2, Vulnerability and Reports tabs |
| `src/app/documents` | Reports index (PDF and evidence downloads) |
| `src/components` | Shared UI (toasts and dialogs, graphs, tables, progress) |
| `src/services/api.ts` | Backend API client |

`NEXT_PUBLIC_API_URL` is embedded at build time; set it as a build argument when building the Docker image.

See the [root README](../README.md) for the full platform documentation.
