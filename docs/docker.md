# Docker deployment

Two Compose stacks are provided: a loopback-only local deployment and an optional public HTTPS deployment. Both run the same non-root Gunicorn image and retain database, uploads, encrypted packages and encrypted keys in a named volume. Docker does not change the application's educational PKI limitations.

## CachyOS / Arch: local deployment

```bash
sudo pacman -Syu --needed docker docker-compose git python
sudo systemctl enable --now docker
# If already cloned, use your existing checkout and run git pull instead.
git clone https://github.com/kali-guru/CertiVault.git
cd CertiVault
# Preserve an existing .env; its CA passphrase may already protect your data.
test -f .env || python scripts/configure.py
sudo docker compose up -d --build --wait
sudo docker compose ps
```

Open **http://localhost:8000**. This stack binds only `127.0.0.1`, uses local HTTP cookies, and explicitly selects development policy so optional fictional demo data is available. It serves with Gunicorn, not Flask's development server. Set `PORT=8080` in `.env` to change the host port if needed.

On first start, the entrypoint applies migrations and creates an encrypted CA in the volume. On restart it preserves the existing CA and accounts, checks that the CA key unlocks and matches its certificate, then starts Gunicorn. A filesystem lock prevents simultaneous initializers from creating different roots. Partial CA state, a wrong passphrase, or existing identities with a missing root fail startup rather than silently replacing trust material.

```bash
# Choose your own password at the hidden prompt; no demo password is shipped.
sudo docker compose exec web flask --app run seed-demo
# Or create a separately configured administrator:
sudo docker compose exec web flask --app run create-admin
# Diagnostics:
sudo docker compose logs --tail=100 web
sudo docker compose exec web flask --app run verify-security-config
# Stop and remove containers; the named volume remains:
sudo docker compose down
# Start again with existing state:
sudo docker compose up -d --wait
```

Container data is separate from a native Python installation's `instance/` directory. Existing local accounts are not automatically imported. Do not mount a partially copied instance or generate a new `.env` for existing container data.

## Public HTTPS deployment

Use a Linux host with Docker Engine and Compose v2, a DNS name pointing to that host, and TCP ports 80 and 443 reachable. Add `DOMAIN=certivault.your-domain.example` to `.env`, replacing the placeholder with your actual hostname. Keep the original `SECRET_KEY` and `CA_PASSPHRASE`.

```bash
# Stop the local stack first if it is running; keep its volume.
sudo docker compose down
# This is a standalone file, not an override to merge with compose.yaml.
sudo docker compose -f compose.https.yaml up -d --build --wait
sudo docker compose -f compose.https.yaml exec web flask --app run create-admin
sudo docker compose -f compose.https.yaml logs --tail=100 proxy
```

Open `https://YOUR_DOMAIN`. Caddy obtains and renews public TLS certificates and redirects HTTP to HTTPS. This is a transport certificate, separate from CertiVault's internal document-identity CA. The application has no published host port in this stack; Caddy forwards over the private Compose network. Production policy enables Secure session cookies and HSTS and rejects demo seeding. The same Compose project name and application volume preserve identities when switching stacks.

Both stacks deliberately run one Gunicorn process with four threads because SQLite and the rate limiter are local to this installation. Do not horizontally scale this configuration. Without trusted proxy middleware, the HTTPS stack sees Caddy's address, so IP throttles are shared by users behind the proxy. This is conservative for a small demonstration, not a distributed production throttling design. Real deployment still needs the operational improvements listed in SECURITY.md.

## Persistence, backup and updates

Named volumes:

- `certivault_certivault_data`: SQLite, CA, user keys, originals and encrypted packages.
- `certivault_caddy_data` and `certivault_caddy_config`: HTTPS proxy state, when using that stack.

Keep `.env` and a consistent volume backup together in protected storage. The volume contains unencrypted original uploads. Never commit or publish backup archives. To take a consistent offline local-stack backup:

```bash
umask 077
mkdir -p backups
sudo docker compose stop web
sudo docker compose run --rm --no-deps --entrypoint tar web -C /data -czf - . > backups/instance.tar.gz
cp .env backups/environment.env
sudo docker compose start web
```

For the HTTPS stack, use `-f compose.https.yaml` on every Compose command. Restore the matching complete database/files snapshot into a fresh application volume with UID/GID 10001 ownership and restore its original environment secrets before starting. Do not merge unrelated CA/database snapshots. Test restores with fictional data first.

Before updating, stop the app and back up its state. Pull reviewed source, then run `docker compose up -d --build --wait` (with the HTTPS file when applicable). Startup applies migrations. Keep a matching pre-upgrade snapshot for rollback. **Do not use `docker compose down -v` unless you intend to delete all persisted identities and documents.** Recreating a CA does not restore lost trust or keys.

## Image and process controls

The Docker build uses an allowlisted context and explicit COPY paths. `.env`, runtime state, test artifacts and private key files are excluded. Dependencies are pinned in `requirements-docker.txt`; test-only packages are omitted. The app runs as UID/GID 10001 with a read-only root filesystem, writable private data volume, temporary `/tmp`, all Linux capabilities dropped and no-new-privileges. Secrets are injected at runtime, not built into image layers; Docker host administrators can still inspect container environment variables.

Gunicorn receives termination signals through the exec-based entrypoint and Compose init process. Health checks confirm HTTP response, migrated SQLite schema and CA file presence. The proxy waits for the application health check before starting. Health checks are readiness evidence, not comprehensive security checks.

## Verification in the authoring workspace

Docker Engine/CLI was unavailable, so no image build, container start, port mapping, named-volume permissions or automatic HTTPS issuance was executed here. The actual Python bootstrap is covered by four tests: fresh migration with restart preservation, incomplete-CA rejection, wrong-passphrase rejection and missing-root rejection for existing identities. Gunicorn's configuration is checked directly. Run the Compose commands above on your Docker host to complete container verification; report errors from `docker compose logs` if startup fails.

References: [Docker Compose health and dependency ordering](https://docs.docker.com/compose/how-tos/startup-order/), [Compose service controls](https://docs.docker.com/reference/compose-file/services/), [Gunicorn settings](https://docs.gunicorn.org/en/stable/settings.html), [Caddy automatic HTTPS](https://caddyserver.com/docs/automatic-https).

## macOS and Windows

Install Docker Desktop and start its engine. On Windows, enable WSL 2 / Linux containers. Clone this repository and open a terminal in its root. Native Python is only needed for generating `.env`; the app dependencies run inside the image.

macOS Terminal:

```bash
test -f .env || python3 scripts/configure.py
docker compose up -d --build --wait
docker compose exec web flask --app run seed-demo
```

Windows PowerShell:

```powershell
if (!(Test-Path .env)) { py -3 scripts/configure.py }
docker compose up -d --build --wait
docker compose exec web flask --app run seed-demo
```

Both open at http://localhost:8000 and use a Docker-managed Linux data volume. Use `docker compose down` to stop while preserving data. The CI/CD workflow and prebuilt-image deployment are documented in [ci-cd.md](ci-cd.md). Native Windows filesystem permissions differ from POSIX; prefer the Linux container for the project's key-vault deployment.
