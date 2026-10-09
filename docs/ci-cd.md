# Cross-platform CI and Docker delivery

Workflow: `.github/workflows/ci-cd.yml`. It runs on pushes to main, version tags (`v*`), pull requests into main and manual dispatch from the Actions tab.

## Pipeline

| Stage | Runner | What executes |
| --- | --- | --- |
| Application tests | Ubuntu, macOS, Windows; Python 3.12 | Pinned dependency installation, real pytest security suite, JUnit and coverage artifacts |
| Container verification | Ubuntu | Compose validation, Docker build, healthy startup, HTTP registration/login, restart and certificate persistence |
| Image publication | Ubuntu, after all test/build jobs succeed | Build and push Linux amd64 + arm64 images to GHCR, with provenance and SBOM |
| Optional deployment | Ubuntu, main only, configured production environment | SSH to your Linux host, pull the published digest, apply Compose and wait for health |

Windows runs native Python application tests. Four POSIX bootstrap tests are intentionally skipped there because `fcntl` and Gunicorn belong to the Linux container, not Windows. POSIX permission-bit verification is replaced with an explicit Windows ACL notice; this does not claim that Unix file modes secure Windows files. Linux/macOS execute the bootstrap tests. Docker Desktop runs the published Linux image on macOS and Windows (Linux container mode / WSL 2 on Windows); these are not native Windows container images.

No production secrets are needed for CI or publishing. Tests create temporary state. Docker CI generates disposable secrets and deletes only its disposable runner volume. Application originals, `.env`, database and key material are excluded from the image. Test artifacts contain JUnit and coverage only, retained for seven days. PR jobs have read-only repository permissions and never publish or deploy. GitHub Actions are pinned to reviewed upstream commit SHAs; Dependabot proposes action/base-image updates.

## Enable and inspect runs

1. Open the repository **Actions** tab. Enable Actions if GitHub has disabled them for the repository.
2. Select **CI and Docker delivery** and inspect the automatically triggered run, or choose **Run workflow** on main.
3. All three OS jobs and the Docker job must pass before image publication can execute.
4. The publish job alone receives `packages: write` and authenticates with the automatically provided `GITHUB_TOKEN`.

No Docker Hub account or token is needed. If repository/organization policy blocks package publishing or disallows an action, the corresponding job will fail; adjust the repository policy rather than adding credentials to source code.

## Published image tags

Image name: `ghcr.io/kali-guru/certivault`.

- `latest`: successful default-branch build.
- `sha-<full-commit-sha>`: commit-specific tag.
- A version such as `1.0.0`: a successfully tested matching `v1.0.0` Git tag.
- The job summary also records the immutable multi-platform image digest. Use a digest for reproducible deployment.

Publishing is configured, not guaranteed until its actual Actions run succeeds. Newly created GHCR packages may be private; make the package public through its settings if public unauthenticated pulls are desired, or log in to GHCR on the target machine with appropriate read access. Never store a registry token in Git.

## Run a published image with HTTPS

`compose.registry.yaml` uses a prebuilt image rather than building source on the server. It is a standalone stack. In the server's protected `.env`, retain the original application secrets and set:

```dotenv
DOMAIN=your-real-domain.example
CERTIVAULT_IMAGE=ghcr.io/kali-guru/certivault@sha256:REPLACE_WITH_PUBLISHED_DIGEST
```

Then:

```bash
docker compose -f compose.registry.yaml pull
docker compose -f compose.registry.yaml up -d --wait
```

The hostname must resolve to the server and ports 80/443 must be reachable. Use only one of the local, HTTPS-build or registry stacks at a time. They share the `certivault` project name and persistent application volume. See `docs/docker.md` for data preservation and backups.

## Optional continuous deployment to your server

The repository does not supply or provision a hosting account. To enable automatic server updates after successful main builds:

1. Prepare a dedicated Linux Docker host and `/opt/certivault` containing the reviewed `compose.registry.yaml`, `deployment/Caddyfile`, and protected `.env`. Copy these from the repository. Docker must be usable by the deployment user without an interactive sudo prompt. Docker control is privileged; scope this account to the deployment host.
2. Set the real domain and original application secrets on that host. Give the host GHCR read access if the package is private. Preserve consistent backups before schema-changing releases. Do not rotate the CA passphrase without re-encrypting its matching key.
3. Create a GitHub environment named **production** and its secrets:

| Secret | Value |
| --- | --- |
| `DEPLOY_HOST` | DNS hostname or IPv4 address of your host (SSH port 22) |
| `DEPLOY_USER` | Dedicated deployment username |
| `DEPLOY_SSH_KEY` | Private key authorized for that account; never place it in repository files |
| `DEPLOY_KNOWN_HOSTS` | Verified SSH known_hosts entry for that host, obtained and checked through a trusted channel |

4. Add a **repository Actions variable** `DEPLOY_ENABLED=true`. It is deliberately a repository variable so job scheduling can evaluate it before the environment starts.
5. Push reviewed changes to main or manually run the main workflow. The deployment job uses the digest produced by that exact successful publish job. Strict SSH host verification is enabled; there is no automatic trust-on-first-use.

The server reads its own `.env`; application secrets never travel through Actions. The job updates the image, not arbitrary checked-out source. Changes to Compose/Caddy deployment configuration must be reviewed and synchronized to the server separately. Deployments are serialized. No automatic database rollback or zero-downtime upgrade is promised; preserve matching pre-upgrade data snapshots and use a maintenance window for schema changes. The HTTPS proxy uses a major-version Caddy image tag; pin a reviewed digest on your production host if full image immutability is required.

Leave `DEPLOY_ENABLED` unset to build, test and publish without contacting any server.

## Local validation and limits

The authoring workspace runs Linux Python tests and can validate workflow/Compose structure. It has no Docker Engine or macOS/Windows runner. Actual cross-platform results, image builds, GHCR publication and remote deployment must be read from the workflow jobs; no green status is assumed from YAML alone.

References: [GitHub image publication](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images), [Docker GitHub Actions](https://docs.docker.com/build/ci/github-actions/), [GitHub Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry).
