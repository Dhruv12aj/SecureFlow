# Setting up the pipeline

The whole lab (Jenkins, SonarQube, registry, staging, production and monitoring) runs in Docker.
There are two ways to get a Docker host:

- **GitHub Codespaces (what this project was built and demoed on)** - a Linux machine in the
  browser with Docker ready to go. Nothing to install locally.
- **Docker Desktop on Windows** - same steps, but you need WSL 2 and Virtual Machine Platform
  working (see the Windows section at the bottom).

## Option A: GitHub Codespaces

1. Repo page > **Code** > **Codespaces** > **...** > **New with options** > machine type
   **4-core / 16 GB** > **Create codespace**. The dev container (`.devcontainer/`) uses GitHub's
   standard image, so Docker and Python are already there.
2. In the Codespace terminal:
   ```bash
   cp .env.example .env      # then fill it in (see step 3 below for what each value is)
   docker network create secureflow-net
   docker compose -f docker-compose.ci.yml up -d sonarqube registry
   ```
3. Create the SonarQube token without the web UI:
   ```bash
   until curl -s localhost:9000/api/system/status | grep -q '"UP"'; do sleep 10; done
   SONAR_PASS='choose-a-strong-Passw0rd!'
   curl -s -u admin:admin -X POST localhost:9000/api/users/change_password \
     -d "login=admin&previousPassword=admin&password=$SONAR_PASS"
   TOKEN=$(curl -s -u "admin:$SONAR_PASS" -X POST localhost:9000/api/user_tokens/generate \
     -d "name=jenkins&type=USER_TOKEN" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
   sed -i "s|^SONAR_TOKEN=.*|SONAR_TOKEN=$TOKEN|" .env
   ```
4. Start Jenkins: `docker compose -f docker-compose.ci.yml up -d --build`
5. **PORTS** tab > 8080 > open in browser, log in with the `.env` credentials, open the
   **secureflow** job, **Build Now**. Every service is reachable from the PORTS tab
   (8000 prod, 8001 staging, 3000 Grafana, 9000 SonarQube, 9090 Prometheus, 9093 Alertmanager).

Stop the Codespace when you're done (github.com/codespaces > ... > Stop) to save free hours.

## Option B: Docker Desktop on Windows

## 1. Install the tools

| Tool | Notes |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Use the WSL 2 backend (default). Give it at least 6 GB of memory |
| [Git for Windows](https://git-scm.com/download/win) | |
| [Python 3.12](https://www.python.org/downloads/) | Tick "Add python.exe to PATH" - only needed to run the app outside Docker |
| [VS Code](https://code.visualstudio.com/) | optional |

**Memory:** SonarQube and Jenkins are heavy. If Docker Desktop has less than 6 GB, create
`C:\Users\<you>\.wslconfig` with:

```ini
[wsl2]
memory=8GB
```

then run `wsl --shutdown` in PowerShell and restart Docker Desktop.

## 2. Get the code

```powershell
git clone https://github.com/Dhruv12aj/secureflow.git
cd secureflow
```

## 3. Collect the secrets

**GitHub token** - GitHub > Settings > Developer settings > Personal access tokens > Tokens (classic)
> Generate new token. Tick the `repo` scope. Jenkins uses it to check out the private repo and
push release tags.

**Gmail app password** - you need 2-Step Verification switched on. Then go to
https://myaccount.google.com/apppasswords, create one called "SecureFlow", and copy the
16 characters (without spaces). Your normal Gmail password will not work.

## 4. Create your `.env`

```powershell
Copy-Item .env.example .env
notepad .env
```

Fill in everything except `SONAR_TOKEN` for now. The API keys can be any long random strings,
e.g. from `python -c "import secrets; print(secrets.token_urlsafe(24))"`.

## 5. Start SonarQube and the registry

```powershell
docker network create secureflow-net
docker compose -f docker-compose.ci.yml up -d sonarqube registry
```

Wait about 2 minutes, then open http://localhost:9000.

1. Log in with `admin` / `admin` and set a new password.
2. Click your avatar (top right) > **My Account** > **Security**.
3. Generate a token: name `jenkins`, type **User Token**, no expiry.
   (It has to be a user token - the pipeline creates the quality gate, which needs admin rights.)
4. Paste it into `.env` as `SONAR_TOKEN`.

## 6. Start Jenkins

```powershell
docker compose -f docker-compose.ci.yml up -d --build
```

The first build of the Jenkins image takes a few minutes. Then open http://localhost:8080 and
log in with `JENKINS_ADMIN_ID` / `JENKINS_ADMIN_PASSWORD` from your `.env`.

There's no setup wizard and nothing to click through: plugins, credentials and the `secureflow`
pipeline job are all created from `jenkins/casc.yaml`. Check **Manage Jenkins > Credentials**
if you want to see them.

## 7. Run the pipeline

Open the **secureflow** job and click **Build Now**. The first run takes 8-10 minutes (it
downloads the Trivy vulnerability database, the scanner, and base images). Later runs take 3-4.

After the first run, the button changes to **Build with Parameters**, and Jenkins starts polling
GitHub every 2 minutes, so every `git push` to `main` triggers a build on its own.

When it's green, check:

- http://localhost:8000 - production (paste your `PROD_ANALYST_KEY` in the dashboard)
- http://localhost:8001 - staging
- http://localhost:3000 - Grafana, dashboard "SecureFlow - Security Operations"
- http://localhost:9093 - Alertmanager
- GitHub > your repo > Tags - a new `v1.0.N` tag per release

## 8. The demos

**Rollback** - Build with Parameters, tick `SIMULATE_BAD_DEPLOY`. Staging gets a version that
can't start, the health check fails, the script rolls back to the previous version, and the
build goes red with "rollback complete" in the log. Staging stays up the whole time.

**Attack wave** - set `INCIDENT_DRILL` to `attack-wave`. The simulator hits production, the
Grafana attack panel spikes, `AttackWave` fires and an email arrives within about 30 seconds.

**Outage** - set `INCIDENT_DRILL` to `staging-outage`. Staging is stopped, `SecureFlowDown`
fires after about a minute (email), then staging is started again and a RESOLVED email follows.

You can also run the simulator from your own machine at any time:

```powershell
python scripts/attack_sim.py --target http://localhost:8000 --rounds 3
```

## Troubleshooting

| Problem | Fix |
|---|---|
| `permission denied ... docker.sock` in Jenkins | Docker Desktop > Settings > General > "Use the WSL 2 based engine" must be on. Recreate Jenkins: `docker compose -f docker-compose.ci.yml up -d --force-recreate jenkins` |
| SonarQube keeps restarting | Not enough memory - see step 1 |
| Code Quality stage: `401` from SonarQube | Wrong/expired token in `.env`. Fix it, then `docker compose -f docker-compose.ci.yml up -d jenkins` so Jenkins reloads its credentials |
| Security stage fails on a Trivy CVE | Read the finding. Usually rebuilding pulls a patched base image. If it can't be fixed yet and doesn't affect us, add it to `.trivyignore` with a reason (see `docs/SECURITY_NOTES.md`) |
| No alert emails | Check the app password, the spam folder, and `docker logs alertmanager` |
| Port already in use | Something else is on 8080/9000/3000/5000 - stop it, or change the left-hand port in the compose file |
| Changed `.env` but Jenkins didn't notice | `docker compose -f docker-compose.ci.yml up -d jenkins` (config-as-code is re-applied on start) |

## Starting over

```powershell
docker compose -f docker-compose.ci.yml down -v
docker compose -f monitoring/docker-compose.yml down -v
docker compose -f deploy/docker-compose.staging.yml down -v
docker compose -f deploy/docker-compose.prod.yml down -v
```

(the last two need `$env:IMAGE_TAG="x"; $env:ANALYST_API_KEY="x"; $env:ADMIN_API_KEY="x"` set first, because the compose files require them)
