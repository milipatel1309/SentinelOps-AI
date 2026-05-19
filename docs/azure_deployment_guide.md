# Azure App Service Deployment Guide

Deploy **SentinelOps AI** to **Azure App Service (Linux)** without Docker. The app stays a standard Streamlit entry point (`app.py`); Azure runs `startup.sh` on port **8000**.

---

## Prerequisites

- An [Azure account](https://azure.microsoft.com/free/) with permission to create resources
- This repository on your machine (or pushed to GitHub)
- Optional: [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az`) for command-line setup
- Optional LLM keys: `GROQ_API_KEY` and/or `OPENAI_API_KEY` (the app runs in **mock mode** without them)

---

## 1. Create the App Service (Linux, Python 3.11)

### Portal (recommended for first deploy)

1. In [Azure Portal](https://portal.azure.com), create **App Service**.
2. **Publish:** Code  
3. **Runtime stack:** Python 3.11 (or 3.10+)  
4. **Operating System:** Linux  
5. **Region:** Choose one close to your users.  
6. Create or select a **Resource group** and **App Service plan** (B1 is enough for demos).

### Azure CLI (optional)

```bash
RESOURCE_GROUP="sentinelops-rg"
APP_NAME="sentinelops-ai-<unique>"   # must be globally unique
LOCATION="eastus"
PLAN="sentinelops-plan"

az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
az appservice plan create --name "$PLAN" --resource-group "$RESOURCE_GROUP" \
  --sku B1 --is-linux
az webapp create --name "$APP_NAME" --resource-group "$RESOURCE_GROUP" \
  --plan "$PLAN" --runtime "PYTHON:3.11"
```

---

## 2. Configure port and startup

App Service routes HTTP traffic to the port in **WEBSITES_PORT**. This project listens on **8000** (see `startup.sh`).

| Setting | Value |
|--------|--------|
| **WEBSITES_PORT** | `8000` |
| **Startup Command** | `bash startup.sh` |

**Portal:** App Service → **Configuration** → **General settings**

- **Startup Command:** `bash startup.sh`  
  (Alternative: `streamlit run app.py --server.port 8000 --server.address 0.0.0.0`)

**Application settings** (same blade, **Application settings** tab):

- Name: `WEBSITES_PORT` → Value: `8000`

Save and restart the app when prompted.

> **Note:** `startup.sh` binds Streamlit to `0.0.0.0:8000`. Do not rely on Streamlit’s default port `8501` on App Service.

---

## 3. Deploy the application

Deploy the **project root** (folder containing `app.py`, `requirements.txt`, `startup.sh`). Do **not** upload `venv/` or `.env`.

### Option A — ZIP deploy (simplest)

From the project root on your machine:

```bash
cd "/path/to/SentinelOps AI"
zip -r deploy.zip . \
  -x "venv/*" ".venv/*" ".git/*" "__pycache__/*" "*.pyc" ".env"
```

**Portal:** App Service → **Deployment Center** → ZIP Deploy, or use **Advanced Tools (Kudu)** → drag-and-drop.

**CLI:**

```bash
az webapp deployment source config-zip \
  --resource-group "$RESOURCE_GROUP" \
  --name "$APP_NAME" \
  --src deploy.zip
```

Oryx will install dependencies from `requirements.txt` when `SCM_DO_BUILD_DURING_DEPLOYMENT=true` (see `.deployment` in the repo).

### Option B — GitHub

1. Push the repo to GitHub.  
2. App Service → **Deployment Center** → **GitHub** → authorize and select repo/branch.  
3. Ensure **Startup Command** and **WEBSITES_PORT** are set as in step 2.

### Option C — Local Git

```bash
az webapp deployment source config-local-git \
  --name "$APP_NAME" --resource-group "$RESOURCE_GROUP"
# Follow the printed git remote URL; push main branch
```

---

## 4. Application settings (API keys)

Secrets belong in **Configuration**, not in the deployed `.env` file.

**Portal:** App Service → **Configuration** → **Application settings** → **New application setting**

| Name | Value | Notes |
|------|--------|--------|
| `GROQ_API_KEY` | Your Groq API key | Optional; Groq is tried first |
| `OPENAI_API_KEY` | Your OpenAI API key | Optional; used if Groq is absent |
| `GROQ_MODEL` | e.g. `llama-3.3-70b-versatile` | Optional |
| `OPENAI_MODEL` | e.g. `gpt-4o-mini` | Optional |

Click **Save**, then **Continue** to restart the app.

`utils/llm_client.py` uses `python-dotenv` for local `.env` files and `os.getenv()` for these variables—on App Service, **Application settings are environment variables**, so no `.env` file is required.

### Production: Azure Key Vault (conceptual)

For production, store secrets in **Azure Key Vault** and reference them from App Service using **Key Vault references** in Application settings (e.g. `@Microsoft.KeyVault(SecretUri=...)`). This keeps keys out of the portal UI and supports rotation. Not required for the MVP prototype.

---

## 5. Verify deployment

1. Open `https://<your-app-name>.azurewebsites.net`  
2. Confirm the Streamlit UI loads.  
3. Run a preset scenario; check the sidebar for **Groq connected**, **OpenAI connected**, or **Mock mode active**.

---

## 6. Troubleshooting

### Application won’t start / 502 / connection refused

- Confirm **WEBSITES_PORT** = `8000` and **Startup Command** = `bash startup.sh`.  
- Ensure `startup.sh` is in the repo root and deployed (not excluded by `.gitignore`).  
- On Linux App Service, make the script executable locally before zip deploy:  
  `chmod +x startup.sh`

### Build failures during deploy

- Check **Deployment Center** / **Log stream** for `pip install` errors.  
- Verify `requirements.txt` at the repo root.  
- `runtime.txt` pins `python-3.11`; match the App Service Python stack.

### Streamlit errors in logs

- Run headless on servers (startup command already passes server flags).  
- If you add `.streamlit/config.toml`, set `[server] headless = true`—optional; `startup.sh` is usually enough.

### View logs

- **Portal:** App Service → **Log stream** (live)  
- **Portal:** **Monitoring** → **App Service logs** → enable Application Logging (Filesystem), level Information  
- **CLI:** `az webapp log tail --name "$APP_NAME" --resource-group "$RESOURCE_GROUP"`

### LLM keys not detected

- Keys must be **Application settings**, not committed `.env`.  
- Restart the app after changing settings.  
- Names are case-sensitive: `GROQ_API_KEY`, `OPENAI_API_KEY`.

### Wrong Python version

- Align **Configuration** → **General settings** runtime with `runtime.txt` (`python-3.11`).

---

## 7. Related documentation

- [README.md](../README.md) — local run, architecture overview, production Azure diagram (conceptual)  
- [architecture_summary.md](architecture_summary.md) — multi-agent design

---

## Summary checklist

- [ ] Linux App Service, Python 3.11  
- [ ] `WEBSITES_PORT=8000`  
- [ ] Startup command: `bash startup.sh`  
- [ ] Deploy root with `app.py`, `requirements.txt`, `startup.sh`, agents/, data/, utils/  
- [ ] Exclude `venv/`, `.env` from deployment package  
- [ ] Optional: `GROQ_API_KEY` / `OPENAI_API_KEY` in Application settings  
- [ ] Browse site and test a preset scenario
