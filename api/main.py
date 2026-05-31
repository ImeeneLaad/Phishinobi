"""
api/main.py
-----------
Step 3 — FastAPI REST service wrapping the phishing detector.

Endpoints:
    GET  /health   → quick liveness/readiness check
    POST /predict  → analyze one URL, return the full risk assessment

Run it (from the project root):
    uvicorn api.main:app --reload --port 8000

Then open http://127.0.0.1:8000/docs for interactive Swagger docs.

Design decisions (mentor notes are inline below):
  - The model is loaded ONCE at startup, not per request.
  - CORS is enabled so the browser-based Chrome extension can call us.
  - We reuse predict_url() unchanged — the API is a thin transport layer
    over the Step 1 engine. No detection logic lives here.
"""

import os
import io
import zipfile
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response

from api.schemas import PredictRequest, PredictResponse, HealthResponse
from src.predict import predict_url, get_model

# ---------------------------------------------------------------------------
# Resolve the model path to an ABSOLUTE path.
#
# Why: predict.py defaults to the relative path "models/phishing_model.pkl",
# which only works if the server is launched from the project root. By
# computing an absolute path from this file's location, the API works no
# matter which directory uvicorn is started from. More robust, fewer
# "file not found" surprises.
# ---------------------------------------------------------------------------
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")
WEB_DIR = os.path.join(PROJECT_ROOT, "web")               # the website's HTML/CSS/JS
EXT_DIR = os.path.join(PROJECT_ROOT, "chrome_extension")  # the extension folder


# ---------------------------------------------------------------------------
# Startup / shutdown lifecycle
#
# The `lifespan` handler is FastAPI's modern way to run code once when the
# server boots. We warm-load the model here so the FIRST request is already
# fast — no client pays the one-time cost of reading the .pkl from disk.
#
# get_model() caches the model in a module-level global inside predict.py,
# so every later predict_url() call reuses this same in-memory instance.
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── startup ──
    try:
        get_model(MODEL_PATH)          # load + cache the Random Forest once
        app.state.model_loaded = True
        print(f"[startup] Model loaded from {MODEL_PATH}")
    except FileNotFoundError as e:
        # Don't crash the server — let /health report the problem instead.
        app.state.model_loaded = False
        print(f"[startup] WARNING: {e}")
    yield
    # ── shutdown ── (nothing to clean up; kept for clarity)


app = FastAPI(
    title="Phishing URL Detection API",
    description="REST wrapper around the Step 1 ML detection engine.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS (Cross-Origin Resource Sharing)
#
# A Chrome extension's content/background scripts make requests from an
# "origin" the browser treats as different from our server. Without CORS,
# the browser blocks the response. Enabling CORS tells the browser our API
# is willing to be called from elsewhere.
#
# SECURITY NOTE: allow_origins=["*"] is fine for LOCAL DEVELOPMENT only.
# Before you ship, lock this down to your extension's exact origin, e.g.
#   "chrome-extension://<your-extension-id>"
# An open CORS policy on a public server lets ANY website call your API.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # TODO(prod): restrict to the extension origin
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# GET /health
#
# Cheap endpoint for uptime monitors, load balancers, and your own sanity.
# Reports whether the model actually loaded — a server that's "up" but has
# no model is not truly ready to serve predictions.
# ---------------------------------------------------------------------------
@app.get("/health", response_model=HealthResponse)
def health():
    return HealthResponse(
        status="ok",
        model_loaded=bool(getattr(app.state, "model_loaded", False)),
        service="phishing-detector-api",
    )


# ---------------------------------------------------------------------------
# POST /predict
#
# The main event. Takes {"url": "..."} and returns the full risk assessment.
# predict_url() does all the real work; we just validate input and translate
# failures into proper HTTP status codes.
# ---------------------------------------------------------------------------
@app.post("/predict", response_model=PredictResponse)
def predict(request: PredictRequest):
    # 503 Service Unavailable: the server is running but can't serve yet.
    if not getattr(app.state, "model_loaded", False):
        raise HTTPException(
            status_code=503,
            detail="Model not loaded. Train it first: python main.py --mode train",
        )

    try:
        result = predict_url(request.url, model_path=MODEL_PATH,
                             enrich=request.enrich)
    except Exception as e:
        # 500: something unexpected blew up during inference. We surface a
        # generic message (don't leak internals to clients) but log details.
        print(f"[predict] error analyzing {request.url!r}: {e}")
        raise HTTPException(status_code=500, detail="Failed to analyze URL.")

    return result


# ---------------------------------------------------------------------------
# The website (served by the same server as the API)
#
#   GET  /              → the Phishinobi web page (paste-a-link tool)
#   /static/...         → its CSS + JS assets
#
# Serving the front-end from the same origin as /predict means the page can
# call the API with no CORS headaches, and you only run ONE command for the
# whole demo. The API routes above are registered first, so they always win;
# the static mount only catches everything else.
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def home():
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


# Lets the website's "Download extension" button work: zips up the
# chrome_extension folder on the fly and sends it as a file download.
@app.get("/download/phishinobi-extension.zip", include_in_schema=False)
def download_extension():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(EXT_DIR):
            for name in files:
                full = os.path.join(root, name)
                # store paths relative to the project so the zip unpacks into
                # a clean "chrome_extension/" folder
                arc = os.path.relpath(full, PROJECT_ROOT)
                zf.write(full, arc)
    buf.seek(0)
    return Response(
        content=buf.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename=phishinobi-extension.zip"},
    )


app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")
