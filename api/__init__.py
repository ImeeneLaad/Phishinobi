"""
api/
----
Step 3 — REST API wrapper around the Step 1 detection engine.

This package exposes the `predict_url()` function (from src/predict.py)
over HTTP using FastAPI, so external clients — most importantly the future
Chrome extension — can request phishing analysis without importing Python.
"""
