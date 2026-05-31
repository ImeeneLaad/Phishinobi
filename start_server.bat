@echo off
REM ============================================================
REM  Phishinobi - double-click this file to start the server.
REM  Keep the window that opens OPEN while you use the website
REM  or the extension. Close it (or press Ctrl+C) to stop.
REM ============================================================

cd /d "%~dp0"

echo.
echo   Starting Phishinobi server...
echo   When you see "Application startup complete", open:
echo.
echo        http://127.0.0.1:8000/
echo.
echo   Keep this window open. Press Ctrl+C here to stop the server.
echo ============================================================
echo.

python -m uvicorn api.main:app --port 8000

echo.
echo   Server stopped. You can close this window.
pause
