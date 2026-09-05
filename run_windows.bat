@echo off
echo Starting TraceMail AI backend...
call .venv\Scripts\activate
uvicorn app.main:app --reload --port 8000
pause
