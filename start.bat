@echo off
title ShieldIoT Full-Stack Launcher
echo ===================================================
echo   Starting ShieldIoT Backend (Port 5000)...
echo ===================================================
start "ShieldIoT Backend" cmd /c "node server/index.js"
timeout /t 2 /nobreak >nul
echo.
echo ===================================================
echo   Starting ShieldIoT Vite Frontend (Port 5173)...
echo ===================================================
call npm run dev
pause

