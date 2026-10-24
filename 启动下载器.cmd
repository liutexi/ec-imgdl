@echo off
chcp 65001 >nul
title 云湖防盗链图片下载器
cd /d "%~dp0"

rem ---- 选一个没被占用的端口 ----
set "PORT=8910"
netstat -ano | findstr /c:":8910 " | findstr LISTENING >nul
if not errorlevel 1 set "PORT=8911"
netstat -ano | findstr /c:":8911 " | findstr LISTENING >nul
if not errorlevel 1 set "PORT=8912"
netstat -ano | findstr /c:":8912 " | findstr LISTENING >nul
if not errorlevel 1 set "PORT=8913"

rem ---- 检查 PHP ----
where php >nul 2>&1
if errorlevel 1 (
  echo.
  echo   [X] 没找到 php 命令。
  echo.
  echo       请先安装 PHP 并把它加入系统 PATH；
  echo       或右键本文件 → 编辑，把最后一行 php 改成 php.exe 的完整路径。
  echo.
  pause
  exit /b 1
)

echo.
echo   ============================================
echo      云湖防盗链图片下载器
echo   ============================================
echo.
echo      地址： http://127.0.0.1:%PORT%/
echo      浏览器会自动打开；关闭本窗口即停止服务。
echo.
echo      原理：云湖图片服务器只认 *.jwzhd.com 的
echo      Referer，浏览器直连一律 403。本工具在服务端
echo      补上该请求头再转发，所以能正常取图。
echo.
echo      下载的图片缓存在本目录的 cache\ 下。
echo   ============================================
echo.

start "" /b powershell -NoProfile -WindowStyle Hidden -Command "Start-Sleep -Seconds 2; Start-Process 'http://127.0.0.1:%PORT%/'"

php -S 127.0.0.1:%PORT%
pause
