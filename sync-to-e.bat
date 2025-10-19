@echo off
setlocal enabledelayedexpansion
set "SRC=C:\Users\Administrator\Downloads\摸金小助手1.4\niao"
set "DST=E:\鸟"
echo Sync start: "%SRC%" -> "%DST%"
if not exist "%DST%" mkdir "%DST%"
robocopy "%SRC%" "%DST%" /MIR /MT:16 /R:1 /W:1 /NFL /NDL /NP /NJH /NJS /XD ".git" ".github" "logs" "node_modules" /XF "*.tmp" "*.log" "*.pyc"
set RC=%ERRORLEVEL%
echo Robocopy exit code: %RC%
if %RC% GEQ 8 (
  echo 同步可能遇到错误（退出码 ^>= 8），请检查输出信息。
) else (
  echo Sync done.
)
exit /b %RC%