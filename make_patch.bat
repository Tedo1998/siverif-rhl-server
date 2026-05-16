@echo off
set BASE=d:\SOFTWARE\DATABASE VERIFIKASI RHL\NEW VERSION\files_v7.2\Suite_v7_2_0\siverif_build
set TMP=%BASE%\_patch_temp
set VER=12.6.0
set ZIP=%BASE%\patch_v%VER%.zip

if exist "%TMP%" rmdir /s /q "%TMP%"
mkdir "%TMP%\audit-rhl"
mkdir "%TMP%\admin-panel"

copy "%BASE%\audit-rhl\SiVerif_RHL_Ultimate_v12.html" "%TMP%\audit-rhl\" >nul
copy "%BASE%\admin-panel\index.html" "%TMP%\admin-panel\" >nul
copy "%BASE%\electron-builder\launcher.html" "%TMP%\" >nul
copy "%BASE%\electron-builder\splash.html" "%TMP%\" >nul
echo {"version":"%VER%"} > "%TMP%\patch-version.json"

if exist "%ZIP%" del /f "%ZIP%"
powershell -Command "Compress-Archive -Path '%TMP%\*' -DestinationPath '%ZIP%' -Force"

rmdir /s /q "%TMP%"
echo.
echo  === patch_v%VER%.zip created successfully ===
