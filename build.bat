@echo off
echo Building IDORaider for Windows...
go build -o idoraider.exe ./cmd/idoraider
if %ERRORLEVEL% EQU 0 (
    echo [OK] Build successful! Run: idoraider.exe -u ^<target^>
) else (
    echo [ERROR] Build failed.
)

