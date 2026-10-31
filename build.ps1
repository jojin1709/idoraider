Write-Host "Building IDORaider for Windows..." -ForegroundColor Cyan
go build -o idoraider.exe ./cmd/idoraider
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] Build successful! Run: .\idoraider.exe -u https://target.com" -ForegroundColor Green
} else {
    Write-Host "[ERROR] Build failed." -ForegroundColor Red
}
