; Sentinella NSIS installer hooks
; Runs with elevated privileges during install/uninstall.
;
; INSTDIR     = where Tauri installs the GUI app (e.g., C:\Program Files\Sentinella)
; Resources   = resolved to $SENTI_DAEMON\*
; PROGRAMDATA = C:\ProgramData\Sentinella (PathManager root in installed mode)

!macro NSIS_HOOK_PREINSTALL
  ; Stop the old daemon before Tauri writes files. Otherwise Windows keeps
  ; sentinelld.exe locked and NSIS leaves the previous engine binary installed.
  nsExec::ExecToLog 'taskkill /F /IM gui.exe'
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'
  nsExec::ExecToLog 'taskkill /F /IM argusd.exe'
  nsExec::ExecToLog 'taskkill /F /IM freshclam.exe'
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 3000
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; Set PROGRAMDATA variable explicitly (NSIS doesn't have a clean built-in).
  Var /GLOBAL SENTI_DATA
  Var /GLOBAL SENTI_DAEMON
  StrCpy $SENTI_DATA "$PROFILE\..\..\ProgramData\Sentinella"
  ; Fallback: use known absolute path.
  StrCpy $SENTI_DATA "C:\ProgramData\Sentinella"
  ; Tauri 2 NSIS unpacks bundle.resources to $INSTDIR\daemon (mapping preserved).
  ; Fallback to $INSTDIR\resources\daemon in case Tauri version changes behavior.
  StrCpy $SENTI_DAEMON "$INSTDIR\daemon"
  IfFileExists "$SENTI_DAEMON\sentinelld.exe" +2 0
    StrCpy $SENTI_DAEMON "$INSTDIR\resources\daemon"

  ; === Create ProgramData directory structure ===
  CreateDirectory "$SENTI_DATA"
  CreateDirectory "$SENTI_DATA\config"
  CreateDirectory "$SENTI_DATA\signatures"
  CreateDirectory "$SENTI_DATA\state"
  CreateDirectory "$SENTI_DATA\logs"
  CreateDirectory "$SENTI_DATA\quarantine"
  CreateDirectory "$SENTI_DATA\cache"
  CreateDirectory "$SENTI_DATA\argus"
  CreateDirectory "$SENTI_DATA\argus\rules"
  CreateDirectory "$SENTI_DATA\argus\rules\yara"
  CreateDirectory "$SENTI_DATA\argus\manifests"
  CreateDirectory "$SENTI_DATA\rules"
  CreateDirectory "$SENTI_DATA\clamav_tmp"
  CreateDirectory "$SENTI_DATA\diagnostics"
  CreateDirectory "$SENTI_DATA\enhanced_signatures"
  CreateDirectory "$SENTI_DATA\update_staging"

  ; === Copy config templates (don't overwrite existing) ===
  IfFileExists "$SENTI_DATA\config\freshclam.conf" +2 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\config\freshclam.conf" "$SENTI_DATA\config\"
  IfFileExists "$SENTI_DATA\config\sentinelld.toml" +2 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\config\sentinelld.toml" "$SENTI_DATA\config\"

  ; === Copy YARA rules ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\argus\rules\yara\*.yar" "$SENTI_DATA\argus\rules\yara\"

  ; === Copy manifests ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\argus\manifests\*.*" "$SENTI_DATA\argus\manifests\"

  ; === Copy IOC hashes ===
  CopyFiles /SILENT "$SENTI_DAEMON\runtime\rules\*.*" "$SENTI_DATA\rules\"

  ; === Copy bootstrap ClamAV signatures (only if no signatures present) ===
  ; This avoids overwriting newer signatures from a previous install/freshclam.
  IfFileExists "$SENTI_DATA\signatures\main.cvd" skip_bootstrap 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\*.sign" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\freshclam.dat" "$SENTI_DATA\signatures\"
  skip_bootstrap:

  ; === Stop existing service if running (upgrade scenario) ===
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 2000

  ; === Delete old service if exists (upgrade) ===
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000

  ; === Register Windows service (no --foreground → uses Windows Service API) ===
  nsExec::ExecToLog 'sc create SentinellaDaemon binPath= "\"$SENTI_DAEMON\sentinelld.exe\" --log-level info --runtime-root \"$SENTI_DATA\" --dll-dir \"$SENTI_DAEMON\" --db-dir \"$SENTI_DATA\\signatures\"" DisplayName= "Sentinella Protection Service" start= delayed-auto obj= "LocalSystem"'

  ; === Set service description ===
  nsExec::ExecToLog 'sc description SentinellaDaemon "Sentinella antivirus daemon with ClamAV signatures and ARGUS heuristic intelligence engine."'

  ; === Configure failure recovery: restart on failure ===
  nsExec::ExecToLog 'sc failure SentinellaDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000'

  ; Signature updates are handled by the daemon scheduler (every N hours).
  ; Bootstrap signatures shipped with installer get user protected immediately.

  ; === Start the service ===
  nsExec::ExecToLog 'sc start SentinellaDaemon'

  ; === Register GUI autostart at login (per-machine, all users) ===
  ; HKLM Run key: launches Sentinella.exe at user login.
  ; --minimized so it starts in tray without showing main window.
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinella" '"$INSTDIR\Sentinella.exe" --minimized'

!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; === Remove autostart registry entry ===
  DeleteRegValue HKLM "Software\Microsoft\Windows\CurrentVersion\Run" "Sentinella"

  ; === Kill GUI if running (so files can be deleted) ===
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  Sleep 500

  ; === Stop and remove service ===
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000
!macroend
