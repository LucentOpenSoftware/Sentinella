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
  ; Resolve ProgramData via env var (handles non-C: system drives).
  Var /GLOBAL SENTI_DATA
  Var /GLOBAL SENTI_DAEMON
  Var /GLOBAL SENTI_PD
  ReadEnvStr $SENTI_PD "ProgramData"
  StrCmp $SENTI_PD "" 0 +2
    StrCpy $SENTI_PD "C:\ProgramData"
  StrCpy $SENTI_DATA "$SENTI_PD\Sentinella"
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
  ; Skip bootstrap if EITHER main.cvd OR main.cld exists.
  ; freshclam switches from .cvd to incremental .cld; checking only .cvd would
  ; cause stale bootstrap .cvd to land next to newer .cld → mixed-version DB.
  IfFileExists "$SENTI_DATA\signatures\main.cvd" skip_bootstrap 0
  IfFileExists "$SENTI_DATA\signatures\main.cld" skip_bootstrap 0
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\main.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\daily.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\bytecode.cvd" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\*.sign" "$SENTI_DATA\signatures\"
    CopyFiles /SILENT "$SENTI_DAEMON\runtime\signatures_bootstrap\freshclam.dat" "$SENTI_DATA\signatures\"
  skip_bootstrap:

  ; === Stop existing service if running (upgrade scenario) ===
  ; Poll until STATE != RUNNING/STOP_PENDING. Slow IO machines need >2s for
  ; clean stop after libclamav.dll DLL flush; old fixed Sleep 2000 raced ahead
  ; and the subsequent sc delete then went into DELETE_PENDING, breaking
  ; sc create on next install. Cap at 30s.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Var /GLOBAL STOP_TRIES
  StrCpy $STOP_TRIES 0
  poll_stopped:
    Sleep 1000
    IntOp $STOP_TRIES $STOP_TRIES + 1
    nsExec::Exec 'cmd /c sc query SentinellaDaemon | findstr /C:": 1 "'
    Pop $0
    StrCmp $0 "0" stopped_ok 0
    IntCmp $STOP_TRIES 30 stopped_ok 0 stopped_ok
    Goto poll_stopped
  stopped_ok:

  ; === Delete old service if exists (upgrade) ===
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  ; Poll until "service does not exist" (exit 1060). Cap at 15s.
  Var /GLOBAL DEL_TRIES
  StrCpy $DEL_TRIES 0
  poll_deleted:
    Sleep 1000
    IntOp $DEL_TRIES $DEL_TRIES + 1
    nsExec::Exec 'cmd /c sc query SentinellaDaemon'
    Pop $0
    StrCmp $0 "1060" deleted_ok 0
    IntCmp $DEL_TRIES 15 deleted_ok 0 deleted_ok
    Goto poll_deleted
  deleted_ok:

  ; === Register Windows service (no --foreground → uses Windows Service API) ===
  nsExec::ExecToLog 'sc create SentinellaDaemon binPath= "\"$SENTI_DAEMON\sentinelld.exe\" --log-level info --runtime-root \"$SENTI_DATA\" --dll-dir \"$SENTI_DAEMON\" --db-dir \"$SENTI_DATA\signatures\"" DisplayName= "Sentinella Protection Service" start= delayed-auto obj= "LocalSystem"'

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
