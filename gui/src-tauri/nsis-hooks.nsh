; Sentinella NSIS installer hooks
; Runs with elevated privileges during install/uninstall.
;
; INSTDIR     = where Tauri installs the GUI app (e.g., C:\Program Files\Sentinella)
; Resources   = resolved to $SENTI_DAEMON\*
; PROGRAMDATA = C:\ProgramData\Sentinella (PathManager root in installed mode)

!macro NSIS_HOOK_PREINSTALL
  ; ORDER IS LOAD-BEARING, for the same reason it is in PREUNINSTALL.
  ;
  ; An UPGRADE does not run the old uninstaller: installer.nsi skips it in
  ; update mode, and the non-uninstall radio choice skips it interactively.
  ; So NSIS_HOOK_PREUNINSTALL — which holds the careful --remove ladder — is
  ; NOT executed on the upgrade path. This hook is the only thing that runs.
  ;
  ; It used to `taskkill /F` sentinelld.exe first. That destroys the only
  ; in-process path that removes the NRPT rule (WebProtection::stop), so
  ; every upgrade left a catch-all rule routing all DNS at a port whose
  ; listener had just been killed. For the length of the install the machine
  ; had NO DNS, and if the install then aborted it stayed that way until the
  ; next reboot, with the service already deleted.
  ;
  ; So: ask nicely first, and remove the rule explicitly before resorting to
  ; force.

  ; 1. Graceful stop. Lets the daemon run its own shutdown, which removes the
  ;    rule and is the only path that also stops the proxy cleanly.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000

  ; 2. Belt and braces: remove the rule out-of-process, whether or not the
  ;    daemon was running or managed to do it itself. This is the OLD
  ;    install's binary — PREINSTALL runs before Tauri overwrites files, so
  ;    it is still on disk. Missing (fresh install, or an older version that
  ;    predates the reconciler) is fine: there is no rule to remove.
  IfFileExists "$INSTDIR\daemon\sentinella-dnsreconcile.exe" 0 +3
    nsExec::ExecToLog '"$INSTDIR\daemon\sentinella-dnsreconcile.exe" --remove'
    Goto senti_rule_done
  IfFileExists "$INSTDIR\resources\daemon\sentinella-dnsreconcile.exe" 0 +2
    nsExec::ExecToLog '"$INSTDIR\resources\daemon\sentinella-dnsreconcile.exe" --remove'
  senti_rule_done:

  ; 3. Only now force. Otherwise Windows keeps sentinelld.exe locked and NSIS
  ;    leaves the previous engine binary installed.
  nsExec::ExecToLog 'taskkill /F /IM gui.exe'
  nsExec::ExecToLog 'taskkill /F /IM Sentinella.exe'
  nsExec::ExecToLog 'taskkill /F /IM sentinelld.exe'
  nsExec::ExecToLog 'taskkill /F /IM argusd.exe'
  nsExec::ExecToLog 'taskkill /F /IM freshclam.exe'
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

  ; === Register the boot-time NRPT reconciler task ===
  ;
  ; WHY THIS IS HERE AND NOT IN THE DAEMON. Web protection points the whole
  ; machine's DNS at a local proxy using a Name Resolution Policy Table rule.
  ; That rule lives in the registry and SURVIVES REBOOTS, while the service
  ; above is delayed-auto. So the dangerous state is not "the proxy crashed"
  ; - it is "the rule is installed and nothing is answering", which is a
  ; machine with no name resolution at all, on every subsequent boot, for a
  ; user who cannot search for the fix because search does not resolve.
  ;
  ; The reconciler runs at startup, before the daemon, and removes the rule
  ; unless the proxy answers with a signature only it can produce. It is the
  ; ONLY thing that removes rules when the daemon is not around. Registering
  ; it at INSTALL time is what makes it exist before the first rule can: the
  ; daemon refuses to install a rule while this task is missing or disabled.
  ;
  ; The binary registers its own task (the task XML must name its absolute
  ; path, which only the running exe knows) and writes settings that the
  ; schtasks command line cannot express - DisallowStartIfOnBatteries alone
  ; would stop a laptop from ever reconciling.
  ;
  ; A failure here is SAFE: no task means the daemon refuses to install a
  ; rule, so web protection stays off. Logged, not fatal.
  nsExec::ExecToLog '"$SENTI_DAEMON\sentinella-dnsreconcile.exe" --install-task'

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
  ; Stopping first gives the daemon its own chance to remove the rule
  ; cleanly, before we do it the blunt way below.
  nsExec::ExecToLog 'sc stop SentinellaDaemon'
  Sleep 3000
  nsExec::ExecToLog 'sc delete SentinellaDaemon'
  Sleep 1000

  ; === Remove the NRPT rule, THEN its reconciler task ===
  ;
  ; ORDER IS LOAD-BEARING and this is the only place it can be enforced:
  ; both must happen BEFORE the uninstaller deletes the files, because the
  ; executable that knows how to do either is one of those files. Removing
  ; the task first would delete the remover while a rule is still live;
  ; letting the files go first would delete both.
  Var /GLOBAL SENTI_UNINST_DAEMON
  StrCpy $SENTI_UNINST_DAEMON "$INSTDIR\daemon"
  IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" +2 0
    StrCpy $SENTI_UNINST_DAEMON "$INSTDIR\resources\daemon"

  IfFileExists "$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" 0 no_reconciler
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove'
    Pop $0
    StrCmp $0 "0" rule_gone 0
      ; The rule could NOT be removed and this machine's DNS is currently
      ; pointed at a proxy we are about to delete. Aborting is the
      ; unfriendly-but-recoverable outcome; continuing is the unrecoverable
      ; one - the reconciler task and its binary would both go, leaving a
      ; rule nothing can ever undo.
      ;
      ; Everything stays in place, so the next boot's reconciler removes the
      ; rule and a retried uninstall then succeeds.
      MessageBox MB_ICONSTOP|MB_OK "Sentinella could not remove its DNS policy rule.$\n$\nUninstalling now would leave this machine unable to resolve names. Please reboot and run the uninstaller again - Sentinella removes the rule automatically at startup.$\n$\nDetails: %ProgramData%\Sentinella\logs\dnsreconcile.log"
      Abort
    rule_gone:
    ; Only now, with the rule provably gone, may the remover be removed.
    ; The binary refuses this itself if a rule is somehow still present.
    nsExec::ExecToLog '"$SENTI_UNINST_DAEMON\sentinella-dnsreconcile.exe" --remove-task'
    Goto senti_uninst_rule_done

  no_reconciler:
    ; The remover is gone but a rule may not be. This used to be a bare label:
    ; the uninstall skipped both steps in silence and deleted everything
    ; anyway, which is the one unrecoverable outcome — a live catch-all rule
    ; with the product, its reconciler, and its scheduled task all removed,
    ; and no reboot that fixes it because the thing the boot task ran is gone.
    ;
    ; We cannot query the registry for the rule without the binary, but the
    ; GUID state file is written BEFORE the rule is ever created, so its
    ; presence is a sound over-approximation of "a rule may exist". Its
    ; absence proves none was.
    Var /GLOBAL SENTI_UNINST_PD
    ReadEnvStr $SENTI_UNINST_PD "ProgramData"
    StrCmp $SENTI_UNINST_PD "" 0 +2
      StrCpy $SENTI_UNINST_PD "C:\ProgramData"
    IfFileExists "$SENTI_UNINST_PD\Sentinella\state\nrpt-rule.guid" 0 senti_uninst_rule_done
      MessageBox MB_ICONSTOP|MB_YESNO|MB_DEFBUTTON2 "Sentinella cannot find sentinella-dnsreconcile.exe, which is the only tool that can remove its DNS policy rule.$\n$\nThis machine may currently route all DNS through Sentinella. Uninstalling now could leave it unable to resolve names, with nothing left to undo it.$\n$\nRepair or reinstall Sentinella first, then uninstall.$\n$\nContinue anyway?" IDYES senti_uninst_rule_done
      Abort

  senti_uninst_rule_done:
!macroend
