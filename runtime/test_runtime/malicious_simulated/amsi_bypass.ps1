# Simulated malicious: AMSI bypass phrases.
# SAMPLE ONLY — NOT EXECUTED. Should score 40-70+.
# These are known AMSI bypass string patterns that real malware uses.
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
$a = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
[System.Runtime.InteropServices.Marshal]::WriteByte($a, 0, 0x80)
$patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
