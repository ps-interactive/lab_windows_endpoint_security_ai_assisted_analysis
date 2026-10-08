## 1. Observed

Values in angle brackets identify fields in your records. For example, `<SYSMON-1-UTC>` means the `TimeCreatedUtc` in your Sysmon event 1, and `<ENCODED-PROCESS-ID>` means its `ProcessId`. These are reference labels, not values to paste into commands. Use your package for the actual timestamps and identifiers.

- **Sysmon, event 1, `<SYSMON-1-UTC>`, record `<SYSMON-1-RECORD-ID>`:** `Image` names Windows PowerShell. `CommandLine` contains `-WindowStyle Hidden` and `-EncodedCommand`. `ProcessId` identifies `<ENCODED-PROCESS-ID>`, and `ProcessGuid` identifies `<ENCODED-PROCESS-GUID>`. `ParentImage` names PowerShell, and `ParentCommandLine` shows a PowerShell script launched with `-File`. These fields describe the recorded parent; they do not establish who authorized it.
- **PowerShell Operational, event 4104, `<POWERSHELL-4104-UTC>`, record `<POWERSHELL-4104-RECORD-ID>`:** `ProcessId` matches `<ENCODED-PROCESS-ID>`. `MessageNumber` and `MessageTotal` are both `1`. `ScriptBlockText` contains commands to write `C:\ProgramData\GloboMantics\TelemetryCheck.ps1`, register `\GloboMantics\Telemetry Updater`, and set the `GloboManticsTelemetry` Run value. The text placed in the payload uses `Add-Content` to append a UTC timestamp to `execution.log`.
- **Security, event 4698, `<SECURITY-4698-UTC>`, record `<SECURITY-4698-RECORD-ID>`:** `TaskName` is `\GloboMantics\Telemetry Updater`. In `TaskContent`, `Actions/Exec/Command` is `powershell.exe`, and `Actions/Exec/Arguments` names `TelemetryCheck.ps1`. The XML includes a logon trigger, an interactive-token principal, and `LeastPrivilege`. `Settings/Enabled` is `true`.
- **Sysmon, event 13, `<SYSMON-13-UTC>`, record `<SYSMON-13-RECORD-ID>`:** `EventType` is `SetValue`. `TargetObject` ends with `\Run\GloboManticsTelemetry` under the sanitized user's registry hive. `Details` contains the same PowerShell command and payload path as the task action. `ProcessId` and `ProcessGuid` match the event 1 process.

## 2. AI interpretation

- **High confidence:** The encoded command and the recorded script block describe the same script. Decoding event 1's `CommandLine` as UTF-16LE produces event 4104's `ScriptBlockText` after accounting for line endings. Their process IDs also match.
- **High confidence:** The encoded PowerShell process wrote the Run value. Events 1 and 13 share a process GUID and process ID. Event 13 supplies the value name and data.
- **High confidence:** The task and Run value are related ways to launch the same payload at sign-in. Event 4698's task action matches event 13's value data, and event 4104 contains the corresponding registration commands. This supports a relationship without assuming that event 4698's `ClientProcessId` must equal the encoded process ID.
- **High confidence:** The script text creates a payload designed to append a timestamp to a local file. The four records do not show that payload being launched. Encoding, hidden windows, persistence settings, and the GloboMantics name alone do not establish malicious intent.

## 3. Missing evidence

The package does not establish:

- Whether `TelemetryCheck.ps1` ever ran, completed, or was started by the task or Run value.
- Whether a network connection or transfer occurred. These four records provide no network evidence supporting a claim that host information was sent outside the computer.
- Who authorized the activity or whether these artifacts are expected in this environment.
- Whether the current task, Run value, or payload still matches the recorded version.
- What happened on other endpoints or outside the selected time window.

An existing `execution.log` would support further investigation. Its existence alone does not prove which program wrote it or which startup mechanism ran. Its absence alone does not prove the payload never ran.

## 4. Local verification steps

Use the `$package` already loaded in the guide. Decode the command as data, then compare it with the script block. Do not execute the decoded text.

```powershell
$process = $package.Records | Where-Object EventId -eq 1
$block = $package.Records | Where-Object EventId -eq 4104
$encoded = ($process.CommandLine -split '-EncodedCommand\s+', 2)[1].Trim()
$decoded = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encoded))
$decoded
($decoded -replace '\r','').Trim() -ceq ($block.ScriptBlockText -replace '\r','').Trim()
$process.ProcessId -eq $block.ProcessId
```

Inspect the current task and compare its XML with event 4698's `TaskContent`.

```powershell
$task = Get-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'
$task.Actions | Format-List Execute, Arguments
$task.Triggers | Format-List
$task.Principal | Format-List UserId, LogonType, RunLevel
Export-ScheduledTask -TaskPath '\GloboMantics\' -TaskName 'Telemetry Updater'
```

Inspect the named value under the same user account whose hive appears in event 13. Compare its data with the task action.

```powershell
$run = Get-ItemPropertyValue 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name GloboManticsTelemetry
$run
$run -ceq "$($task.Actions.Execute) $($task.Actions.Arguments)"
```

Read and hash the payload without running it. Check for the execution log.

```powershell
$payload = 'C:\ProgramData\GloboMantics\TelemetryCheck.ps1'
Get-Content $payload
Get-FileHash $payload -Algorithm SHA256
$marker = 'C:\ProgramData\GloboMantics\execution.log'
Test-Path $marker
if (Test-Path $marker) { Get-Content $marker }
```

Use **Locally confirmed** only for findings supported by these checks. Use **Expected** for behavior predicted from the checked configuration, such as launching the payload at sign-in. Keep that prediction separate from observed execution.

**Proposed fix:** Obtain approval and verify the exact task, value, account, and payload first. Preserve the original logs and hashes, task XML, Run-key export, payload copy, and any execution log. If removal of these startup mechanisms is approved, disable only `\GloboMantics\Telemetry Updater` and remove only `GloboManticsTelemetry`. Keep unrelated tasks, registry values, and files intact. Verify that the named task is disabled and the named value is absent. Disabling the task changes its enabled state and exported XML; compare the remaining settings with the recovery copy. Do not apply these changes as part of this read-only review.
