# ProcessShield - Build, Install & Beta-Test Guide

This walks you from source to a running beta, using **Visual Studio 2022**. CLI
equivalents are given where useful. Read section 0 first.

---

## 0. Safety first (read this)

ProcessShield **suspends and can kill processes, adds Windows Firewall rules, and
moves files to quarantine**. Do **not** run it on a machine you care about.

- Use a **disposable Windows 10/11 x64 VM** (Hyper-V, VMware, or VirtualBox).
- Take a **VM snapshot** before you start so you can roll back.
- Keep `autoKill` = `false` (the default) during early testing so contained
  processes are only suspended, not terminated.

---

## 1. Prerequisites

| Need | For |
|------|-----|
| Windows 10/11 x64 (or Server 2019/2022), in a VM | running the agent (ETW + admin) |
| **Visual Studio 2022 17.8+** with the **".NET desktop development"** workload | building the solution |
| .NET 8 SDK | included with that VS workload (or install standalone for CLI) |
| Local **Administrator** rights | ETW kernel session, process access, service control |
| *(optional)* **Windows Driver Kit (WDK)** matching your VS | building the kernel minifilter (section 9) |

Nothing extra is needed for the default build. YARA and the kernel driver are
opt-in (sections 7 and 9).

---

## 2. Get the code onto the VM

1. Copy `ProcessShield.zip` into the VM and unzip it. You'll get a `ProcessShield\`
   folder containing **`ProcessShield.sln`**.
2. Folder map:
   - `ProcessShield.csproj` - the agent (app)
   - `tests\ProcessShield.Tests\` - the xUnit test project
   - `kernel\ShieldFilter\` - the C minifilter (built separately with the WDK)
   - `rules\` - sample YARA rules
   - `tools\simulate-benign-stealer.ps1` - the safe detection demo
   - `shield.config.json` - configuration

---

## 3. Build in Visual Studio

1. **Double-click `ProcessShield.sln`** to open it in Visual Studio 2022.
2. Wait for **NuGet restore** (watch the status bar). If it doesn't start
   automatically: right-click the solution in Solution Explorer -> **Restore
   NuGet Packages**. (First restore needs internet: it pulls TraceEvent,
   System.Management, and Microsoft.Extensions.Hosting[.WindowsServices].)
3. In the top toolbar set the two dropdowns to **`Release`** and **`x64`**.
   (Both projects are x64-only; `x64` is the only platform offered.)
4. **Build -> Build Solution** (`Ctrl+Shift+B`). You should get
   **`Build: 2 succeeded, 0 failed`**.

**Output:** `bin\x64\Release\net8.0-windows\ProcessShield.exe` (plus its DLLs).

> CLI equivalent:
> ```
> dotnet build ProcessShield.csproj -c Release
> ```

---

## Desktop GUI (ProcessShield.Gui)

Besides the console, the solution includes a **WPF desktop app** — a dark
instrument-panel dashboard. It shows current posture, a live table of contained and
flagged processes with one-click **Release / Suspend / End process**, a live event
feed, and a Settings editor that writes `shield.config.json` (threshold and
allowlist changes apply live).

Build the solution (section 3), then run it either way:
- **Visual Studio:** right-click **ProcessShield.Gui** in Solution Explorer ->
  **Set as Startup Project**, then **Debug -> Start** (F5). It requests administrator
  rights through its manifest, so a UAC prompt appears automatically.
- **Or** run `ProcessShield.Gui.exe` from
  `gui\ProcessShield.Gui\bin\x64\Release\net8.0-windows\`.

It drives the same engine as the console — use whichever you prefer. The
detection walkthrough below works with either front-end.

---

## 4. Run the unit tests

- In VS: **Test -> Run All Tests** (opens Test Explorer). All tests should pass.
  They cover the exfil-chain scoring, the audit hash-chain (incl. tamper
  detection), config clamping, the firewall-name sanitizer, the routable-IP check,
  and the pattern matcher.

> CLI equivalent:
> ```
> dotnet test tests\ProcessShield.Tests\ProcessShield.Tests.csproj -c Release
> ```

---

## 5. Run the agent interactively (the main beta loop)

The agent **requires elevation**. Double-clicking the `.exe` now pops a **UAC
prompt** and relaunches itself elevated (accept it, and an elevated console opens
at the `shield>` prompt). If anything fails at startup the window stays open with
the error and a "Press Enter to close" pause, so it won't just vanish anymore.

For the cleanest experience, run it from an elevated terminal. Pick one:

**Option A - elevated terminal (recommended, simplest):**
1. Open **Windows Terminal** or **cmd** via right-click -> **Run as administrator**.
2. `cd` into the build output folder, e.g.:
   ```
   cd C:\path\to\ProcessShield\bin\x64\Release\net8.0-windows
   ```
3. Run:
   ```
   ProcessShield.exe
   ```

**Option B - from Visual Studio:** right-click Visual Studio -> **Run as
administrator**, reopen the solution, make `ProcessShield` the startup project,
then **Debug -> Start Without Debugging** (`Ctrl+F5`). If VS is *not* elevated the
app prints `Run as Administrator` and exits by design - use Option A.

You should see it start the ETW monitor and print the prompt:
```
[*] ProcessShield active (console mode). Monitors: ETW(process,image,file,network), FileStaging.
shield>
```

**Console commands:** `list` / `list all`, `info N`, `resume N`, `suspend N`,
`kill N`, `stats`, `reload` (re-read config), `audit` (verify the tamper-evident
log), `quit`.

---

## 6. Trigger a detection safely

With the agent running (section 5), open a **second** elevated PowerShell and run
the included harmless simulator:

```
powershell -ExecutionPolicy Bypass -File .\tools\simulate-benign-stealer.ps1
```

It reproduces the **collect -> archive -> exfil** shape without stealing anything:
it writes a dummy file on a path containing `\Google\Chrome\User Data\...\Login
Data` under `%TEMP%`, zips it into `%TEMP%`, and opens/closes a TCP connection to
`1.1.1.1:443`. That crosses the quarantine threshold, so ProcessShield will
**suspend that PowerShell process**.

Now switch to the ProcessShield console:
```
shield> list
  #   PID     SCORE  STATE                NAME
  1   7364    90     contained            powershell.exe
shield> info 1        # see the full [+points] reason breakdown
shield> resume 1      # release it  (or:  kill 1)
```

The simulator sleeps ~90s so you can observe and resume it, then cleans up its
dummy files.

> If ETW couldn't start (you'll see it fall back to WMI), file/network events are
> not captured and only process-start heuristics fire - make sure you launched
> elevated.

---

## 7. Optional: build with the YARA engine

YARA is **off by default** so the standard build has no third-party native/API
dependency. To enable it:

```
dotnet build ProcessShield.csproj -c Release -p:EnableYara=true
```
(In Visual Studio, open **Tools -> Command Line -> Developer PowerShell** and run
the same command, or add `<EnableYara>true</EnableYara>` to a
`Directory.Build.props` at the repo root.)

Then set `"memoryScanEngine": "yara"` in `shield.config.json`. If the installed
dnYara build doesn't match, the agent logs a warning and falls back to the builtin
scanner automatically - it won't crash.

---

## 8. Optional: install as a Windows Service (longer soak testing)

The service host needs a **self-contained** executable so its binPath is the app
itself (not `dotnet.exe`).

1. Publish self-contained:
   ```
   dotnet publish ProcessShield.csproj -c Release -r win-x64 --self-contained true -o publish
   ```
   (VS: right-click the project -> **Publish** -> Folder -> target `win-x64`,
   deployment mode **Self-contained**.)
2. From an **elevated** prompt in the `publish` folder:
   ```
   ProcessShield.exe --install
   ```
   This registers and starts the `ProcessShield` service (with auto-restart
   recovery) plus a SYSTEM **watchdog** scheduled task.
3. Verify:
   ```
   sc query ProcessShield
   ```
   Events stream to the configured `incidents.jsonl` and `audit.log`.
4. Remove it when done:
   ```
   ProcessShield.exe --uninstall
   ```

> Tamper note: the watchdog + service recovery restart the agent if it crashes or
> is stopped, but an administrator can still kill both. True kill-resistance needs
> PPL/ELAM, which requires Microsoft's anti-malware vendor program (out of scope).

---

## 9. Optional: the kernel minifilter (advanced, lab only)

Real inline prevention. Built **separately** with the WDK.

1. Install the **WDK** matching your VS 2022.
2. In VS: **New Project -> "Filter Driver: Filesystem Mini-Filter"**. Add
   `kernel\ShieldFilter\ShieldFilter.c`, `.h`, and `.inf` to it. Build **x64 /
   Release** to produce `ShieldFilter.sys`.
3. In the VM, enable test signing and reboot:
   ```
   bcdedit /set testsigning on
   ```
   Then install + load (see full steps in `kernel\ShieldFilter\README.md`):
   ```
   RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 128 .\ShieldFilter.inf
   fltmc load ShieldFilter
   ```
4. The agent's `MinifilterClient` auto-connects to `\ShieldFilterPort` and pushes
   policy on startup.

> Keep `"kernelBlocking": false` unless you've extended the driver with a
> trusted-PID allowlist (per the driver README) - with it `true`, the skeleton
> denies **every** process access to sensitive paths, including legitimate apps.
> Production loading (no test signing) requires attestation/EV signing + a
> Microsoft-assigned altitude.

---

## 10. Configuration (`shield.config.json`)

Key settings:
- `detection.warnThreshold` / `quarantineThreshold` - scoring cutoffs.
- `detection.autoKill` - `false` = suspend only (recommended for beta).
- `detection.memoryScanEngine` - `"builtin"` or `"yara"`.
- `allowlist.publishers` / `thumbprints` - signed apps to de-prioritise (e.g. your
  legitimate RMM tools); pin exact SHA-1 thumbprints for strongest trust.
- `telemetry.syslog` / `webhook` - set `enabled` + endpoint to forward to a SIEM.

Editing the file **hot-reloads** the detection posture and allowlist live (the
console prints `config applied: ...`). Scan-engine and telemetry-endpoint changes
take effect on restart.

---

## 11. Telemetry & audit

- `incidents.jsonl` - one JSON line per WARN/QUARANTINE/ACTION event.
- `audit.log` - the same events in a **SHA-256 hash chain**; run `audit` in the
  console (or `AuditLogSink.Verify`) to prove nothing was altered or deleted.

---

## 12. Troubleshooting

| Symptom | Fix |
|---------|-----|
| App prints `Run as Administrator` and exits | Launch from an elevated terminal (section 5, Option A). |
| Window flashed open and closed on double-click (older build) | The app now self-elevates via UAC; accept the prompt, or run from an elevated terminal. |
| Falls back to `WMI(process)` only | You're not elevated, or ETW is blocked; file/network correlation is limited until ETW works. |
| Build error about platform / `AnyCPU` | Set the VS platform dropdown to **x64**. |
| NuGet restore fails | Check the VM's internet/proxy; retry **Restore NuGet Packages**. |
| `--install` says it needs a self-contained exe | You ran it from a framework-dependent build; publish self-contained first (section 8). |
| YARA build errors | Only happens with `-p:EnableYara=true`; the default build doesn't reference dnYara. |
| Nothing detects during the sim | Confirm the agent started ETW (not WMI) and that you ran the sim **after** the agent. |
| GUI shows a red banner, a warning dialog, or won't start | It logs to `%LOCALAPPDATA%\ProcessShield\gui.log` — open that for the exact error. The banner usually means "not running as Administrator." |

---

## 13. Honest status

This is a **hardened prototype plus real integration layers**, audited by review
but not yet run through a full security review or tested against live malware.
Two capabilities are intentionally not shippable here because they're gated behind
Microsoft programs: **PPL/ELAM tamper protection** and **production driver
signing**. See `README.md` -> "Known limitations (beta)".
