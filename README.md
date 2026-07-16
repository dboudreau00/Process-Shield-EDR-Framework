# ProcessShield

A user-mode behavioral endpoint agent that detects RAT and infostealer IOCs
(remote-control modules, credential-store access, the collect -> archive -> exfil
chain), scores them with cross-signal correlation, and responds by suspending,
firewalling, and quarantining — with an analyst console, a Windows Service host,
a kernel minifilter for inline prevention, YARA memory scanning, SIEM/audit
telemetry, and hot-reloadable policy.

> Honest scope: this is a **hardened prototype plus real integration layers**, not
> a shippable commercial EDR. Two capabilities are gated behind Microsoft programs
> and cannot be delivered as loadable artifacts here (see "External gates").

## Architecture
- **Monitoring** (`Monitoring/`): ETW kernel session (process/image/file/network,
  PID-attributed) with a WMI fallback, plus a FileSystemWatcher for archive staging.
- **Detection** (`Detection/`): a single-owner (actor) state machine. All profile
  state is mutated by one thread; monitors and the console feed one queue, so there
  are no data races. Thresholds are hot-reloadable.
- **Memory** (`Memory/`): a bounded builtin substring scanner (ASCII + UTF-16) or a
  optional YARA engine (`YaraMemoryScanner`, compiled in with `-p:EnableYara=true`;
  otherwise a stub, so the default build has no dnYara dependency and uses builtin).
- **Response** (`Response/`): suspend-first quarantine, injection-safe firewall block,
  archive quarantine, optional kill; trust decisions via full Authenticode.
- **Security** (`Security/`): `WinVerifyTrust` chain validation + thumbprint pinning.
- **Telemetry** (`Telemetry/`): JSONL + syslog (RFC 5424) + HTTP webhook sinks, plus
  a **hash-chained, tamper-evident audit log** with a verifier.
- **Hosting** (`Hosting/`): Windows Service worker + heartbeat, a mutual **watchdog**,
  and `sc.exe`/`schtasks` install/uninstall.
- **Driver** (`kernel/ShieldFilter/` + `Driver/MinifilterClient.cs`): a real FS
  minifilter that denies opens of sensitive paths, driven by policy from the agent.

## Build & run

There are two front-ends: a **console** (`ProcessShield.exe`) and a **WPF desktop
GUI** (`ProcessShield.Gui.exe`) with a live dashboard, event feed, and settings editor.

**New to this? Follow [`GETTING_STARTED.md`](GETTING_STARTED.md)** for step-by-step
Visual Studio instructions (build -> test -> run -> install -> beta), including a
safe detection-simulation script. In short: open **`ProcessShield.sln`** in Visual
Studio 2022, set **Release / x64**, and Build Solution. CLI equivalents:

```
dotnet build ProcessShield.csproj -c Release                 # default: builtin memory scanner
dotnet build ProcessShield.csproj -c Release -p:EnableYara=true   # optional: add the dnYara YARA engine
# interactive (Administrator):
ProcessShield.exe
# service:
ProcessShield.exe --install        # publish self-contained first (see below)
ProcessShield.exe --uninstall
```
For the service, publish a self-contained exe so the service binPath is the app
itself, not dotnet.exe:
```
dotnet publish -c Release -r win-x64 --self-contained true
# then, from the publish folder, as Administrator:
ProcessShield.exe --install
```

## Analyst console
`list [all]`, `info N`, `resume N`, `suspend N`, `kill N`, `stats`, `reload`
(re-reads config), `audit` (verifies the audit chain), `quit`.

## Configuration (`shield.config.json`)
Thresholds, allowlist (publishers + pinned thumbprints), scan engine
(`builtin`/`yara`), telemetry sinks, and service/heartbeat settings. Editing the
file hot-reloads the **posture + allowlist** live; scan-engine and telemetry
endpoint changes take effect on restart.

## Tests
```
dotnet test tests/ProcessShield.Tests
```
Covers the exfil-chain scoring, trust discount, parent/child and command-line
rules, the pattern matcher (incl. cross-chunk), the firewall-name sanitizer, the
audit hash chain (including tamper detection), config clamping, and ActionResult.

## Kernel minifilter
See `kernel/ShieldFilter/README.md` for building with the WDK, lab test-signing,
and loading. The agent connects via `MinifilterClient` and pushes policy; if the
driver is not installed, kernel enforcement is simply unavailable and user-mode
detection continues.

## External gates (cannot be delivered as loadable artifacts)
- **Tamper protection via PPL/ELAM**: requires being an approved anti-malware
  vendor and having an ELAM driver attestation-signed by Microsoft. The watchdog +
  service recovery here raise the bar, but an admin attacker can still kill both.
- **Production driver signing**: loading the minifilter on non-test machines needs
  attestation/WHQL or EV signing via the Partner Center, plus a Microsoft-assigned
  altitude. The driver builds and runs in a test-signed lab as-is.

## Known limitations (beta)
- **Archive quarantine for ETW-detected files**: ETW kernel file events report
  `\Device\HarddiskVolumeN\...` paths, which `System.IO` cannot open directly, so
  the *move-to-quarantine* step no-ops for those (it fails safe, and suspend +
  firewall containment still apply). Archives caught by the FileSystemWatcher use
  normal drive-letter paths and quarantine correctly. Device-path translation is a
  planned follow-up.
- **`kernelBlocking: true` is aggressive**: the skeleton driver denies *any* open of
  a sensitive path while blocking is on, including legitimate apps. Leave it off
  until the trusted-PID allowlist extension (see the driver README) is added.
- **Not yet done**: red-team runs against live samples, perf/soak testing, and a
  driver security review still stand between this and production.

## Notes / files most likely to need a per-environment tweak
The two integration points most likely to need a small
adjustment are `Memory/YaraMemoryScanner.cs` (only when built with
`-p:EnableYara=true`; dnYara method names vary by version, and it fails safe to the
builtin scanner) and `Driver/MinifilterClient.cs`
(must match the installed driver's message layout).
