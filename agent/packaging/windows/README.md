# ZaqorinCore Agent — Windows service install

The Windows agent runs as a service via
[WinSW](https://github.com/winsw/winsw) (Windows Service
Wrapper), a small executable that wraps any binary as a
Windows service. This directory ships:

- `zaqorin-agent-service.xml` — the WinSW config (service
  id, start mode, restart policy, log rotation, etc.)
- `install.cmd` — drops the agent binary, the WinSW
  wrapper, the XML into `C:\Program Files\ZaqorinCore\`,
  copies a starter `agent.toml` into
  `C:\ProgramData\ZaqorinCore\`, then installs and
  starts the service.
- `uninstall.cmd` — stops and uninstalls the service,
  removes the install directory, and (after a prompt)
  optionally removes the data directory.

## Install

1. **Download WinSW.** Grab `WinSW-x64.exe` from the
   [latest release](https://github.com/winsw/winsw/releases)
   and rename it to `zaqorin-agent-service.exe`.
2. **Build the agent** on a Linux or Windows build host:
   ```cmd
   make smoke-build
   ```
   This produces `bin\zaqorin-agent-windows-amd64.exe`.
   Rename it to `zaqorin-agent.exe`.
3. **Place all three files** in a temporary directory
   along with `agent.example.toml` from the agent repo:
   ```
   zaqorin-agent.exe
   zaqorin-agent-service.exe
   zaqorin-agent-service.xml
   agent.example.toml
   install.cmd
   ```
4. **Run install as Administrator** (right-click
   `install.cmd` → "Run as administrator", or from an
   elevated cmd):
   ```cmd
   install.cmd
   ```
5. **Edit the config** at
   `C:\ProgramData\ZaqorinCore\agent.toml` with your
   server URL, auth token, and host ID. Restart the
   service:
   ```cmd
   sc stop ZaqorinCoreAgent
   sc start ZaqorinCoreAgent
   ```

## Verify

```cmd
sc query ZaqorinCoreAgent
type "C:\Program Files\ZaqorinCore\zaqorin-agent-service.out.log"
type "C:\ProgramData\ZaqorinCore\logs\agent.log"
```

The first log is WinSW's own log (start/stop events).
The second is the agent's structured JSON log. Look
for `"msg":"agent started"` with `"platform":"windows"`.

## Uninstall

```cmd
uninstall.cmd
```

The script prompts before deleting
`C:\ProgramData\ZaqorinCore\` (which contains logs and
state). Answer `N` to keep the data for a re-install.

## Notes

- The service runs as **LocalSystem** because the agent
  needs to read the Security event log (ACL: only
  SYSTEM, local Administrators, and the Event Log
  Readers group).
- WinSW rotates its own log at 10 MiB, keeping 5 files.
  The agent's own log rotation is configured in
  `agent.toml`.
- The agent handles `--stop` by sending SIGINT to
  itself via a sentinel in the config; the service
  wrapper passes that flag through. Adjust the agent's
  shutdown timeout (`stoptimeout` in the XML) if you
  observe slow shutdowns.
- For development (no service install), just run
  `zaqorin-agent.exe --config agent.toml` from a
  `cmd` window. Stop with Ctrl-C.
