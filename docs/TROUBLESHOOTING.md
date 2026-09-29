# Troubleshooting

## "It says connected / does not connect / no internet"

Every client keeps a log of each connection stage and every OS command it ran:

- **Windows**: the app has *Show log* / *Copy log*; the same text is in `mcvpn.log` next to `mcvpn.exe`.
- **Android**: the *LOG / COPY* button (includes device model and Android version).
- **Server**: `journalctl -u mcvpn -n 80 --no-pager` — a client that fails after the
  handshake leaves a line `client session ended with error peer=… error=…`.

Stages logged by a client (a healthy connect shows all of them):
`connecting (TCP)` → `TCP connected` → `login: encryption request received` →
`login: encryption enabled` → `login: success` → `tunnel authenticated` →
`creating the network device` → `VPN is up`.
The last line printed is where it stopped.

| Symptom (log ends at…) | Meaning |
|---|---|
| `TCP connect failed` | Address/port wrong, firewall closed TCP 25565, or the ISP blocks it |
| `kicked: You are not whitelisted…` | Wrong token (paste the `mcvpn://…` link instead of typing) |
| `kicked: The server is full!` | `max_clients` reached (server config), or a server older than v0.1.4 that was bricked by one failed login: `systemctl restart mcvpn` and update |
| `device setup failed` + `routing failed` | Windows could not install routes; the log has the exact `route`/`netsh` output |
| `VPN is up` but the app warns *Windows is not sending traffic into the VPN* | Routes were installed but the OS does not use them; send the log |
| `TUN self-test FAILED` (server) | The VPS does not fully support TUN networking (LXC/OpenVZ) |

## Sharing one token

One token can be given to any number of users: every connection gets its own
tunnel IP and a random player name, and `max_clients` (default 256) is the cap.
