# RSBP — evidence for an industry audience

Two reproducible tools that pre-answer the two hardest questions a detection engineer or
blue-team lead will ask. Both run locally on the VM, produce real numbers (run them
yourself — don't quote anyone else's), and make strong, honest slides.

Start the daemon first in its own terminal:

```bash
sudo ./bin/rsbpd run --config config/demo.yaml
```

---

## 1. Technique coverage matrix — "what do you catch, and what do you miss?"

```bash
sudo ./test/coverage/run_coverage.sh
```

Runs ~9 real reverse-shell techniques (bash `/dev/tcp`, python, perl, ruby, php, nc, ncat,
socat, awk) against the live daemon and prints a table of **detected / missed**, with the
pattern and severity, to the terminal and to `/var/log/rsbp/coverage_report.md`.

**How to present it:** show the table. The hits prove breadth across shells and interpreters;
the honest miss (`awk` via gawk's `/inet/tcp`, which never duplicates the socket onto stdio
and isn't a relay tool) proves you understand your own detection boundary. Veterans trust the
engineer who names the gap. Quote it as **"N / M executed techniques detected"**, never a
percentage, and state which interpreters were installed.

> Install more interpreters to widen the matrix: `sudo apt install perl ruby php-cli gawk`.
> Uninstalled ones are shown as `n/a`, not counted against you.

---

## 2. Overhead benchmark — "what does it cost on a busy host?"

```bash
sudo ./scripts/benchmark.sh 30 4      # 30s load window, 4 generators
```

Generates a local syscall storm and reports, idle vs under load: daemon **CPU%** (of one
core), **RSS**, the sustained **kernel-event rate** RSBP decoded, and **events lost** (ring
buffer overflow). Example of how to read the output is printed at the end.

**How to present it:** state the exact numbers from your run — e.g. *"under a sustained
N-thousand-events/second syscall load, the daemon used X% of one core and ~Y MB RSS, with Z
events lost."* If `lost > 0` at extreme load, say so and note the ring-buffer size is tunable
(`ebpf.ring_buffer_size`). Honesty about the ceiling is more credible than "zero overhead".

---

## Two more honest slides (no code needed)

- **The real false positive you found:** on this very GCP VM, a legitimate Google agent
  (`gce_workload_cert_refresh`) talking to the metadata server (`169.254.169.254`) tripped the
  behavioural signature; you found it, understood why (fork+pipe+dup resembles a shell), and
  tuned it out by suppressing link-local/metadata destinations. A genuine FP-hunt beats any
  accuracy claim.
- **Evasion & limits:** staged/encrypted C2, a payload that never dups onto stdio and isn't a
  relay tool, and container/namespace scope are current boundaries — name them, with a roadmap.

## What NOT to claim
Production-ready · any detection **percentage** · "zero overhead" · low-FP numbers without a
measured corpus · "first/novel eBPF RS detector". State lab-measured facts with their
environment, and you're on solid ground with that room.
