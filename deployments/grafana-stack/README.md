# RSBP — Grafana + Prometheus (operational view)

A lightweight, **Elasticsearch-free** monitoring view that complements the per-alert console
on `http://127.0.0.1:9001/`. Prometheus scrapes the metrics `rsbpd` already exposes; Grafana
renders them. ~300 MB, two containers, Linux host networking.

This is the **"fits your SOC stack"** screen (event rate, detections vs suppressed,
detection latency p50/p95, severity mix). The per-alert syscall-chain detail stays on the
`:9001` console — Prometheus holds metrics, not per-event detail.

## Run

```bash
# one-time: install Docker on the VM
sudo apt-get install -y docker.io docker-compose-v2
sudo usermod -aG docker "$USER"   # then log out/in, or use sudo for the next command

# start the daemon first (it exposes metrics on 127.0.0.1:9090)
cd ~/RSBP && sudo ./bin/rsbpd run --config config/demo.yaml   # in its own terminal

# bring up Grafana + Prometheus
cd ~/RSBP/deployments/grafana-stack
docker compose up -d        # first run pulls the two images (needs internet, once)
```

- **Grafana:** http://localhost:3000 — opens the *"RSBP — Catching Shells at the Kernel"*
  board directly (anonymous viewer, no login on the projector). Admin login if you need to
  edit: `admin` / `rsbp-demo`.
- **Prometheus:** http://localhost:9091 (query/debug only).

## View it from your laptop (headless VM)

Add Grafana's port to your SSH tunnel alongside the console:

```powershell
gcloud compute ssh rsbp-demo --zone asia-south1-a -- -N -L 3000:127.0.0.1:3000 -L 9001:127.0.0.1:9001
```

Then open **http://localhost:3000** (Grafana) and **http://localhost:9001** (alert console)
on your laptop. Press F11 for fullscreen on either.

## Stop

```bash
docker compose down
```

## Notes

- Host networking is required so Prometheus can scrape the daemon's loopback metrics
  endpoint (Linux only). Prometheus serves its UI on **9091** to avoid clashing with the
  daemon's metrics port (**9090**).
- Only the *monitoring* stack touches the network here; the **detection path stays offline**.
- This replaces the old, heavier Elasticsearch/Kibana/Filebeat stack in
  `deployments/monitoring/` for demo purposes.
