# SDN Dynamic Host Blocker

An automated network security system using **Software-Defined Networking (SDN)**. The SDN switch handles data forwarding, while the SDN controller monitors network traffic for abnormal TCP connection rates. When an anomaly is detected from an attacking host, the controller dynamically installs a high-priority OpenFlow `DROP` rule on the switch to drop the offending host's traffic at the switch level, allowing legitimate clients to continue uninterrupted.

---

## Repository Structure

```
.
├── topology.py             # Mininet virtual network (1 switch s1, 4 hosts)
├── tcp_server.py           # Multi-threaded TCP server on Target Host (h1)
├── normal_tcp_client.py    # Periodic baseline client on Normal Hosts (h2, h3)
├── attack_tcp_client.py    # High-rate TCP flood client on Attacker Host (h4)
├── controller.py           # SDN Security Controller (flow monitoring & dynamic drop rule)
└── README.md
```

---

## System Architecture & Components

* **Topology (`topology.py`)**:
  Initializes a Mininet network with 1 OpenFlow switch (`s1`) and 4 virtual hosts with fixed IP addresses:
  - `h1`: Target Server (`10.0.0.1`)
  - `h2`: Legitimate Client 1 (`10.0.0.2`)
  - `h3`: Legitimate Client 2 (`10.0.0.3`)
  - `h4`: Attacking Host (`10.0.0.4`)

* **Target Server (`tcp_server.py`)**:
  Runs on `h1:8080`. Accepts incoming TCP connections, sends lightweight responses, and displays live throughput.

* **Legitimate Clients (`normal_tcp_client.py`)**:
  Runs on `h2` and `h3`. Sends periodic TCP requests to `h1:8080` at regular intervals (1–2 seconds) to simulate baseline traffic.

* **Attack Traffic Generator (`attack_tcp_client.py`)**:
  Runs on `h4`. Generates rapid TCP connection bursts toward `h1:8080` to trigger the anomaly detection threshold.

* **SDN Security Controller (`controller.py`)**:
  - Periodically queries switch flow statistics using `ovs-ofctl dump-flows s1`.
  - Calculates per-host delta packet rates (`packets/sec`).
  - When a host breaches the threshold (default: `>= 25.0 pkts/s`), installs a high-priority OpenFlow rule (`priority=50000,tcp,nw_src=<offender>,actions=drop`) directly onto switch `s1`.
  - Appends structured security event records to `audit_log.json`.

---

## Network Specification

| Host | Role | IP Address | MAC Address | Interface | Description |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`h1`** | Target Server | `10.0.0.1/24` | `00:00:00:00:00:01` | `h1-eth0` | Listens on port 8080, responds to traffic |
| **`h2`** | Normal Client 1 | `10.0.0.2/24` | `00:00:00:00:00:02` | `h2-eth0` | Sends polite requests every 1–2s |
| **`h3`** | Normal Client 2 | `10.0.0.3/24` | `00:00:00:00:00:03` | `h3-eth0` | Sends polite requests every 1–2s |
| **`h4`** | Attacking Host | `10.0.0.4/24` | `00:00:00:00:00:04` | `h4-eth0` | Sends rapid connection bursts (> 100 pkts/s) |
| **`s1`** | OpenFlow Switch | - | - | - | OpenFlow 1.3 switch controlled via `ovs-ofctl` |

---

## Running the System

### Step 1: Start the Mininet Topology
In **Terminal 1**:
```bash
sudo python3 topology.py
```
*(Starts the 4 hosts and switch `s1` with standard learning forwarding).*

### Step 2: Start the SDN Security Controller
In **Terminal 2**:
```bash
sudo python3 controller.py --threshold 25.0 --interval 1.0
```

### Step 3: Run the Socket Applications Inside Mininet CLI (`mininet>`)

Inside the Mininet terminal (Terminal 1):
```bash
# 1. Start target TCP server on h1 in background
mininet> h1 python3 tcp_server.py &

# 2. Start normal clients on h2 and h3 in background
mininet> h2 python3 normal_tcp_client.py -t 10.0.0.1 -p 8080 --name h2 &
mininet> h3 python3 normal_tcp_client.py -t 10.0.0.1 -p 8080 --name h3 &

# 3. Launch the attack flood from h4
mininet> h4 python3 attack_tcp_client.py -t 10.0.0.1 -p 8080 --threads 5
```

---

## Verification & Execution Flow

1. **Traffic Monitoring**: The controller observes legitimate traffic from `10.0.0.2` and `10.0.0.3` (~1.0 pkts/s). When `h4` begins flooding, the monitor detects a sudden spike (`10.0.0.4 -> 120.5 pkts/s`).
2. **Dynamic Flow Installation**: Because the observed rate breaches the threshold (`120.5 >= 25.0 pkts/s`), the controller executes `ovs-ofctl add-flow s1 "priority=50000,tcp,nw_src=10.0.0.4,actions=drop"` and writes the incident to `audit_log.json`.
3. **Hardware Switch Drop**: Switch `s1` matches `10.0.0.4`'s TCP packets against the priority 50000 rule and drops them at the switch level. The attacker (`h4`) shows `[BLOCKED / DROPPED] Passed Rate: 0.0/s`, while normal clients (`h2`, `h3`) continue communicating with `h1` without interruption.
