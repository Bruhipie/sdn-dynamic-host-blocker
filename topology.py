#!/usr/bin/env python3
"""
topology.py - Mininet Topology for SDN Dynamic Host Blocker Project

Sets up a single OpenFlow switch (s1) connected to:
  - h1: 10.0.0.1, MAC 00:00:00:00:00:01 (Target Server)
  - h2: 10.0.0.2, MAC 00:00:00:00:00:02 (Legitimate Client 1)
  - h3: 10.0.0.3, MAC 00:00:00:00:00:03 (Legitimate Client 2)
  - h4: 10.0.0.4, MAC 00:00:00:00:00:04 (Attacking Host)

And links the switch to a local SDN controller (RemoteController on 127.0.0.1:6653 or 6633).
Can be run directly via `sudo python3 topology.py` or used with `mn --custom topology.py --topo sdn_topo`.
"""

import argparse
import sys

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch, DefaultController
    from mininet.link import TCLink
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
except ImportError:
    Topo = object  # Fallback for static analysis when mininet is only in venv / root


class SDNBlockerTopo(Topo):
    """
    1 OpenFlow Switch connected to 4 hosts with fixed IP and MAC addresses.
    """
    def build(self):
        # Add OpenFlow switch s1 (supports both OF10 and OF13 with standalone failMode)
        s1 = self.addSwitch("s1", cls=OVSSwitch, protocols="OpenFlow10,OpenFlow13", failMode="standalone")

        # Define 4 hosts with deterministic IPs and MACs
        hosts_config = [
            ("h1", "10.0.0.1/24", "00:00:00:00:00:01"),
            ("h2", "10.0.0.2/24", "00:00:00:00:00:02"),
            ("h3", "10.0.0.3/24", "00:00:00:00:00:03"),
            ("h4", "10.0.0.4/24", "00:00:00:00:00:04"),
        ]

        for name, ip, mac in hosts_config:
            host = self.addHost(name, ip=ip, mac=mac)
            self.addLink(host, s1)


# Allow mininet custom topo loader: `mn --custom topology.py --topo sdn_topo`
topos = {"sdn_topo": (lambda: SDNBlockerTopo())}


def run_topology(
    controller_ip: str = "127.0.0.1",
    controller_port: int = 6653,
    use_test_controller: bool = False,
    openflow_version: str = "OpenFlow13",
):
    """Initializes and runs the Mininet network."""
    topo = SDNBlockerTopo()

    info("*** Creating network\n")
    if use_test_controller:
        info("*** Starting Mininet Network with switch s1\n")
        net = Mininet(
            topo=topo,
            switch=lambda name: OVSSwitch(name, protocols="OpenFlow10,OpenFlow13", failMode="standalone"),
            controller=DefaultController,
            link=TCLink,
            autoSetMacs=False,
            autoStaticArp=True,
        )
    else:
        info(f"*** Connecting to Remote SDN Controller at {controller_ip}:{controller_port}\n")
        net = Mininet(
            topo=topo,
            switch=lambda name: OVSSwitch(name, protocols=openflow_version),
            controller=lambda name: RemoteController(
                name, ip=controller_ip, port=controller_port
            ),
            link=TCLink,
            autoSetMacs=False,
            autoStaticArp=True,
        )

    info("*** Starting network\n")
    net.start()

    # Install OpenFlow baseline and per-host monitoring rules on s1
    s1 = net.get("s1")
    s1.cmd("ovs-ofctl add-flow s1 priority=1,actions=normal")
    for host_ip in ["10.0.0.2", "10.0.0.3", "10.0.0.4"]:
        s1.cmd(f"ovs-ofctl add-flow s1 priority=10,ip,nw_src={host_ip},actions=normal")

    info("\n*** Network Configuration Summary:\n")
    info("  - Target Server (h1): 10.0.0.1  (00:00:00:00:00:01)\n")
    info("  - Normal Client (h2): 10.0.0.2  (00:00:00:00:00:02)\n")
    info("  - Normal Client (h3): 10.0.0.3  (00:00:00:00:00:03)\n")
    info("  - Attacker Host (h4): 10.0.0.4  (00:00:00:00:00:04)\n")
    info("  - OpenFlow Switch:    s1        (Protocols: OpenFlow10, OpenFlow13)\n")

    if use_test_controller:
        info("\n*** Running quick ping connectivity test between all hosts:\n")
        net.pingAll()

    info("\n*** Entering Mininet CLI. Type 'exit' or Ctrl+D to quit.\n")
    info("*** Quick tips for testing in Mininet CLI:\n")
    info("    h1 python3 tcp_server.py &\n")
    info("    h2 python3 normal_tcp_client.py --name h2 &\n")
    info("    h3 python3 normal_tcp_client.py --name h3 &\n")
    info("    h4 python3 attack_tcp_client.py --threads 5\n\n")

    CLI(net)

    info("*** Stopping network\n")
    net.stop()


def main():
    parser = argparse.ArgumentParser(description="SDN Dynamic Host Blocker - Mininet Topology")
    parser.add_argument(
        "--controller-ip",
        type=str,
        default="127.0.0.1",
        help="Remote SDN controller IP address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--controller-port",
        type=int,
        default=6653,
        help="Remote SDN controller OpenFlow port (default: 6653, common: 6633)",
    )
    parser.add_argument(
        "--openflow",
        type=str,
        default="OpenFlow13",
        choices=["OpenFlow10", "OpenFlow13"],
        help="OpenFlow protocol version (default: OpenFlow13)",
    )
    parser.add_argument(
        "--remote",
        action="store_true",
        help="Connect to a remote SDN controller instead of Mininet's built-in learning controller",
    )

    args = parser.parse_args()
    setLogLevel("info")
    run_topology(
        controller_ip=args.controller_ip,
        controller_port=args.controller_port,
        use_test_controller=not args.remote,
        openflow_version=args.openflow,
    )


if __name__ == "__main__":
    main()
