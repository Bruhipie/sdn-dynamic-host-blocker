#!/usr/bin/env python3
"""
topology.py - Mininet Topology for SDN Dynamic Host Blocker Project
"""

import argparse
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, DefaultController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class SDNBlockerTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", cls=OVSSwitch)
        hosts_config = [
            ("h1", "10.0.0.1/24", "00:00:00:00:00:01"),
            ("h2", "10.0.0.2/24", "00:00:00:00:00:02"),
            ("h3", "10.0.0.3/24", "00:00:00:00:00:03"),
            ("h4", "10.0.0.4/24", "00:00:00:00:00:04"),
        ]
        for name, ip, mac in hosts_config:
            host = self.addHost(name, ip=ip, mac=mac)
            self.addLink(host, s1)


def run_topology():
    topo = SDNBlockerTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=DefaultController, link=TCLink, autoStaticArp=True)
    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
