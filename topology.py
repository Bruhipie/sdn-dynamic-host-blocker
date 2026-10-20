#!/usr/bin/env python3
"""
topology.py - Mininet Topology for SDN Dynamic Host Blocker Project
"""

import argparse
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, DefaultController
from mininet.cli import CLI
from mininet.log import setLogLevel, info


class SDNBlockerTopo(Topo):
    def build(self):
        s1 = self.addSwitch("s1", cls=OVSSwitch)
        for i in range(1, 5):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s1)


def run_topology():
    topo = SDNBlockerTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=DefaultController)
    net.start()
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    run_topology()
