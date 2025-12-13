from mininet.net import Mininet
from mininet.node import OVSController
from mininet.cli import CLI
from mininet.log import setLogLevel
from myTopo import myTopo

def run():
    net = Mininet(topo=myTopo(), controller=OVSController)
    
    net.start()
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run()
