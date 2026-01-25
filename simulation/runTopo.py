from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel
from myTopo import myTopo

def run():
    net = Mininet(topo=myTopo(), controller=None)
    
    net.start()

    # Start REG servers
    reg1 = net.get('reg1')
    reg2 = net.get('reg2')
    reg1.cmd('python3 reg_server.py reg1 &')
    reg2.cmd('python3 reg_server.py reg2 &')

    # Start SP server
    sp = net.get('sp')
    sp.cmd('python3 server.py &')

    # Start SO server (if needed, assuming web.py or so_forwarder.py)
    so = net.get('so')
    so.cmd('python3 so_forwarder.py &')  # Assuming this exists

    print("All servers started. Use CLI to interact.")
    CLI(net)
    net.stop()

if __name__ == "__main__":
    setLogLevel('info')
    run()
