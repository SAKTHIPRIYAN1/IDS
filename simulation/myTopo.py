from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink

class myTopo(Topo):
    def __init__(self):
        Topo.__init__(self)

        #sp,so
        SO = self.addHost('so', ip='10.0.3.2/24')
        SP = self.addHost('sp', ip='10.0.3.1/24') # Main IP on eth0

        # regs
        reg1 = self.addHost('reg1', ip='10.0.1.254/24')
        reg2 = self.addHost('reg2', ip='10.0.2.254/24')

        # reg Switches
        regS1 = self.addSwitch('regS1') 
        regS2 = self.addSwitch('regS2')
        self.addLink(reg1, regS1)
        self.addLink(reg2, regS2)

        # --- SMART METERS ---
        for i in range(1, 6):
            sm = self.addHost(f'sm{i}', ip=f'10.0.1.{i}/24', defaultRoute='via 10.0.1.254')
            self.addLink(sm, regS1)
        
        for i in range(6, 11):
            sm = self.addHost(f'sm{i}', ip=f'10.0.2.{i-5}/24', defaultRoute='via 10.0.2.254')
            self.addLink(sm, regS2)


        
        # 1.SP -> SO FIRSt
        # This ensures SP's default IP (10.0.3.1) goes to sp-eth0 (the core link)
        self.addLink(SP, SO)

        # 2. Connect REG1 -> SP 
        # SP side gets 10.0.99.2 on sp-eth1
        self.addLink(reg1, SP, params1={'ip': '10.0.99.1/24'}, params2={'ip': '10.0.99.2/24'}) 
        
        # 3. Connect REG2 -> SP 
        # SP side gets 10.0.98.2 on sp-eth2
        self.addLink(reg2, SP, params1={'ip': '10.0.98.1/24'}, params2={'ip': '10.0.98.2/24'})


topos = { 'myTopo': (lambda: myTopo()) }