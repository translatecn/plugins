package main

import (
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/coreos/go-iptables/iptables"
	"github.com/vishvananda/netlink"
)

func main() {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: "ptp0", // ptp0
			MTU:  5000,   // 5000
		},
		PeerName: "hostVeth", //
		//PeerNamespace: netlink.NsFd(int(hostNS.Fd())),
	}

	_ = netlink.LinkAdd
	_ = netlink.AddrAdd
	_ = netlink.RouteAddEcmp // ping 回写
	_ = ip.AddHostRoute
	_ = ip.SetupIPMasq
	netlink.LinkDel(veth)

	ipt, _ := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	ipt.ListChains("nat")
	ipt.NewChain("nat", "CNI-1b29d9511ed2bb3134d925d5")
}
