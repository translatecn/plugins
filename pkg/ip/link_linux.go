// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/containernetworking/plugins/pkg/utils/sysctl"
)

var ErrLinkNotFound = errors.New("link not found")

func peerExists(name string) bool {
	if _, err := netlink.LinkByName(name); err != nil {
		return false
	}
	return true
}

func RenameLink(curName, newName string) error {
	link, err := netlink.LinkByName(curName)
	if err == nil {
		err = netlink.LinkSetName(link, newName)
	}
	return err
}

// DelLinkByName removes an interface link.
func DelLinkByName(ifName string) error {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return ErrLinkNotFound
		}
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	return nil
}

// DelLinkByNameAddr remove an interface and returns its addresses
func DelLinkByNameAddr(ifName string) ([]*net.IPNet, error) {
	iface, err := netlink.LinkByName(ifName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil, ErrLinkNotFound
		}
		return nil, fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	addrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
	if err != nil {
		return nil, fmt.Errorf("failed to get IP addresses for %q: %v", ifName, err)
	}

	if err = netlink.LinkDel(iface); err != nil {
		return nil, fmt.Errorf("failed to delete %q: %v", ifName, err)
	}

	out := []*net.IPNet{}
	for _, addr := range addrs {
		if addr.IP.IsGlobalUnicast() {
			out = append(out, addr.IPNet)
		}
	}

	return out, nil
}

// GetVethPeerIfindex returns the veth link object, the peer ifindex of the
// veth, or an error. This peer ifindex will only be valid in the peer's
// network namespace.
func GetVethPeerIfindex(ifName string) (netlink.Link, int, error) {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return nil, -1, fmt.Errorf("could not look up %q: %v", ifName, err)
	}
	if _, ok := link.(*netlink.Veth); !ok {
		return nil, -1, fmt.Errorf("interface %q was not a veth interface", ifName)
	}

	// veth supports IFLA_LINK (what vishvananda/netlink calls ParentIndex)
	// on 4.1 and higher kernels
	peerIndex := link.Attrs().ParentIndex
	if peerIndex <= 0 {
		// Fall back to ethtool for 4.0 and earlier kernels
		e, err := ethtool.NewEthtool()
		if err != nil {
			return nil, -1, fmt.Errorf("failed to initialize ethtool: %v", err)
		}
		defer e.Close()

		stats, err := e.Stats(link.Attrs().Name)
		if err != nil {
			return nil, -1, fmt.Errorf("failed to request ethtool stats: %v", err)
		}
		n, ok := stats["peer_ifindex"]
		if !ok {
			return nil, -1, fmt.Errorf("failed to find 'peer_ifindex' in ethtool stats")
		}
		if n > 32767 || n == 0 {
			return nil, -1, fmt.Errorf("invalid 'peer_ifindex' %d", n)
		}
		peerIndex = int(n)
	}

	return link, peerIndex, nil
}

// SetupVeth sets up a pair of virtual ethernet devices.
// Call SetupVeth from inside the container netns.  It will create both veth
// devices and move the host-side veth into the provided hostNS namespace.
// On success, SetupVeth returns (hostVeth, containerVeth, nil)
func SetupVeth(contVethName string, mtu int, contVethMac string, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	return SetupVethWithName(contVethName, "", mtu, contVethMac, hostNS)
}

// RandomVethName returns string "veth" with random prefix (hashed from entropy)
func RandomVethName() (string, error) {
	entropy := make([]byte, 4)
	_, err := rand.Read(entropy)
	if err != nil {
		return "", fmt.Errorf("failed to generate random veth name: %v", err)
	}

	// NetworkManager (recent versions) will ignore veth devices that start with "veth"
	return fmt.Sprintf("veth%x", entropy), nil
}

func makeVeth(ifName, vethPeerName string, mtu int, mac string, hostNS ns.NetNS) (string, netlink.Link, error) {
	var peerName string // 主机 veth pair的名称
	var veth netlink.Link
	var err error
	for i := 0; i < 10; i++ {
		if vethPeerName != "" {
			peerName = vethPeerName
		} else {
			peerName, err = RandomVethName()
			if err != nil {
				return peerName, nil, err
			}
		}

		veth, err = makeVethPair(ifName, peerName, mtu, mac, hostNS)
		switch {
		case err == nil:
			return peerName, veth, nil

		case os.IsExist(err):
			if peerExists(peerName) && vethPeerName == "" {
				continue
			}
			return peerName, veth, fmt.Errorf("container veth ifName (%q) peer provided (%q) already exists", ifName, peerName)
		default:
			return peerName, veth, fmt.Errorf("failed to make veth pair: %v", err)
		}
	}

	// should really never be hit
	return peerName, nil, fmt.Errorf("failed to find a unique veth ifName")
}

// makeVethPair is called from within the container's network namespace
func makeVethPair(ifName, hostVethPairName string, mtu int, mac string, hostNS ns.NetNS) (netlink.Link, error) {
	veth := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{
			Name: ifName, // ptp0
			MTU:  mtu,    // 5000
		},
		PeerName:      hostVethPairName, //
		PeerNamespace: netlink.NsFd(int(hostNS.Fd())),
	}
	if mac != "" {
		m, err := net.ParseMAC(mac)
		if err != nil {
			return nil, err
		}
		veth.LinkAttrs.HardwareAddr = m
	}
	if err := netlink.LinkAdd(veth); err != nil {
		return nil, err
	}
	// Re-fetch the container link to get its creation-time parameters, e.g. index and mac
	veth2, err := netlink.LinkByName(ifName)
	if err != nil {
		netlink.LinkDel(veth) // try and clean up the link if possible.
		return nil, err
	}

	return veth2, nil
}

// SetupVethWithName sets up a pair of virtual ethernet devices.
// Call SetupVethWithName from inside the container netns.  It will create both veth
// devices and move the host-side veth into the provided hostNS namespace.
// hostVethName: If hostVethName is not specified, the host-side veth name will use a random string.
// On success, SetupVethWithName returns (hostVeth, containerVeth, nil)
func SetupVethWithName(contVethName, hostVethName string, mtu int, contVethMac string, hostNS ns.NetNS) (net.Interface, net.Interface, error) {
	// 在新的ns 执行
	hostVethName, contVeth, err := makeVeth(contVethName, hostVethName, mtu, contVethMac, hostNS) // ptp0  "" 5000 ""  /proc/896741/task/896741/ns/net
	if err != nil {
		return net.Interface{}, net.Interface{}, err
	}

	var hostVeth netlink.Link
	// 在 主机 ns执行
	err = hostNS.Do(func(_ ns.NetNS) error {
		hostVeth, err = netlink.LinkByName(hostVethName)
		if err != nil {
			return fmt.Errorf("failed to lookup %q in %q: %v", hostVethName, hostNS.Path(), err)
		}

		if err = netlink.LinkSetUp(hostVeth); err != nil {
			return fmt.Errorf("failed to set %q up: %v", hostVethName, err)
		}

		//RA（Router Advertisement）报文是IPv6网络中路由器发送给主机的广播消息，用以告知主机关于网络的各项配置信息，如IPv6前缀、默认网关、MTU、以及是否支持SLAAC等。
		//
		//RA报文作为IPv6网络中的一个重要组成部分，其设计初衷是为了简化网络管理，并使网络设备能够快速适应不断变化的网络环境。在IPv6协议中
		//，节点通过解析RA报文来自动配置网络参数，这一机制不仅提高了网络配置的效率，还增强了网络的灵活性和可扩展性。
		//0表示不接受RA；
		//1表示如果forwarding是关闭的就接受RA，如果forwarding是打开的则不接受RA（代表主机可能作为一个路由器）；
		//2表示不论forwarding是打开还是关闭，都接受RA。
		_, _ = sysctl.Sysctl(fmt.Sprintf("net/ipv6/conf/%s/accept_ra", hostVethName), "0")
		return nil
	})
	if err != nil {
		return net.Interface{}, net.Interface{}, err
	}
	return ifaceFromNetlinkLink(hostVeth), ifaceFromNetlinkLink(contVeth), nil
}

func ifaceFromNetlinkLink(l netlink.Link) net.Interface {
	a := l.Attrs()
	return net.Interface{
		Index:        a.Index,
		MTU:          a.MTU,
		Name:         a.Name,
		HardwareAddr: a.HardwareAddr,
		Flags:        a.Flags,
	}
}
