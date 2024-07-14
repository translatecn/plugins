// Copyright 2016 CNI authors
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

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/containernetworking/plugins/pkg/testutils"
	"net"

	"github.com/vishvananda/netlink"

	"github.com/containernetworking/plugins/3rd/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/plugins/3rd/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/plugins/3rd/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/plugins/3rd/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ns"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

func cmdAdd(args *skel.CmdArgs) error {
	conf, err := parseNetConf(args.StdinData)
	if err != nil {
		return err
	}

	var v4Addr, v6Addr *net.IPNet

	args.IfName = "lo" // ignore config, this only works for loopback
	err = ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		// [root@vm ~]# ip netns add ns1
		// root@vm ~]# ip netns exec ns1 ip addr
		// : lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN group default qlen 1000
		//    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err // not tested
		}
		// [root@vm ~]# ip netns exec ns1 ip link set lo up
		// [root@vm ~]# ip netns exec ns1 ip addr
		// 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
		//     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
		//     inet 127.0.0.1/8 scope host lo
		//        valid_lft forever preferred_lft forever
		//     inet6 ::1/128 scope host
		//        valid_lft forever preferred_lft forever
		err = netlink.LinkSetUp(link) //
		if err != nil {
			return err // not tested
		}

		v4Addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return err // not tested
		}
		if len(v4Addrs) != 0 {
			v4Addr = v4Addrs[0].IPNet
			// sanity check that this is a loopback address
			for _, addr := range v4Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		v6Addrs, err := netlink.AddrList(link, netlink.FAMILY_V6)
		if err != nil {
			return err // not tested
		}
		if len(v6Addrs) != 0 {
			v6Addr = v6Addrs[0].IPNet
			// sanity check that this is a loopback address
			for _, addr := range v6Addrs {
				if !addr.IP.IsLoopback() {
					return fmt.Errorf("loopback interface found with non-loopback address %q", addr.IP)
				}
			}
		}

		return nil
	})
	if err != nil {
		return err // not tested
	}

	var result types.Result
	if conf.PrevResult != nil {
		// If loopback has previous result which passes from previous CNI plugin,
		// loopback should pass it transparently
		result = conf.PrevResult
	} else {
		r := &current.Result{
			CNIVersion: conf.CNIVersion,
			Interfaces: []*current.Interface{
				{
					Name:    args.IfName,
					Mac:     "00:00:00:00:00:00",
					Sandbox: args.Netns,
				},
			},
		}

		if v4Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v4Addr,
			})
		}

		if v6Addr != nil {
			r.IPs = append(r.IPs, &current.IPConfig{
				Interface: current.Int(0),
				Address:   *v6Addr,
			})
		}

		result = r
	}

	return types.PrintResult(result, conf.CNIVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	if args.Netns == "" {
		return nil
	}
	args.IfName = "lo" // ignore config, this only works for loopback
	err := ns.WithNetNSPath(args.Netns, func(ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err // not tested
		}

		err = netlink.LinkSetDown(link)
		if err != nil {
			return err // not tested
		}

		return nil
	})
	if err != nil {
		//  if NetNs is passed down by the Cloud Orchestration Engine, or if it called multiple times
		// so don't return an error if the device is already removed.
		// https://github.com/kubernetes/kubernetes/issues/43014#issuecomment-287164444
		_, ok := err.(ns.NSPathNotExistErr)
		if ok {
			return nil
		}
		return err
	}

	return nil
}

// #1、在宿主机上创建 veth 对
//ip link add name veth1 type veth peer name veth2
//
//#2、创建 两个 net ns
//ip netns add ns1  &&  ip netns add ns2
//
//#3、在宿主机上把 veth设备 设置到  ns上
//ip link set veth1 netns ns1
//ip link set veth2 netns ns2
//ls /var/run/netns
//
//#4、利用exec命令 设置IP
//ip netns exec ns1 ip addr add local 10.12.0.2/24 dev veth1
//ip netns exec ns2 ip addr add local 10.12.0.3/24 dev veth2
//ip netns exec ns1 ip a
//ip netns exec ns1 ip a
//
//#5、启动各自的设备
//ip netns exec ns1 ip link set veth1 up
//ip netns exec ns2 ip link set veth2 up

func init2() {
	networkNS, _ := testutils.NewNS()
	cmdAdd(&skel.CmdArgs{
		ContainerID: "dummy",
		Netns:       networkNS.Path(),
		IfName:      "lo",
		Args:        "none",
		Path:        "/test/cni/bin",
		StdinData:   []byte(`{"cniVersion":"0.3.1","name":"cni-loopback","type":"loopback"}`),
	})
	networkNS.Close()
	testutils.UnmountNS(networkNS)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("loopback"))
}

func cmdCheck(args *skel.CmdArgs) error {
	args.IfName = "lo" // ignore config, this only works for loopback

	return ns.WithNetNSPath(args.Netns, func(_ ns.NetNS) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return err
		}

		if link.Attrs().Flags&net.FlagUp != net.FlagUp {
			return errors.New("loopback interface is down")
		}

		return nil
	})
}

func parseNetConf(bytes []byte) (*types.NetConf, error) {
	conf := &types.NetConf{}
	if err := json.Unmarshal(bytes, conf); err != nil {
		return nil, fmt.Errorf("failed to parse network config: %v", err)
	}

	if conf.RawPrevResult != nil {
		if err := version.ParsePrevResult(conf); err != nil { // RawPrevResult -> PrevResult
			return nil, fmt.Errorf("failed to parse prevResult: %v", err)
		}
		if _, err := current.NewResultFromResult(conf.PrevResult); err != nil { // 不会修改 conf.PrevResult 的值
			return nil, fmt.Errorf("failed to convert result to current version: %v", err)
		}
	}

	return conf, nil
}
