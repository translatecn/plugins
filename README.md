[![test](https://github.com/containernetworking/plugins/actions/workflows/test.yaml/badge.svg)](https://github.com/containernetworking/plugins/actions/workflows/test.yaml?query=branch%3Amaster)

# Plugins
Some CNI network plugins, maintained by the containernetworking team. For more information, see the [CNI website](https://www.cni.dev).

Read [CONTRIBUTING](CONTRIBUTING.md) for build and test instructions.

## Plugins supplied:
### Main: interface-creating
- loopback: 将环回接口的状态设置为启动。
- ptp: 创建一个veth对。
- bridge: 创建一个网桥，将主机和容器添加到其中。
- ipvlan: 在容器中添加一个 ipvlan 接口。
- macvlan: 创建一个新的MAC地址，将所有流量转发到该容器。
- vlan: 分配一个vlan设备。
- host-device: 将已存在的设备移动到容器中。
- dummy: 在容器中创建一个新的虚拟设备。

### IPAM: IP address allocation
- host-local: 维护一个本地已分配IP的数据库
- dhcp: 在主机上运行守护进程，代表容器发出DHCP请求
- static: 为容器分配单个静态IPv4/IPv6地址。它在调试目的中很有用。

### Meta: other plugins
- tuning: 调整现有接口的sysctl参数
- portmap: 一个基于iptables的端口映射插件。将主机地址空间的端口映射到容器。
- bandwidth: 通过使用流量控制tbf（入口/出口）允许带宽限制。
- sbr: 一个为接口配置源基于路由的插件（从其链接）。
- firewall: 一个使用iptables或firewalld添加规则以允许来自/到容器的流量的防火墙插件。

### Sample
The sample plugin provides an example for building your own plugin.

## Contact

For any questions about CNI, please reach out via:
- Email: [cni-dev](https://groups.google.com/forum/#!forum/cni-dev)
- Slack: #cni on the [CNCF slack](https://slack.cncf.io/).

If you have a _security_ issue to report, please do so privately to the email addresses listed in the [OWNERS](OWNERS.md) file.

- https://www.jianshu.com/p/a1607e9eea32
- ip netns ls
- /var/run/netns/
- ip netns monitor


host-local 分配IP
loopback 无依赖
ptp 依赖 host-local 

portmap 依赖 ptp
- iptables -t filter -P FORWARD ACCEPT
- 





# iptables 重置 
```
cd /var/run/netns/
sudo iptables -F
sudo iptables -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT
 
ls | xargs -I F umount F 
ls | xargs -I F rm -rf F 
```

# ptp
```
iptables -t nat -S
iptables -t nat -N CNI-1b29d9511ed2bb3134d925d5

iptables -t nat -C CNI-1b29d9511ed2bb3134d925d5 -d 10.1.2.2/24 -j ACCEPT -m comment --comment 'name: "mynet" id:"dummy"'
iptables -t nat -A CNI-1b29d9511ed2bb3134d925d5 -d 10.1.2.2/24 -j ACCEPT -m comment --comment 'name: "mynet" id:"dummy"'

iptables -t nat -C CNI-1b29d9511ed2bb3134d925d5 ! -d 224.0.0.0/4 -j MASQUERADE -m comment --comment 'name: "mynet" id:"dummy"'
iptables -t nat -A CNI-1b29d9511ed2bb3134d925d5 ! -d 224.0.0.0/4 -j MASQUERADE -m comment --comment 'name: "mynet" id:"dummy"'


# 在数据包离开本地主机后，对数据包进行操作，如nat，mangle等。
# 针对源地址为 10.1.2.2 的数据包进行MASQUERADE操作，将源地址替换为本地主机的公网IP地址，从而实现内网主机访问互联网。
iptables -t nat -C POSTROUTING -s 10.1.2.2 -j CNI-1b29d9511ed2bb3134d925d5 -m comment --comment 'name: "mynet" id:"dummy"'
iptables -t nat -A POSTROUTING -s 10.1.2.2 -j CNI-1b29d9511ed2bb3134d925d5 -m comment --comment 'name: "mynet" id:"dummy"'
```







