[![test](https://github.com/containernetworking/plugins/actions/workflows/test.yaml/badge.svg)](https://github.com/containernetworking/plugins/actions/workflows/test.yaml?query=branch%3Amaster)

# Plugins
Some CNI network plugins, maintained by the containernetworking team. For more information, see the [CNI website](https://www.cni.dev).

Read [CONTRIBUTING](CONTRIBUTING.md) for build and test instructions.

## Plugins supplied:
### Main: interface-creating
- bridge: 创建一个网桥，将主机和容器添加到其中。
- ipvlan: 在容器中添加一个 ipvlan 接口。
- loopback: 将环回接口的状态设置为启动。
- macvlan: 创建一个新的MAC地址，将所有流量转发到该容器。
- ptp: 创建一个veth对。
- vlan: 分配一个vlan设备。
- host-device: 将已存在的设备移动到容器中。
- dummy: 在容器中创建一个新的虚拟设备。

#### Windows: Windows specific
- win-bridge: 创建一个网桥，将主机和容器添加到其中。
- win-overlay: 为容器创建一个覆盖接口。

### IPAM: IP address allocation
- dhcp: 在主机上运行守护进程，代表容器发出DHCP请求
- host-local: 维护一个本地已分配IP的数据库
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
