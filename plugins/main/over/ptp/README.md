```

RA（Router Advertisement）报文是IPv6网络中路由器发送给主机的广播消息，用以告知主机关于网络的各项配置信息，如IPv6前缀、默认网关、MTU、以及是否支持SLAAC等。

RA报文作为IPv6网络中的一个重要组成部分，其设计初衷是为了简化网络管理，并使网络设备能够快速适应不断变化的网络环境。在IPv6协议中
，节点通过解析RA报文来自动配置网络参数，这一机制不仅提高了网络配置的效率，还增强了网络的灵活性和可扩展性。
0表示不接受RA；
1表示如果forwarding是关闭的就接受RA，如果forwarding是打开的则不接受RA（代表主机可能作为一个路由器）；
2表示不论forwarding是打开还是关闭，都接受RA。
echo '0' > /proc/sys/net/ipv6/conf/veth467bf51d/accept_ra

```