## 在 linux 发行版上生成 linux_header 作为 linux 内核开发依赖的头文件

```
cd /usr/src/linux-headers-5.11.0-41-generic
sudo make headers_install ARCH=arm64

# 如果出现 sys/typps.h no such file 错误，则安装 libc6-dev
sudo apt install libc6-dev

# 如果libc6-dev 因为版本冲突而无法安装，则降级 libc6-dev,比如依赖 2.31-0ubuntu9 但系统已安装的版本是 2.31-0ubuntu9.2，则需要降级
sudo apt install $(dpkg -l | awk '/2.31-0ubuntu9.2/ { print $2"=2.31-0ubuntu9" }')

# 如果出现 clang 或 llvm 版本不对，则通过下载预编译二进制文件来安装 clang/llvm
```

### linux 重要头文件

```
定义 bpf_cmd bpf_map_type bpf_prog_type bpf_attach_type bpf_attr 以及 bpf 辅助函数注解
/usr/include/linux/bpf.h

定义 bpf_elf_map
/usr/include/iproute2/bpf_elf.h

有用的辅助函数
bpf_helpers.h 来源于 libbpf 项目 https://github.com/libbpf/libbpf/blob/master/src/bpf_helpers.h

定义 TC action 枚举
/usr/include/linux/pkt_cls.h

定义 IP 协议
/usr/include/linux/in.h

定义 Ethernet ethhdr
/usr/include/linux/if_ether.h

定义 IP iphdr
/usr/include/linux/ip.h

定义 TCP tcphdr
/usr/include/linux/tcp.h

定义 UDP udphdr
/usr/include/linux/udp.h
```
