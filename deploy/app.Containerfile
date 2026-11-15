# VPN Access Control C++ 组件镜像（离线友好）。
#
# 不在镜像里编译、也不联网装包：直接使用宿主上已经编译好的二进制、
# 宿主上的 nft，以及它们依赖的非基础库。
# 先运行 deploy/stage-app.sh 生成 deploy/build-context/。
#
# 基础镜像固定 Rocky Linux 10，与构建宿主（EL10）同一代 glibc/OpenSSL。

FROM quay.io/rockylinux/rockylinux:10

COPY deploy/build-context/bin/  /usr/local/sbin/
COPY deploy/build-context/sbin/ /usr/sbin/
COPY deploy/build-context/lib/  /usr/local/lib/vpn/

RUN printf '/usr/local/lib/vpn\n' > /etc/ld.so.conf.d/vpn.conf && ldconfig

CMD ["/usr/local/sbin/vpn-admin", "--config", "/etc/vpn-policy/admin.conf"]