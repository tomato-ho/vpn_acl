# 参与贡献

## 许可证

本项目采用 **AGPL-3.0-only**（见 `LICENSE`）。第三方组件及其许可证见 `NOTICE`。

## 当前政策：欢迎 issue，暂不接受外部 PR

出于维护成本与法律清晰度的考虑，目前**不接受外部代码贡献（Pull Request）**，但非常欢迎：

- 报告 bug（附版本、复现步骤、日志）；
- 提出功能需求与使用场景；
- 反馈部署问题（尤其是不同发行版、SELinux、防火墙场景）；
- 指出文档错误。

如果你希望提交代码，请先开 issue 讨论。维护者确认后再约定贡献方式。

## DCO（Developer Certificate of Origin）兜底

如果未来某个改动被同意以补丁形式接收，提交必须包含签署：

```
Signed-off-by: Your Name <you@example.com>
```

即 `git commit -s`。这表示你确认：

1. 该改动由你创作，或你有权按本项目许可证提交；
2. 你同意该改动按 **AGPL-3.0-only** 授权。

## 关于 CLA

为保证未来可能的双许可（AGPL 开源版 + 商业授权版），若项目开始接收常规的外部代码贡献，会要求贡献者签署贡献者许可协议（CLA）。

**在签署 CLA 之前的贡献，仍会被视为仅按 AGPL-3.0-only 授权。**

## 本地开发

```bash
# 编译并跑测试
cmake -S . -B build -DVPN_WITH_DB=ON -DVPN_WITH_ADMIN=ON
cmake --build build -j
ctest --test-dir build --output-on-failure

# 前端
cd vpn-admin/web && npm ci && npm run build

# 部署（会改动宿主网络，建议在测试机执行）
./deploy/install.sh --check
```

测试是自包含的：不需要数据库、网络、nftables 或 fixtures。

## 不要提交的内容

- `.env`、任何真实密码/密钥/证书；
- `mariadb/data/`、`build/`、`deploy/build-context/`、`deploy/images/`；
- `vpn-admin/web/dist/`（构建产物）。

这些已经在 `.gitignore` 中。

## 安全问题

请不要在公开 issue 中披露安全漏洞。请私下联系维护者，说明影响范围与复现方式。