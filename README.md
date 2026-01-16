# OpenProxifier

[English](README_EN.md) | [中文](README.md)

一个 Windows 透明 SOCKS5 代理工具，可以将目标应用程序的网络连接通过 SOCKS5 代理路由，无需修改目标程序或系统代理设置。

## 功能特性

- **双代理模式**：
  - **WinDivert 模式**：内核级数据包拦截，实现真正的透明代理（推荐）
  - **DLL 注入模式**：通过 DLL 注入 Hook Winsock API，兼容旧版应用
- **规则路由**：为不同应用配置不同规则（代理 / 直连 / 阻止）
- **进程监控**：自动检测目标进程启动并进行代理
- **SOCKS5 认证**：完整支持用户名/密码认证（RFC 1929）
- **连接测试**：启动前测试代理服务器连接和认证
- **服务器历史**：保存和管理多个代理服务器配置
- **系统托盘**：最小化到系统托盘，快速访问菜单
- **内置测试工具**：ProxyTestApp 用于验证代理功能
- **双语界面**：完整的中英文界面支持

## 工作原理

### WinDivert 模式（推荐）

```
OpenProxifier (Qt GUI)
        |
        | WinDivert 内核驱动
        v
网络数据包 <---> PacketProcessor
        |
        | NAT 重定向到 LocalProxy
        v
LocalProxy (TCP:34010)
        |
        | SOCKS5 隧道
        v
SOCKS5 代理服务器
        |
        v
      互联网
```

WinDivert 模式使用 WinDivert 驱动在内核层拦截网络数据包。来自被监控应用程序的数据包被重定向到本地代理，然后通过 SOCKS5 代理隧道传输。这提供了真正的透明代理，无需修改目标应用程序。

### DLL 注入模式

```
OpenProxifier (Qt GUI)
        |
        | 监控 & 注入
        v
目标应用程序.exe
        |
        | Hook Winsock API
        v
OpenProxifierHook.dll
        |
        | 重定向连接
        v
SOCKS5 代理服务器
```

DLL 注入模式使用 Microsoft Detours 钩住 Winsock API 调用（`connect`、`WSAConnect`），将 TCP 连接重定向到 SOCKS5 代理。

## 系统要求

- Windows 10/11（64位）
- 管理员权限（WinDivert 模式必需）
- Qt 6.x（用于编译）
- CMake 3.20+
- vcpkg（用于 Microsoft Detours）

## 构建方法

1. **通过 vcpkg 安装依赖**：
   ```batch
   vcpkg install detours:x64-windows
   ```

2. **配置并构建**：
   ```batch
   cmake -B build -A x64 -DCMAKE_PREFIX_PATH=C:/Qt/6.x/msvc2022_64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build --config Release
   ```

3. **输出文件**位于 `build/bin/Release/`：
   - `OpenProxifier_x64.exe` - 主程序
   - `OpenProxifierHook_x64.dll` - 注入模式使用的 Hook DLL
   - `ProxyTestApp.exe` - 代理测试工具
   - `WinDivert64.sys` / `WinDivert.dll` - WinDivert 驱动和库

## 使用方法

### 图形界面模式

1. **以管理员身份**启动 `OpenProxifier_x64.exe`
2. 配置 SOCKS5 代理设置（服务器、端口、可选认证）
3. 点击"测试连接"验证代理连通性
4. 添加目标进程名称到规则列表，选择操作：
   - **代理**：通过 SOCKS5 代理路由
   - **直连**：直接连接（绕过代理）
   - **阻止**：阻止所有连接
5. 点击"开始监控"开始透明代理
6. 使用"启动测试程序"验证代理是否正常工作

### 命令行模式

```batch
# 通过环境变量设置代理
set PROXIFIER_PROXY=127.0.0.1:1080

# 注入到指定程序
ProxifierInjector_x64.exe notepad.exe

# 带认证
set PROXIFIER_PROXY=127.0.0.1:1080
set PROXIFIER_USER=用户名
set PROXIFIER_PASS=密码
ProxifierInjector_x64.exe curl.exe http://httpbin.org/ip
```

## 项目结构

```
OpenProxifier/
├── launcher/           # Qt GUI 应用程序
│   ├── MainWindow.*    # 主窗口界面和逻辑
│   ├── ProcessMonitor.*# 进程检测和注入
│   ├── Injector.*      # DLL 注入实现
│   └── ProxyEngineWrapper.*  # C++/C 桥接层
├── core/               # WinDivert 透明代理引擎（C语言）
│   ├── ProxyEngine.*   # 主引擎接口
│   ├── PacketProcessor.* # 数据包拦截和 NAT
│   ├── LocalProxy.*    # 本地 SOCKS5 隧道代理
│   ├── RuleEngine.*    # 应用程序路由规则
│   ├── ConnectionTracker.* # NAT 连接跟踪
│   ├── Socks5.*        # SOCKS5 协议实现
│   └── UdpRelay.*      # UDP 中继支持
├── hookdll/            # 注入模式使用的 DLL
│   ├── HookManager.*   # Hook 安装/移除
│   ├── WinsockHooks.*  # Winsock API 钩子
│   └── Socks5Client.*  # SOCKS5 协议实现
├── proxytestapp/       # 代理测试应用程序
├── common/             # 共享头文件
│   ├── ProxyConfig.h   # 代理配置结构体
│   └── SharedMemory.h  # 通过共享内存进行 IPC
└── cli/                # 命令行工具
```

## 技术细节

### WinDivert 模式

- 使用 WinDivert 2.2 进行内核级数据包捕获
- 实现双向 NAT 进行透明重定向
- LocalProxy 监听 TCP 端口 34010
- 通过 PID 跟踪支持按进程规则匹配

### Hook API（注入模式）

| DLL | 函数 | 用途 |
|-----|------|------|
| ws2_32.dll | connect | 重定向 TCP 连接 |
| ws2_32.dll | WSAConnect | 重定向 TCP 连接（扩展版） |
| kernel32.dll | CreateProcessW | 注入子进程 |
| kernel32.dll | CreateProcessA | 注入子进程 |

### SOCKS5 协议支持

- SOCKS5 版本 5（RFC 1928）
- 无认证（0x00）
- 用户名/密码认证（0x02，RFC 1929）
- TCP 连接的 CONNECT 命令
- 支持 IPv4 和 IPv6 地址

## 已知限制

- WinDivert 模式需要管理员权限
- 某些带有反调试功能的应用程序可能无法使用注入模式
- UDP 代理为实验性功能

## 许可证

Apache-2.0（商业友好）

## 贡献

欢迎贡献！请随时提交问题和拉取请求。

## 致谢

- [WinDivert](https://github.com/basil00/WinDivert) - Windows 数据包捕获/修改库
- [Microsoft Detours](https://github.com/microsoft/Detours) - API 钩子库
- [Qt Framework](https://www.qt.io/) - GUI 框架
