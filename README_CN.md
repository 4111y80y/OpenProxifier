# OpenProxifier

[English](README.md) | [中文](README_CN.md)

一个 Windows 透明 SOCKS5 代理注入器，可以将目标应用程序的所有 TCP 连接通过 SOCKS5 代理路由，无需修改目标程序或系统代理设置。

## 功能特性

- **透明代理注入**：注入任意 Windows 可执行文件，将其所有 TCP 连接通过 SOCKS5 代理路由
- **进程监控**：自动检测目标进程启动并进行注入
- **子进程传递**：自动将代理设置传递给子进程
- **SOCKS5 认证**：完整支持用户名/密码认证（RFC 1929）
- **连接测试**：启动前测试代理服务器连接和认证
- **服务器历史**：保存和管理多个代理服务器配置
- **双语界面**：完整的中英文界面支持
- **32位和64位支持**：支持 x86 和 x64 应用程序

## 工作原理

```
OpenProxifier (Qt GUI)
        |
        | 监控 & 注入
        v
目标应用程序.exe
        |
        | Hook Winsock API
        v
MiniProxifierHook.dll
        |
        | 重定向连接
        v
SOCKS5 代理服务器
```

应用程序使用 DLL 注入和 API 钩子（通过 Microsoft Detours）拦截 Winsock API 调用（`connect`、`WSAConnect`、`CreateProcessW`），并透明地将 TCP 连接重定向到配置的 SOCKS5 代理。

## 系统要求

- Windows 10/11
- Visual Studio 2019 或更高版本
- Qt 6.x
- CMake 3.20+
- vcpkg（用于 Microsoft Detours）

## 构建方法

1. **通过 vcpkg 安装依赖**：
   ```batch
   vcpkg install detours:x64-windows detours:x86-windows
   ```

2. **构建 64 位版本**：
   ```batch
   cmake -B build_x64 -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build_x64 --config Release
   ```

3. **构建 32 位版本**：
   ```batch
   cmake -B build_x86 -A Win32 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build_x86 --config Release
   ```

## 使用方法

### 图形界面模式

1. 启动 `MiniProxifier_x64.exe` 或 `MiniProxifier_x86.exe`
2. 配置 SOCKS5 代理设置（服务器、端口、可选认证）
3. 点击"测试连接"验证代理连通性
4. 添加目标进程名称到监控列表
5. 点击"开始监控"开始自动注入

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
│   └── ProxifierInjector.cpp  # 命令行注入器
├── hookdll/            # 注入的 DLL
│   ├── HookManager.*   # Hook 安装/移除
│   ├── WinsockHooks.*  # Winsock API 钩子
│   └── Socks5Client.*  # SOCKS5 协议实现
├── common/             # 共享头文件
│   ├── ProxyConfig.h   # 代理配置结构体
│   └── SharedMemory.h  # 通过共享内存进行 IPC
└── docs/               # 文档
```

## 技术细节

### 钩子 API

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
- IPv4 地址类型

## 已知限制

- 仅代理 TCP 连接（不支持 UDP）
- 目前仅支持 IPv4 地址
- 某些带有反调试功能的应用程序可能无法工作
- 某些目标应用程序需要管理员权限

## 许可证

本项目是开源的。详见 LICENSE 文件。

## 贡献

欢迎贡献！请随时提交问题和拉取请求。

## 致谢

- [Microsoft Detours](https://github.com/microsoft/Detours) - API 钩子库
- [Qt Framework](https://www.qt.io/) - GUI 框架
