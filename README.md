# OpenProxifier

[English](README.md) | [中文](README_CN.md)

A Windows transparent SOCKS5 proxy injector that routes all TCP connections of target applications through a SOCKS5 proxy without modifying the target program or system proxy settings.

## Features

- **Transparent Proxy Injection**: Inject into any Windows executable and route all its TCP connections through SOCKS5 proxy
- **Process Monitoring**: Automatically detect and inject into target processes when they start
- **Child Process Propagation**: Automatically propagate proxy settings to child processes
- **SOCKS5 Authentication**: Full support for username/password authentication (RFC 1929)
- **Connection Testing**: Test proxy server connectivity and authentication before starting
- **Server History**: Save and manage multiple proxy server configurations
- **Bilingual Interface**: Full English and Chinese UI support
- **32-bit and 64-bit Support**: Works with both x86 and x64 applications

## How It Works

```
OpenProxifier (Qt GUI)
        |
        | Monitor & Inject
        v
TargetApp.exe
        |
        | Hook Winsock APIs
        v
MiniProxifierHook.dll
        |
        | Redirect connections
        v
SOCKS5 Proxy Server
```

The application uses DLL injection and API hooking (via Microsoft Detours) to intercept Winsock API calls (`connect`, `WSAConnect`, `CreateProcessW`) and transparently redirect TCP connections through the configured SOCKS5 proxy.

## Requirements

- Windows 10/11
- Visual Studio 2019 or later
- Qt 6.x
- CMake 3.20+
- vcpkg (for Microsoft Detours)

## Building

1. **Install dependencies via vcpkg**:
   ```batch
   vcpkg install detours:x64-windows detours:x86-windows
   ```

2. **Build for 64-bit**:
   ```batch
   cmake -B build_x64 -A x64 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build_x64 --config Release
   ```

3. **Build for 32-bit**:
   ```batch
   cmake -B build_x86 -A Win32 -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake
   cmake --build build_x86 --config Release
   ```

## Usage

### GUI Mode

1. Launch `MiniProxifier_x64.exe` or `MiniProxifier_x86.exe`
2. Configure SOCKS5 proxy settings (server, port, optional authentication)
3. Click "Test Connection" to verify proxy connectivity
4. Add target process names to the monitoring list
5. Click "Start Monitoring" to begin auto-injection

### Command Line Mode

```batch
# Set proxy via environment variable
set PROXIFIER_PROXY=127.0.0.1:1080

# Inject into a specific program
ProxifierInjector_x64.exe notepad.exe

# With authentication
set PROXIFIER_PROXY=127.0.0.1:1080
set PROXIFIER_USER=username
set PROXIFIER_PASS=password
ProxifierInjector_x64.exe curl.exe http://httpbin.org/ip
```

## Project Structure

```
OpenProxifier/
├── launcher/           # Qt GUI application
│   ├── MainWindow.*    # Main window UI and logic
│   ├── ProcessMonitor.*# Process detection and injection
│   ├── Injector.*      # DLL injection implementation
│   └── ProxifierInjector.cpp  # CLI injector
├── hookdll/            # Injected DLL
│   ├── HookManager.*   # Hook installation/removal
│   ├── WinsockHooks.*  # Winsock API hooks
│   └── Socks5Client.*  # SOCKS5 protocol implementation
├── common/             # Shared headers
│   ├── ProxyConfig.h   # Proxy configuration structure
│   └── SharedMemory.h  # IPC via shared memory
└── docs/               # Documentation
```

## Technical Details

### Hooked APIs

| DLL | Function | Purpose |
|-----|----------|---------|
| ws2_32.dll | connect | Redirect TCP connections |
| ws2_32.dll | WSAConnect | Redirect TCP connections (extended) |
| kernel32.dll | CreateProcessW | Inject into child processes |
| kernel32.dll | CreateProcessA | Inject into child processes |

### SOCKS5 Protocol Support

- SOCKS5 version 5 (RFC 1928)
- No authentication (0x00)
- Username/password authentication (0x02, RFC 1929)
- CONNECT command for TCP connections
- IPv4 address type

## Known Limitations

- Only TCP connections are proxied (UDP not supported)
- Only IPv4 addresses are currently supported
- Some applications with anti-debugging features may not work
- Requires administrator privileges for some target applications

## License

Apache-2.0 (commercial friendly)

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Acknowledgments

- [Microsoft Detours](https://github.com/microsoft/Detours) - API hooking library
- [Qt Framework](https://www.qt.io/) - GUI framework
