# Cryptograf — Build Instructions

## Requirements

| Component | Version | Where to get |
|-----------|---------|--------------|
| C++ compiler | C++20 | GCC ≥ 12 / Clang ≥ 15 / MSVC 2022 |
| CMake | ≥ 3.21 | https://cmake.org/download/ |
| Qt6 Widgets | ≥ 6.2 | See platform section below |
| OpenSSL | ≥ 1.1 | See platform section below |

---

## Linux (Ubuntu, AstraLinux, Debian)

### Install dependencies

```bash
# Ubuntu 22.04+ / AstraLinux 1.7+
sudo apt install build-essential cmake \
                 qt6-base-dev libssl-dev
```

### Build

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel

# Binaries:
#   build/cryptograf       — CLI tool
#   build/cryptograf-gui   — GUI application
```

### Quick Linux build (no CMake)

```bash
make        # CLI only
make gui    # Qt6 GUI
make test   # encrypt/decrypt self-test
```

---

## Windows 10 / 11

### 1 — Install Qt6

Download the Qt Online Installer from https://www.qt.io/download-open-source

During installation select:
- **Qt → Qt 6.x.x → MSVC 2022 64-bit** (for Visual Studio)  
  *or* **Qt 6.x.x → MinGW 13.1 64-bit** (for MinGW/GCC)
- Component **Qt → Qt 6.x.x → Additional Libraries** is not required

### 2 — Install OpenSSL

**Option A — vcpkg** (recommended, integrates with CMake automatically):
```powershell
git clone https://github.com/microsoft/vcpkg C:\vcpkg
C:\vcpkg\bootstrap-vcpkg.bat
C:\vcpkg\vcpkg install openssl:x64-windows
```

**Option B — prebuilt installer**  
Download from https://slproweb.com/products/Win32OpenSSL.html  
Install the "Win64 OpenSSL" full package to `C:\OpenSSL-Win64`.

### 3 — Build with Visual Studio 2022

Open **x64 Native Tools Command Prompt for VS 2022**, then:

```bat
:: With vcpkg
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake ^
      -DCMAKE_PREFIX_PATH=C:\Qt\6.x.x\msvc2022_64
cmake --build build --config Release

:: Without vcpkg (prebuilt OpenSSL)
cmake -B build -G "Visual Studio 17 2022" -A x64 ^
      -DCMAKE_PREFIX_PATH="C:\Qt\6.x.x\msvc2022_64;C:\OpenSSL-Win64"
cmake --build build --config Release
```

### 3 (alt) — Build with MinGW

```powershell
cmake -B build -G "MinGW Makefiles" ^
      -DCMAKE_BUILD_TYPE=Release ^
      -DCMAKE_PREFIX_PATH=C:\Qt\6.x.x\mingw_64
cmake --build build --parallel
```

### 4 — Run

After the build, `windeployqt6` is called automatically to copy Qt DLLs
next to `cryptograf-gui.exe`. OpenSSL DLLs (`libssl-3-x64.dll`,
`libcrypto-3-x64.dll`) must also be in the same directory or on `PATH`.

```
build\Release\cryptograf-gui.exe
```

---

---

## Windows installer

### Способ A — GitHub Actions (рекомендуется)

1. Залейте репозиторий на GitHub.
2. Перейдите в **Actions → Windows — Build & Installer → Run workflow**.
3. После завершения скачайте `Cryptograf-Setup.exe` из раздела **Artifacts**.

При пуше тега `v*` (например `git tag v1.0 && git push --tags`) установщик
автоматически прикрепляется к GitHub Release.

### Способ Б — Локальная сборка на Windows

Требования: Visual Studio 2022, Qt 6, OpenSSL, [NSIS](https://nsis.sourceforge.io/).

Откройте **Developer Command Prompt for VS 2022** в папке проекта:

```powershell
# автоопределение Qt и OpenSSL:
.\installer\stage.ps1

# явные пути:
.\installer\stage.ps1 -QtDir "C:\Qt\6.7.3\msvc2022_64" `
                      -OpenSSL "C:\Program Files\OpenSSL-Win64"
```

Скрипт выполняет cmake → build → windeployqt6 → staging → makensis
и создаёт `Cryptograf-Setup.exe` в корне проекта.

---

## Source layout

```
src/
  main.cpp          CLI entry point
  gui_main.cpp      Qt6 GUI
  aes_cipher.cpp    AES-256 all modes (ECB/CBC/CFB/OFB/CTR/GCM/CCM/GCM-SIV/SIV)
  aes_cipher.hpp
  gcmsiv.cpp        GCM-SIV (RFC 8452) — manual implementation over OpenSSL AES-ECB
  gcmsiv.hpp
CMakeLists.txt      Cross-platform build (Windows + Linux)
Makefile            Linux quick-build wrapper
```
