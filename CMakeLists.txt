cmake_minimum_required(VERSION 3.21)
project(Cryptograf VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── Dependencies ───────────────────────────────────────────────────────────────
find_package(Qt6 6.2 REQUIRED COMPONENTS Widgets)
find_package(OpenSSL 1.1 REQUIRED)

# ── Qt automation (handles moc, rcc, uic) ────────────────────────────────────
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

# ── Compiler options ───────────────────────────────────────────────────────────
if(MSVC)
    # /utf-8: treat source and execution charsets as UTF-8 (needed for Cyrillic literals)
    add_compile_options(/W4 /utf-8)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── Shared crypto sources ──────────────────────────────────────────────────────
set(CRYPTO_SRCS
    src/aes_cipher.cpp
    src/gcmsiv.cpp
)

# ── CLI tool ───────────────────────────────────────────────────────────────────
add_executable(cryptograf
    src/main.cpp
    ${CRYPTO_SRCS}
)
target_include_directories(cryptograf PRIVATE src)
target_link_libraries(cryptograf PRIVATE OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    # OpenSSL on Windows needs winsock and crypto32
    target_link_libraries(cryptograf PRIVATE ws2_32 crypt32)
endif()

# ── GUI tool ───────────────────────────────────────────────────────────────────
set(GUI_SRCS
    src/gui_main.cpp
    ${CRYPTO_SRCS}
    resources/icons.qrc
)
if(WIN32)
    list(APPEND GUI_SRCS resources/app.rc)
endif()

qt_add_executable(cryptograf-gui ${GUI_SRCS})
target_include_directories(cryptograf-gui PRIVATE src)
target_link_libraries(cryptograf-gui PRIVATE Qt6::Widgets OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    # Hide the console window and link runtime deps
    set_target_properties(cryptograf-gui PROPERTIES WIN32_EXECUTABLE TRUE)
    target_link_libraries(cryptograf-gui PRIVATE ws2_32 crypt32)

    # After build, collect Qt and OpenSSL DLLs next to the executable
    find_program(WINDEPLOYQT windeployqt6
                 HINTS "${Qt6_DIR}/../../../bin"
                       "$ENV{QTDIR}/bin")
    if(WINDEPLOYQT)
        add_custom_command(TARGET cryptograf-gui POST_BUILD
            COMMAND "${WINDEPLOYQT}"
                    --no-translations
                    --no-system-d3d-compiler
                    --no-opengl-sw
                    "$<TARGET_FILE:cryptograf-gui>"
            COMMENT "Running windeployqt6 to collect Qt DLLs…"
        )
    endif()
endif()

# ── Install ────────────────────────────────────────────────────────────────────
include(GNUInstallDirs)
install(TARGETS cryptograf cryptograf-gui
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
