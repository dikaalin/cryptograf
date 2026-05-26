## Cryptograf — build rules
##
## Preferred (cross-platform): use CMake
##   cmake -B build -DCMAKE_BUILD_TYPE=Release
##   cmake --build build
##
## Quick Linux build (no CMake required):
##   make          — CLI binary
##   make gui      — Qt6 GUI binary
##   make test     — quick encrypt/decrypt self-test

CXX      := g++
CXXFLAGS := -std=c++20 -O2 -Wall -Wextra -Wpedantic
LDFLAGS  := -lssl -lcrypto

MOC      := /usr/lib/qt6/libexec/moc
QT_FLAGS := $(shell pkg-config --cflags Qt6Widgets) -I/tmp/qt6svg-dev/usr/include/x86_64-linux-gnu/qt6 -I/tmp/qt6svg-dev/usr/include/x86_64-linux-gnu/qt6/QtSvg
QT_LIBS  := $(shell pkg-config --libs Qt6Widgets) /tmp/qt6svg-dev/usr/lib/x86_64-linux-gnu/libQt6Svg.so.6

SRCS     := src/main.cpp src/aes_cipher.cpp src/gcmsiv.cpp
BIN      := cryptograf

GUI_SRCS := src/gui_main.cpp src/aes_cipher.cpp src/gcmsiv.cpp src/digital_sign.cpp
GUI_BIN  := cryptograf-gui

.PHONY: all gui clean test cmake-build cmake-clean

all: $(BIN)

gui: $(GUI_BIN)

$(BIN): $(SRCS) src/aes_cipher.hpp src/gcmsiv.hpp
	$(CXX) $(CXXFLAGS) $(SRCS) -o $@ $(LDFLAGS)

# moc generates gui_main.moc which gui_main.cpp includes at the bottom
# via  #include "gui_main.moc"
src/gui_main.moc: src/gui_main.cpp
	$(MOC) $< -o $@

$(GUI_BIN): src/gui_main.moc $(GUI_SRCS) src/aes_cipher.hpp src/gcmsiv.hpp
	$(CXX) $(CXXFLAGS) $(QT_FLAGS) $(GUI_SRCS) -o $@ $(LDFLAGS) $(QT_LIBS)

clean:
	rm -f $(BIN) $(GUI_BIN) src/gui_main.moc *.enc *.dec test_*

# CMake convenience targets (cross-platform)
BUILD_DIR ?= build

cmake-build:
	cmake -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --parallel

cmake-clean:
	rm -rf $(BUILD_DIR)

# Quick self-test — encrypts/decrypts a temp file in all 5 modes
test: $(BIN)
	@echo "=== Running self-test ==="
	@echo "Hello, AES-256 World! This is a test file." > /tmp/_aes_test_plain.txt
	@for mode in ECB CBC CFB OFB CTR; do \
		echo "--- $$mode ---"; \
		printf "testpassword123\ntestpassword123\n" | ./$(BIN) encrypt $$mode /tmp/_aes_test_plain.txt \
			/tmp/_aes_test_$${mode}.enc 2>&1 || true; \
		printf "testpassword123\n" | ./$(BIN) decrypt \
			/tmp/_aes_test_$${mode}.enc /tmp/_aes_test_$${mode}.dec 2>&1 || true; \
		diff /tmp/_aes_test_plain.txt /tmp/_aes_test_$${mode}.dec \
			&& echo "  PASS" || echo "  FAIL"; \
		rm -f /tmp/_aes_test_$${mode}.enc /tmp/_aes_test_$${mode}.dec; \
	done
	@rm -f /tmp/_aes_test_plain.txt
	@echo "=== Done ==="
