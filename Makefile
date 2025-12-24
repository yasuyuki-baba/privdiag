# Simple Makefile for MinGW (g++)

CXX := g++
CXXFLAGS := -std=c++17 -Wall -Wextra -O2 -DUNICODE -D_UNICODE -Iinclude
LDFLAGS_DLL := -shared -Wl,--out-implib,libPrivDialogDll.a
LDFLAGS_EXE := -municode

SRC_DLL := src/privdiag_dll.cpp
SRC_EXE := src/privdiag_exe.cpp

HDRS := include/privdiag/security_summary.h

all: PrivDialogExe.exe PrivDialogDll.dll

PrivDialogDll.dll: $(SRC_DLL) $(HDRS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS_DLL) -o $@ $(SRC_DLL) -luser32 -ladvapi32

PrivDialogExe.exe: $(SRC_EXE) $(HDRS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS_EXE) -o $@ $(SRC_EXE) -luser32 -ladvapi32

clean:
	rm -f PrivDialogExe.exe PrivDialogDll.dll libPrivDialogDll.a

.PHONY: all clean
