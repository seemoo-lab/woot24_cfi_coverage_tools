CXX = clang++-16
CFLAGS = -Weverything -Wno-declaration-after-statement -pedantic -std=c99 -O3 -fvisibility=hidden -fuse-ld=lld -flto -fno-sanitize-recover -fsanitize-trap
CFLAGS_ARM = -march=armv8-a -target aarch64-linux-gnueabi
CXXFLAGS = -Weverything -pedantic -Wno-c++98-compat -Wno-weak-vtables -std=c++20 -fvisibility=hidden -flto -fuse-ld=lld -fsanitize-trap

TARGETS = timing_attack

all: $(TARGETS)

timing_attack: timing_attack.cpp
	@echo Compiling $< to $@ $(CXXFLAGS)
	@$(CXX) $(CXXFLAGS) -O0 -fsanitize=cfi -fsanitize-cfi-cross-dso -o $@ $<

clean:
	rm -f $(TARGETS)
	rm -f *.o

.PHONY: clean all
