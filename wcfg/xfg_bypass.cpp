#include <windows.h>
#include <iostream>

typedef VOID (*FNPTR)(LONG);
VOID normal_fn(LONG arg) {
    std::cout << "Called normal_fn with " << arg << std::endl;
}
VOID __declspec(guard(suppress)) sensitive_fn(LONG arg) {
    std::cout << "Called sensitive_fn with " << arg << std::endl;
}

int main(INT argc, CHAR **argv) {
    FNPTR fptr = &normal_fn;

    // simulate vulnerability
    fptr = &sensitive_fn;
    // should not work, sensitive_fn is marked as suppressed
    fptr(5);
}
