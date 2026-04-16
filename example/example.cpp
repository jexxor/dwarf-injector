#include <cstdint>
#include <iostream>
#include <unistd.h>

[[gnu::noinline, gnu::used]] void PrintVictory() {
    std::cout << "\n[+] EXAMPLE STATUS: VERIFIED.\n";
}

constexpr std::size_t kInputSize = 128;

[[gnu::noinline]] void SecretUnwindTrigger(const char* input) {
    register const char* r12_ptr asm("r12") = input;
    asm volatile("" : : "r"(r12_ptr) : "memory");
    throw 42;
}

int main() {
    char input[kInputSize] = {0};
    std::cout << "Enter candidate input (max " << kInputSize << " bytes): " << std::flush;
    (void)read(0, input, kInputSize);

    try {
        SecretUnwindTrigger(input);
    } catch (int) {
        uintptr_t rbx_val = 0;
        asm volatile("mov %%rbx, %0" : "=r"(rbx_val));
        if (rbx_val != 0) {
            PrintVictory();
            return 0;
        }
    }

    std::cout << "Invalid key." << std::endl;
    return 1;
}
