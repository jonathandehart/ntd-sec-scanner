#include <cstring>
#include <cstdio>

void process_packet(const char* network_input) {
    char buffer[32];
    strcpy(buffer, network_input); // Should trigger warning
}

int main() {
    process_packet("This string is way too long for a 32-byte buffer!");
    return 0;
}
