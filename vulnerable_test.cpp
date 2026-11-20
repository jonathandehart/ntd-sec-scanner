#include <cstring>
#include <cstdlib>
#include <cstdint>

// TRUE POSITIVE (CWE-120): Unbounded copy from external input)
void process_packet(const char* network_input) {
    char buffer;
    strcpy(buffer, network_input);
}

// FALSE POSITIVE (CWE-120): Safe constant copy that fits in bufferE
void init_tag() {
    char tag;
    strcpy(tag, "NTD");
}

//TRUE POSITIVE (CWE-190): Potential integer overflow in heap allocation
struct PacketHeader {
    uint32_t id;
    uint64_t payload[8];
};

PacketHeader* allocate_headers(uint32_t count)

int main() {
    process_packet("Payload exceeding 32 bytes...");
    init_tag();
    PacketHeader* h = allocate_headers(100);
    free(h);
    return 0;
}
