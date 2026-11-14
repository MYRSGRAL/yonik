#pragma once
#include <cstdint>

namespace yonik_bench {
int run_application();
std::uint64_t rendered_frames();
void request_probe(std::uint64_t nonce);
void request_frame(std::int32_t token);
void exit_application();
void resume_for_show();
}
