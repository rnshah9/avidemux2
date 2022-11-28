#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern bool ADM_splitString(const std::string &separator, const std::string &source, std::vector<std::string> &result);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string separator = provider.ConsumeRandomLengthString(500);
    std::string source = provider.ConsumeRandomLengthString(500);
    if (separator.length() == 0 || source.length() == 0) {
        return 0;
    }
    std::vector<std::string> vec;
    ADM_splitString(separator, source, vec);

    return 0;
}