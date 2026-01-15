#pragma once

#include <string>
#include <cstdint>
#include <vector>

namespace cpppwn
{
    
    //Generates a cyclic pattern (De Bruijn sequence) to determine buffer overflow offsets. 
    std::string cyclic(size_t length, size_t period = 4);

   //Finds the offset of a value inside the generated cyclic pattern.
    int cyclicFind(std::string const& subPattern, size_t period = 4);
    int cyclicFind(uint32_t value, size_t period = 4);
}
