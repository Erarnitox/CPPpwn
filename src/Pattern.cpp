#include <vector>
#include <algorithm>
#include "Pattern.hpp"

namespace cpppwn
{
    // Internal helper for De Bruijn sequence generation
    static void generateDb(int t, int p, std::vector<int> const& alphabet, std::vector<int>& a, std::vector<int>& sequence)
    {
        if (t > p)
        {
            if (p % t == 0)
            {
                for (int j = 1; j <= p; ++j)
                {
                    sequence.push_back(a[j]);
                }
            }
        }
        else
        {
            a[t] = a[t - p];
            generateDb(t + 1, p, alphabet, a, sequence);
            for (int j = a[t - p] + 1; j < (int)alphabet.size(); ++j)
            {
                a[t] = j;
                generateDb(t + 1, t, alphabet, a, sequence);
            }
        }
    }

    std::string cyclic(size_t length, size_t period)
    {
        std::vector<int> alphabet;
        for (int i = 0; i < 26; ++i)
        {
            alphabet.push_back('a' + i);
        }

        std::vector<int> a(period * alphabet.size(), 0);
        std::vector<int> sequence;

        generateDb(1, 1, alphabet, a, sequence);

        std::string result;
        result.reserve(length);

        while (result.size() < length)
        {
            for (int val : sequence)
            {
                result += (char)val;
                if (result.size() >= length)
                {
                    break;
                }
            }
        }

        return result;
    }

    int cyclicFind(std::string const& subPattern, size_t period)
    {
        
        std::string haystack = cyclic(20000, period);

        size_t pos = haystack.find(subPattern);
        if (pos != std::string::npos)
        {
            return static_cast<int>(pos);
        }
        return -1;
    }

    int cyclicFind(uint32_t value, size_t period)
    {
        std::string s;
        // Handle value as little-endian string
        s.push_back(static_cast<char>(value & 0xFF));
        s.push_back(static_cast<char>((value >> 8) & 0xFF));
        s.push_back(static_cast<char>((value >> 16) & 0xFF));
        s.push_back(static_cast<char>((value >> 24) & 0xFF));

        return cyclicFind(s, period);
    }
}
