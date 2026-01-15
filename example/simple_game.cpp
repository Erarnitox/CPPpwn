#include <print>
#include <iostream>

int points{ 1970 };   

int main() {
    std::println("You need more than 10.000 Points to win!");
    
    while(true) {
        std::println("[{:x}] = {} Points", (size_t)&points, points);
        std::print("Press [ENTER] to check again.");
        (void) std::cin.get();
        points += 1;

        if(points > 10000) {
            std::println("You WON!");
            break;
        }
    }
}