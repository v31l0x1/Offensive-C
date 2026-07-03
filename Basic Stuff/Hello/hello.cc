#include <iostream>
#include <string>
#include <vector>

int main( int argc, char* argv[] ) {
    std::vector<std::string> args( argv, argv + argc );
    std::cout << "[+] Hello from C++\n";
    std::cout << "[+] Argc = " << args.size() << "\n";
    for ( size_t i = 0; i < args.size(); i++ ) {
        std::cout << "    Argv[" << i << "] = " << args[i] << "\n";
    }

    return 0;
}

