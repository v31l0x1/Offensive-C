#include <iostream>
#include <string>
#include <format>

class Target {
public:
    Target( const std::string& host, int port );
    std::string display() const;

private:
    std::string host_;
    int         port_;
};

Target::Target( const std::string& host, int port ) : host_( host ), port_( port ) {

}

std::string Target::display() const {
    return host_ + ":" + std::to_string( port_ );
}


int main( void ) {

    Target t( "10.0.0.1", 445 );
    std::cout << t.display() << "\n";
}

