#include <iostream>
#include <vector>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>


struct ProcessSummary {
    DWORD pid;
    DWORD ppid;
    DWORD threads;
    std::string name;
};

class ProcessSnapshot {

public:
    ProcessSnapshot() {
        snap_ = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
    }

    ~ProcessSnapshot() {
        if ( snap_ && snap_ != INVALID_HANDLE_VALUE ) {
            CloseHandle( snap_ );
        }
    }

    ProcessSnapshot( const ProcessSnapshot& ) = delete;
    ProcessSnapshot& operator=( const ProcessSnapshot& ) = delete;

    bool valid() const {
        return snap_ != INVALID_HANDLE_VALUE && snap_ != nullptr;
    }

    std::vector<ProcessSummary> entries() const {
        std::vector<ProcessSummary> out;
        if ( !valid() ) return out;

        PROCESSENTRY32 pe = {};
        pe.dwSize = sizeof( PROCESSENTRY32 );

        if ( !Process32First( snap_, &pe ) ) return out;

        do {
            ProcessSummary s;
            s.pid = pe.th32ProcessID;
            s.ppid = pe.th32ParentProcessID;
            s.threads = pe.cntThreads;
            s.name = pe.szExeFile;
            out.push_back( s );
        } while ( Process32Next( snap_, &pe ) );
        return out;
    }

private:
    HANDLE snap_ = INVALID_HANDLE_VALUE;
};

int main( int argc, char* argv[] ) {
    std::string filter = ( argc >= 2 ) ? argv[1] : "";

    ProcessSnapshot snap;

    if ( !snap.valid() ) {
        std::cout << "[-] Failed to create process snapshot." << std::endl;
        return 1;
    }

    std::vector<ProcessSummary> list = snap.entries();
    for ( int i = 0; i < list.size(); ++i ) {
        const ProcessSummary& p = list[i];

        if ( !filter.empty() && _strcmpi( p.name.c_str(), filter.c_str() ) != 0 ) {
            continue;
        }

        printf( "PID = %d, PPID = %d, Threads = %d, %s\n", p.pid, p.ppid, p.threads, p.name.c_str() );
    }



    return 0;
}

