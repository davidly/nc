// This is in a good state, though I figured out how to get PID info in dns.cs, so I'm not adding more features here for now

#define UNICODE

#include <stdio.h>
#include <process.h>
#include <direct.h>
#include <stdlib.h>
#include <ctype.h>
#include <ppl.h>
#include <vector>
#include <string>
#include <atomic>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <conio.h>
#include <list>
#include <mutex>
#include <chrono>
#include <unordered_map>

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <ip2string.h>
#include <windns.h>
#include <ws2tcpip.h>

using namespace concurrency;
using namespace std;

#pragma comment( lib, "iphlpapi.lib" )
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "dnsapi.lib" )
#pragma comment( lib, "advapi32.lib" )
#pragma comment( lib, "ntdll.lib" )

std::mutex mtxGlobal;

unordered_map<string,string> g_persistentEntries;
unordered_map<string,string> g_inmemoryEntries;
unordered_map<string,string> g_prefixEntries;
const WCHAR * pwcDNSEntriesFile = L"dns_entries.txt";

struct procinfo
{
    procinfo( DWORD p, WCHAR * n ) : pid( p ), name( n ) {}
    
    DWORD pid;
    wstring name;
};

struct dnsentry
{
    dnsentry( string & i, string & n ) : remoteip( i ), remotename( n ) {}
    string remoteip;
    string remotename;
};

bool SetPrivilege( HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege ) 
{
    LUID luid;

    if ( !LookupPrivilegeValue( NULL, lpszPrivilege, &luid ) )
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return false; 
    }

    TOKEN_PRIVILEGES tp = {0};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = bEnablePrivilege ? SE_PRIVILEGE_ENABLED : 0;

    // Enable the privilege or disable all privileges.

    if ( !AdjustTokenPrivileges( hToken, FALSE, &tp, sizeof( TOKEN_PRIVILEGES ), 0, 0 ) )
    { 
        printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return false; 
    } 

    if ( ERROR_NOT_ALL_ASSIGNED == GetLastError() )
    {
        printf("The token does not have the specified privilege. \n");
        return false;
    } 

    return true;
} //SetPrivilege

bool SetDebugPrivilege()
{
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;

    if ( OpenProcessToken( hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken ) )
    {
        bool worked = SetPrivilege( hToken, SE_DEBUG_NAME, TRUE );
        CloseHandle( hToken );
        return worked;
    }

    return false;
} //SetDebugPrivilege

void ReadPersistentEntries()
{
    ifstream input( pwcDNSEntriesFile );
    string line;

    while( getline( input, line ) )
    {
        if ( line.length() >= 17 )
        {
            size_t sp = line.find_first_of( ' ' );
            if ( ( string::npos != sp ) && ( ( sp + 1 ) < line.length() ) )
            {
                string ip( line, 0, sp );
                string host( line, sp + 1 );

                g_persistentEntries[ ip ] = host;
            }
        }
    }

    //printf( "persistent entry count: %zd\n", g_persistentEntries.size() );
} //ReadPersistentEntries

void Usage( WCHAR *pwcApp )
{
    wprintf( L"usage: %ws [-l]\n", pwcApp );
    wprintf( L"    Shows outbound Network Connections\n" );
    wprintf( L"    arguments:   [-l]    loop infinitely\n" );
    wprintf( L"                 [-l:X]  loop X times\n" );
    wprintf( L"    notes:       reads from and writes to %ws\n", pwcDNSEntriesFile );
    exit( 1 );
} //Usage

const char * TcpState( DWORD s )
{
    if ( MIB_TCP_STATE_CLOSED == s )
        return "closed";
    if ( MIB_TCP_STATE_LISTEN == s )
        return "listen";
    if ( MIB_TCP_STATE_SYN_SENT == s )
        return "syn_sent";
    if ( MIB_TCP_STATE_SYN_RCVD == s )
        return "syn_rcvd";
    if ( MIB_TCP_STATE_ESTAB == s )
        return "established";
    if ( MIB_TCP_STATE_FIN_WAIT1 == s )
        return "fin_wait1";
    if ( MIB_TCP_STATE_FIN_WAIT2 == s )
        return "fin_wait2";
    if ( MIB_TCP_STATE_CLOSE_WAIT == s )
        return "close_wait";
    if ( MIB_TCP_STATE_CLOSING == s )
        return "closing";
    if ( MIB_TCP_STATE_LAST_ACK == s )
        return "last_ack";
    if ( MIB_TCP_STATE_TIME_WAIT == s )
        return "time_wait";
    if ( MIB_TCP_STATE_DELETE_TCB == s )
        return "delete_tcb";

    return "invalid";
} //TcpState

void FindProcesses( vector<procinfo> & procs )
{
    vector<DWORD> processes( 8192 );
    DWORD cbNeeded = 0;
    if ( !EnumProcesses( processes.data(), (DWORD) processes.size() * sizeof DWORD, &cbNeeded ) )
    {
        printf( "can't enumerate processes; error %d\n", GetLastError() );
        exit( 1 );
    }

    DWORD cProcesses = cbNeeded / sizeof DWORD;
    vector<WCHAR> path( MAX_PATH );

    for ( DWORD process = 0; process < cProcesses; process++ )
    {
        HANDLE h = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, processes[ process ] );
        if ( 0 != h ) // many will fail with error_invalid_parameter or access_denied
        {
            DWORD size = (DWORD) path.size();
            if ( QueryFullProcessImageName( h, 0, path.data(), &size ) )
            {
                procinfo pi( processes[ process ], path.data() );
                procs.push_back( pi );
            }
        }
    }

    for ( int i = 0; i < procs.size(); i++ )
        printf( "process %d: %ws\n", procs[i].pid, procs[i].name.c_str() );
} //FindProcesses

bool FindProcessName( DWORD pid, WCHAR * name )
{
    if ( 0 == pid )
    {
        wcscpy( name, L"idle" );
        return true;
    }

    HANDLE h = OpenProcess( PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid );
    if ( 0 != h ) // many will fail with error_invalid_parameter or access_denied
    {
        WCHAR path[ MAX_PATH ];
        DWORD size = _countof( path );
        if ( QueryFullProcessImageName( h, 0, path, &size ) )
        {
            WCHAR * slash = wcsrchr( path, '\\' );
            if ( slash )
            {
                wcscpy( name, slash + 1 );
 
                WCHAR * period = wcsrchr( name, '.' );
                if ( period )
                    *period = 0;
 
                return true;
            }
        }
    }

    wcscpy( name, L"n/a" );
    return false;
} //FindProcessName

// This function works terribly -- it returns incorrect results. Don't call it.
bool IPToHostName( WCHAR * ip, vector<WCHAR> & name )
{
    name[ 0 ] = 0;
    WCHAR awc[ MAX_PATH + 20 ];
    wcscpy( awc, ip );
    wcscat( awc, L".IN-ADDR.ARPA" );
    PDNS_RECORD pDnsRecord = 0;    
    DNS_STATUS status = DnsQuery_W( awc, DNS_TYPE_PTR, DNS_QUERY_STANDARD, 0, &pDnsRecord, 0 );
    if ( 0 == status )
    {
        wcscpy( name.data(), pDnsRecord->Data.PTR.pNameHost );
        DnsRecordListFree( pDnsRecord, DnsFreeRecordListDeep );
        return true;
    }

    return false;
} //IPToHostName

bool IpToName( char * ip, USHORT port, char * name )
{
    name[ 0 ] = 0;

    struct sockaddr_in saGNI;
    saGNI.sin_family = AF_INET;
    IN_ADDR in_addr;
    InetPtonA( AF_INET, ip, &in_addr );
    saGNI.sin_addr.s_addr = in_addr.S_un.S_addr; // inet_addr(ip);
    saGNI.sin_port = port;

    char hostname[ NI_MAXHOST ];
    char servInfo[ NI_MAXSERV ];
    DWORD ret = getnameinfo( (struct sockaddr *) &saGNI, sizeof ( struct sockaddr ), hostname, NI_MAXHOST, servInfo, NI_MAXSERV, 0 );

    // when a hostname can't be found, the IP address is sometimes copied into the host variable

    if ( ( 0 == ret ) && ( strcmp( hostname, ip ) ) )
    {
        strcpy( name, hostname );
        return true;
    }

    return false;
} //IpToName

extern "C" int __cdecl wmain( int argc, WCHAR * argv[] )
{
    _set_se_translator([]( unsigned int u, EXCEPTION_POINTERS * pExp )
    {
        wprintf( L"translating exception %x\n", u );
        std::string error = "SE Exception: ";
        switch (u)
        {
            case 0xC0000005:
                error += "Access Violation";
                break;
            default:
                char result[11];
                sprintf_s(result, 11, "0x%08X", u);
                error += result;
        };

        wprintf( L"throwing std::exception\n" );
    
        throw std::exception( error.c_str() );
    });

    if ( argc < 1 || argc > 5 )
        Usage( argv[0] );

    bool loop = false;
    int loopPasses = -1;

    try
    {
        WSADATA wsaData = {0};
        int iResult = WSAStartup( MAKEWORD( 2, 2 ), &wsaData );
        if ( 0 != iResult )
        {
            printf( "can't wsastartup: %d\n", iResult );
            exit( 1 );
        }

        // Can't see the dashost process name without this. Ha!
        SetDebugPrivilege();

        int iArg = 1;
        while ( iArg < argc )
        {
            const WCHAR * pwcArg = argv[iArg];
            WCHAR a0 = pwcArg[0];
    
            if ( ( L'-' == a0 ) ||
                 ( L'/' == a0 ) )
            {
               WCHAR a1 = towlower( pwcArg[1] );

               if ( 'l' == a1 )
               {
                   loop = true;

                   if ( ':' == pwcArg[ 2 ] )
                       loopPasses = _wtoi( pwcArg + 3 );
               }
               else
                   Usage( argv[ 0 ] );
            }
    
            iArg++;
        }

        ReadPersistentEntries();

        // Cache all processes so lookups later are faster. (I abandoned this, because it's fast enough as-is).
        //vector<procinfo> procs;
        //FindProcesses( procs );

        printf( "  State        Local address         Foreign address       Host/Company                                            PID    Process\n" );
        std::mutex mtx;
        int passes = 0;
        do
        {
            DWORD cbNeeded = 32 * 1024; // tested with 0
            vector<byte> tcpTable;

            do
            {
                tcpTable.resize( cbNeeded );
                DWORD result = GetExtendedTcpTable( tcpTable.data(), &cbNeeded, FALSE, AF_INET, TCP_TABLE_OWNER_PID_CONNECTIONS, 0 );
                if ( 0 == result )
                    break;

                if ( ERROR_INSUFFICIENT_BUFFER == result )
                    continue;

                printf( "can't get size of list of tcp connections, error %d\n", result );
                exit( 1 );
            } while( true );
    
            MIB_TCPTABLE_OWNER_PID * ptable = (MIB_TCPTABLE_OWNER_PID *) tcpTable.data();
            int limit = ptable->dwNumEntries;
            vector<dnsentry> newentries;
    
            //for ( int i = 0; i < ptable->dwNumEntries; i++ )
            parallel_for( 0, limit, [&] ( int i )
            {
                char hostname[ NI_MAXHOST ];
                hostname[ 0 ] = 0;
                MIB_TCPROW_OWNER_PID & row = ptable->table[ i ];

                const int maxIP = 15 + 6 + 1;   // aaa.bbb.ccc.ddd:eeeee + null termination
                char localIP[ maxIP ];
                RtlIpv4AddressToStringA( (const in_addr *) &row.dwLocalAddr, localIP );
    
                char remoteIP[ maxIP ];
                RtlIpv4AddressToStringA( (const in_addr *) &row.dwRemoteAddr, remoteIP );

                string remoteip( remoteIP );
                bool inPersistent, inMemory;

                inPersistent = g_persistentEntries.count( remoteip );
                inMemory = g_inmemoryEntries.count( remoteip );

                if ( inPersistent )
                {
                    string host = g_persistentEntries[ remoteip ];
                    strcpy( hostname, host.c_str() );
                }
                else if ( inMemory )
                {
                    string host = g_inmemoryEntries[ remoteip ];
                    strcpy( hostname, host.c_str() );
                }

                if ( !inPersistent && !inMemory )
                {
                    IpToName( remoteIP, ntohs( (u_short) row.dwRemotePort ), hostname );

                    if ( 0 == hostname[ 0 ] )
                        strcpy( hostname, "(unknown)" );
                }

                if ( !inMemory || ( !inPersistent && strcmp( hostname, "(unknown)" ) ) )
                {
                    // Add to the vector of entries so it can be added to the map later

                    string remotehost( hostname );
                    dnsentry save( remoteip, remotehost );

                    lock_guard<mutex> lock( mtx );
                    newentries.push_back( save );
                }

                if ( !inMemory )
                {
                    snprintf( localIP + strlen( localIP ), _countof( localIP ) - strlen( localIP ), ":%d", ntohs( (u_short) row.dwLocalPort ) );
                    snprintf( remoteIP + strlen( remoteIP ), _countof( remoteIP ) - strlen( remoteIP ), ":%d", ntohs( (u_short) row.dwRemotePort ) );
    
                    WCHAR procname[ MAX_PATH ];
                    FindProcessName( row.dwOwningPid, procname );
    
                    lock_guard<mutex> lock( mtx );
                    printf( "  %-12s %-21s %-21s %-54s  %-6d %ws\n", TcpState( row.dwState ), localIP, remoteIP, hostname, row.dwOwningPid, procname );
                }
            }, static_partitioner() ); // huge performance win over default partitioner; avoid spinlocks

            // Write updates to the global maps and file after the iteration above to avoid lock contention in map lookups.
            // newentries may contain duplicates and entries may already be in the maps.

            for ( int i = 0; i < newentries.size(); i++ )
            {
                dnsentry & e = newentries[ i ];
                if ( !g_persistentEntries.count( e.remoteip ) && strcmp( "(unknown)", e.remotename.c_str() ) )
                {
                    g_persistentEntries[ e.remoteip ] = e.remotename;

                    FILE * fp = _wfopen( pwcDNSEntriesFile, L"a" );
                    if ( fp )
                    {
                        fprintf( fp, "%s %s\n", e.remoteip.c_str(), e.remotename.c_str() );
                        fclose( fp );
                    }
                }

                if ( !g_inmemoryEntries.count( e.remoteip ) )
                    g_inmemoryEntries[ e.remoteip ] = e.remotename;
            }

            if ( -1 != loopPasses )
            {
                passes++;
                if ( passes >= loopPasses )
                    break;
            }

            if ( loop )
                Sleep( 100 );
        } while ( loop );
    }
    catch( ... )
    {
        wprintf( L"caught an exception in nc.exe, exiting\n" );
    }

    return 0;
} //main


