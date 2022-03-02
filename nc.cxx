// simple app to iterate through active connections

#ifndef UNICODE
#define UNICODE
#endif

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
#include <unordered_set>
#include <omp.h>

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <ip2string.h>
#include <windns.h>
#include <ws2tcpip.h>
#include <wininet.h>

using namespace concurrency;
using namespace std;

#pragma comment( lib, "iphlpapi.lib" )
#pragma comment( lib, "ws2_32.lib" )
#pragma comment( lib, "dnsapi.lib" )
#pragma comment( lib, "advapi32.lib" )
#pragma comment( lib, "ntdll.lib" )
#pragma comment( lib, "wininet.lib" )

unordered_map<string,string> g_persistentEntries;
unordered_set<string> g_unknownEntries;
unordered_map<string,string> g_prefixEntries;
const WCHAR * pwcDNSEntriesFile = L"dns_entries.txt";
const int maxIP = 15 + 6 + 1;   // aaa.bbb.ccc.ddd:eeeee + null termination

enum ConName { unresolvedCN = 0, persistentCN, unknownCN, revipCN, lookipCN, prefixCN };

struct tcpconnection
{
    tcpconnection()
    {
        newConnection = false;
        conName = ConName::unresolvedCN;
    }

    MIB_TCPROW_OWNER_PID tcp;
    bool newConnection;
    ConName conName;
    string remoteName;
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

class ihandle
{
    private:
        HINTERNET handle;

    public:
        ihandle( HINTERNET h ) : handle( h ) {}
        HINTERNET get() { return handle; }
        ~ihandle() { if ( 0 != handle ) InternetCloseHandle( handle ); }
};

static string likelyOwnerFromLookIP( const char * ip )
{
    string request = "https://www.lookip.net/ip/";
    request.append( ip );

    ihandle xinternet( InternetOpenA( "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0 ) );
    if ( 0 == xinternet.get() )
        return "";

    ihandle xurl( InternetOpenUrlA( xinternet.get(), request.c_str(), NULL, 0, 0, 0 ) );
    if ( 0 == xurl.get() )
        return "";

    // <title> is in the first 300 bytes of the response
    const DWORD chunk = 300;
    vector<char> response( 1 + chunk );
    DWORD dwRead = 0;
    BOOL ok = InternetReadFile( xurl.get(), response.data(), chunk, &dwRead );
    if ( !ok )
        return "";

    response[ __min( dwRead, response.size() - 1 ) ] = 0;

    char * title = strstr( response.data(), "<title>" );
    if ( title )
    {
        char * dash = strchr( title, '-' );
        if ( dash )
        {
            char * bar = strchr( dash, '|' );
            if ( bar )
            {
                char * start = dash + 2;
                size_t len = bar - start - 1;
                if ( len >= 2 )
                    return string( start, len );
            }
        }
    }

    return "";
} //likelyOwnerFromLookIP

static string FindPrefixEntry( char * ip )
{
    char * dot = strchr( ip, '.' );
    if ( dot )
    {
        char * dot2 = strchr( dot + 1, '.' );
        if ( dot2 )
        {
            string prefix( ip, dot2 - ip );

            if ( g_prefixEntries.count( prefix ) )
                return g_prefixEntries[ prefix ];
        }
    }

    return "";
} //FindPrefixEntry

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
 
                CloseHandle( h );
                return true;
            }
        }

        CloseHandle( h );
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

static void PrintConnection( tcpconnection & conn )
{
    char localIP[ maxIP ];
    RtlIpv4AddressToStringA( (const in_addr *) &conn.tcp.dwLocalAddr, localIP );
    char remoteIP[ maxIP ];
    RtlIpv4AddressToStringA( (const in_addr *) &conn.tcp.dwRemoteAddr, remoteIP );

    snprintf( localIP + strlen( localIP ), _countof( localIP ) - strlen( localIP ), ":%d", ntohs( (u_short) conn.tcp.dwLocalPort ) );
    snprintf( remoteIP + strlen( remoteIP ), _countof( remoteIP ) - strlen( remoteIP ), ":%d", ntohs( (u_short) conn.tcp.dwRemotePort ) );

    WCHAR procname[ MAX_PATH ];
    FindProcessName( conn.tcp.dwOwningPid, procname );
        
    printf( "  %-12s %-21s %-21s %-54s  %-6d %ws\n", TcpState( conn.tcp.dwState ), localIP, remoteIP, conn.remoteName.c_str(), conn.tcp.dwOwningPid, procname );
} //PrintConnection

static void InitializePrefixEntries()
{
    // most of these are Microsoft services that run on Azure -- Office, Defender, etc.

    g_prefixEntries[ "192.168" ] = "PrivateNetwork";
    g_prefixEntries[ "13.69" ] = "Microsoft Azure";
    g_prefixEntries[ "13.78" ] = "Microsoft Azure";
    g_prefixEntries[ "13.89" ] = "Microsoft Azure";
    g_prefixEntries[ "13.91" ] = "Microsoft Azure";
    g_prefixEntries[ "13.105" ] = "Microsoft Azure";
    g_prefixEntries[ "13.107" ] = "Microsoft Azure";
    g_prefixEntries[ "20.40" ] = "Microsoft Azure";
    g_prefixEntries[ "20.42" ] = "Microsoft Azure";
    g_prefixEntries[ "20.44" ] = "Microsoft Azure";
    g_prefixEntries[ "20.49" ] = "Microsoft Azure";
    g_prefixEntries[ "20.50" ] = "Microsoft Azure";
    g_prefixEntries[ "20.54" ] = "Microsoft Azure";
    g_prefixEntries[ "20.60" ] = "Microsoft Azure";
    g_prefixEntries[ "20.69" ] = "Microsoft Azure";
    g_prefixEntries[ "20.72" ] = "Microsoft Azure";
    g_prefixEntries[ "20.189" ] = "Microsoft Azure";
    g_prefixEntries[ "20.190" ] = "Microsoft Azure";
    g_prefixEntries[ "40.70" ] = "Microsoft Azure";
    g_prefixEntries[ "40.79" ] = "Microsoft Azure";
    g_prefixEntries[ "40.90" ] = "Microsoft Azure";
    g_prefixEntries[ "40.91" ] = "Microsoft Azure";
    g_prefixEntries[ "40.97" ] = "Microsoft Azure";
    g_prefixEntries[ "40.125" ] = "Microsoft Azure";
    g_prefixEntries[ "40.126" ] = "Microsoft Azure";
    g_prefixEntries[ "51.132" ] = "Microsoft Azure";
    g_prefixEntries[ "52.96" ] = "Microsoft Azure";
    g_prefixEntries[ "52.108" ] = "Microsoft Azure";
    g_prefixEntries[ "52.109" ] = "Microsoft Azure";
    g_prefixEntries[ "52.111" ] = "Microsoft Azure";
    g_prefixEntries[ "52.113" ] = "Microsoft Azure";
    g_prefixEntries[ "52.152" ] = "Microsoft Azure";
    g_prefixEntries[ "52.160" ] = "Microsoft Azure";
    g_prefixEntries[ "52.168" ] = "Microsoft Azure";
    g_prefixEntries[ "52.174" ] = "Microsoft Azure";
    g_prefixEntries[ "52.182" ] = "Microsoft Azure";
    g_prefixEntries[ "52.239" ] = "Microsoft Azure";
    g_prefixEntries[ "52.249" ] = "Microsoft Azure";
    g_prefixEntries[ "52.137" ] = "Microsoft Azure";
    g_prefixEntries[ "104.208" ] = "Microsoft Azure";
    g_prefixEntries[ "104.46" ] = "Microsoft Azure";
} //InitializePrefixEntries

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
    bool useLookIP = false;
    InitializePrefixEntries();

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
               else if ( 'x' == a1 )
                   useLookIP = true;
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
        int passes = 0;
        vector<tcpconnection> prev( 0 );

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

            vector<tcpconnection> conns( limit );
            for ( int i = 0; i < limit; i++ )
            {
                tcpconnection & conn = conns[ i ];
                conn.tcp = ptable->table[ i ];
                conn.newConnection = false;
                conn.conName = ConName::unresolvedCN;
            }

            vector<int> unresolvedIndexes;

            for ( int i = 0; i < limit; i++ )
            {
                tcpconnection & conn = conns[ i ];
                bool duplicate = false;

                for ( int p = 0; p < prev.size(); p++ )
                {
                    tcpconnection & pr = prev[ p ];

                    if ( 0 == memcmp( & pr.tcp, & conn.tcp, sizeof conn.tcp ) )
                    {
                        duplicate = true;
                        break;
                    }
                }

                if ( duplicate )
                    continue;

                conn.newConnection = true;

                char remoteIP[ maxIP ];
                RtlIpv4AddressToStringA( (const in_addr *) &conn.tcp.dwRemoteAddr, remoteIP );
                string remoteip( remoteIP );

                if ( g_persistentEntries.count( remoteip ) )
                {
                    conn.remoteName = g_persistentEntries[ remoteip ];
                    conn.conName = ConName::persistentCN;
                    PrintConnection( conn );
                }
                else if ( g_unknownEntries.count( remoteip ) )
                {
                    conn.remoteName.assign( "(unknown)" );
                    conn.conName = ConName::unknownCN;
                }

                if ( ConName::unresolvedCN == conn.conName )
                    unresolvedIndexes.push_back( i );
            }

            // Perform a reverse DNS lookup for unresolved entries

            int unresolvedCount = unresolvedIndexes.size();
            //for ( int u = 0; u < unresolvedCount; u++ )
            parallel_for( 0, unresolvedCount, [&] ( int u )
            {
                tcpconnection & conn = conns[ unresolvedIndexes[ u ] ];

                char remoteIP[ maxIP ];
                RtlIpv4AddressToStringA( (const in_addr *) &conn.tcp.dwRemoteAddr, remoteIP );
                char hostname[ NI_MAXHOST ];
                IpToName( remoteIP, ntohs( (u_short) conn.tcp.dwRemotePort ), hostname );

                if ( 0 != hostname[ 0 ] )
                {
                    conn.remoteName = hostname;
                    conn.conName = ConName::revipCN;
                }
                else
                {
                    conn.remoteName = FindPrefixEntry( remoteIP );

                    if ( conn.remoteName.length() )
                    {
                        conn.conName = ConName::prefixCN;
                    }
                    else if ( useLookIP )
                    {
                         conn.remoteName = likelyOwnerFromLookIP( remoteIP );
                         conn.conName = ConName::lookipCN;
                    }

                    if ( !conn.remoteName.length() )
                    {
                        conn.remoteName = "(unknown)";
                        conn.conName = ConName::unknownCN;
                    }
                }
            } , static_partitioner() ); // huge performance win over default partitioner; avoid spinlocks

            for ( int i = 0; i < limit; i++ )
            {
                tcpconnection & conn = conns[ i ];

                if ( conn.newConnection )
                {
                    if ( conn.conName == ConName::lookipCN ||
                         conn.conName == ConName::prefixCN ||
                         conn.conName == ConName::revipCN )
                    {
                        char remoteIP[ maxIP ];
                        RtlIpv4AddressToStringA( (const in_addr *) &conn.tcp.dwRemoteAddr, remoteIP );

                        if ( ! g_persistentEntries.count( remoteIP ) )
                        {
                            g_persistentEntries[ remoteIP ] = conn.remoteName;
                            printf( "persistent entries count %zd\n", g_persistentEntries.size() );

                            FILE * fp = _wfopen( pwcDNSEntriesFile, L"a" );
                            if ( fp )
                            {
                                fprintf( fp, "%s %s\n", remoteIP, conn.remoteName.c_str() );
                                fclose( fp );
                            }
                        }
                    }
                    else if ( ConName::unknownCN == conn.conName )
                        g_unknownEntries.insert( conn.remoteName );

                    if ( ConName::persistentCN != conn.conName )
                        PrintConnection( conn );
                }
            }
          
            prev.clear();
            prev.swap( conns );

            if ( -1 != loopPasses )
            {
                passes++;
                if ( passes >= loopPasses )
                    break;
            }

            if ( loop )
                Sleep( 50 );
        } while ( loop );
    }
    catch( ... )
    {
        wprintf( L"caught an exception in nc.exe, exiting\n" );
    }

    return 0;
} //main


