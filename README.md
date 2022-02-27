# nc
Network Connections -- Windows command-line app to show active outbound network connections

usage: nc [-l]

    Shows outbound Network Connections
    arguments:   [-l]    loop infinitely
                 [-l:X]  loop X times
    notes:       reads from and writes to dns_entries.txt
    
Sample usage:

C:\Users\david\OneDrive\nc>nc

    State        Local address         Foreign address       Host/Company                                            PID    Process
    time_wait    192.168.0.105:64967   142.250.217.97:443    sea09s30-in-f1.1e100.net                                0      idle
    established  127.0.0.1:65001       127.0.0.1:50322       david-pc                                                5480   nvcontainer
    established  192.168.0.105:64957   34.149.130.207:443    207.130.149.34.bc.googleusercontent.com                 16388  msedge
    established  192.168.0.105:64940   8.39.36.141:443       The Rubicon Project                                     16388  msedge
    established  192.168.0.105:64949   34.107.191.194:443    194.191.107.34.bc.googleusercontent.com                 16388  msedge
    established  192.168.0.105:64931   151.101.22.217:443    Fastly                                                  16388  msedge
    established  192.168.0.105:64933   104.26.8.50:443       Cloudflare                                              16388  msedge
    time_wait    192.168.0.105:64928   142.251.33.110:443    sea30s10-in-f14.1e100.net                               0      idle
    established  192.168.0.105:52106   173.222.228.236:443   a173-222-228-236.deploy.static.akamaitechnologies.com   16388  msedge
    time_wait    192.168.0.105:64827   107.21.107.56:443     ec2-107-21-107-56.compute-1.amazonaws.com               0      idle
    time_wait    192.168.0.105:64837   34.98.72.95:443       95.72.98.34.bc.googleusercontent.com                    0      idle
    established  192.168.0.105:52146   52.96.165.18:443      Microsoft Azure                                         5612   OUTLOOK
    time_wait    192.168.0.105:52147   52.96.164.194:443     Microsoft Azure                                         0      idle
    established  192.168.0.105:60625   72.21.91.70:443       Edgecast/Verizon/Yahoo                                  16388  msedge
    established  192.168.0.105:60468   104.244.42.194:443    Twitter                                                 16388  msedge
    established  192.168.0.105:60692   34.111.8.32:443       32.8.111.34.bc.googleusercontent.com                    16388  msedge
    established  192.168.0.105:60653   151.101.21.67:443     Fastly                                                  16388  msedge
    established  192.168.0.105:52157   185.199.111.154:443   cdn-185-199-111-154.github.com                          16388  msedge
    established  192.168.0.105:60712   74.119.118.149:443    Criteo Corp.                                            16388  msedge
    established  192.168.0.105:60680   151.101.22.132:443    Fastly                                                  16388  msedge
    established  192.168.0.105:52161   40.97.143.146:443     outlook.com                                             5612   OUTLOOK
    established  192.168.0.105:60626   104.244.43.131:443    Fastly                                                  16388  msedge
    established  192.168.0.105:56814   13.64.180.106:443     wns.windows.com                                         5488   svchost
    established  192.168.0.105:60685   130.211.23.194:443    194.23.211.130.bc.googleusercontent.com                 16388  msedge
    established  192.168.0.105:60727   52.95.119.178:443     aax-eu.amazon-adsystem.com                              16388  msedge
    
    
