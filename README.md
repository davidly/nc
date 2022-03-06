# nc
Network Connections -- Windows command-line app to show active outbound network connections

usage: nc [-l] [-o] [-x]

    Shows outbound Network Connections
    arguments:   [-l]    loop infinitely
                 [-l:X]  loop X times
                 [-o]     Append to nc_output.txt with timestamps and connections as a CSV file
                 [-x]    use lookip.net for reverse dns lookups
    notes:       reads from and writes to dns_entries.txt
    
Sample usage:

C:\Users\david\OneDrive\nc>nc

    State        Local address         Foreign address       Host/Company                                            PID    Process
    established  192.168.0.105:49759   13.64.180.106:443     wns.windows.com                                         5372   svchost / Windows Push Notifications System Service
    time_wait    192.168.0.105:49992   13.107.5.93:443       Microsoft Azure                                         0      idle
    established  192.168.0.105:50214   40.97.85.18:443       Microsoft Azure                                         11348  SearchHost
    established  127.0.0.1:50238       127.0.0.1:65001       david-pc                                                5816   nvcontainer / NVIDIA LocalSystem Container
    established  127.0.0.1:50241       127.0.0.1:50256       david-pc                                                12448  NVIDIA Web Helper
    established  127.0.0.1:50256       127.0.0.1:50241       david-pc                                                16272  NVIDIA Share
    established  192.168.0.105:50296   40.83.247.108:443     Microsoft Azure                                         13240  OneDrive
    established  127.0.0.1:50345       127.0.0.1:50532       david-pc                                                22296  node
    established  127.0.0.1:50532       127.0.0.1:50345       david-pc                                                21776  Adobe CEF Helper
    established  192.168.0.105:50648   52.108.78.24:443      Microsoft Azure                                         17792  EXCEL
    established  192.168.0.105:50755   40.97.132.34:443      Microsoft Azure                                         1796   OUTLOOK
    established  192.168.0.105:50884   40.97.85.66:443       Microsoft Azure                                         1796   OUTLOOK
    established  192.168.0.105:51030   65.8.158.29:443       server-65-8-158-29.sfo53.r.cloudfront.net               17460  msedge
    established  192.168.0.105:51611   54.161.91.12:443      ec2-54-161-91-12.compute-1.amazonaws.com                21820  CoreSync
    established  192.168.0.105:52897   104.244.42.1:443      Twitter                                                 17460  msedge
    established  192.168.0.105:53167   52.96.164.66:443      Microsoft Azure                                         1796   OUTLOOK
    established  192.168.0.105:53176   40.97.143.146:443     outlook.com                                             1796   OUTLOOK
    established  192.168.0.105:53179   54.208.86.132:443     ec2-54-208-86-132.compute-1.amazonaws.com               21820  CoreSync
    close_wait   192.168.0.105:53185   23.44.160.62:443      a23-44-160-62.deploy.static.akamaitechnologies.com      7900   Video.UI
    established  192.168.0.105:53213   13.107.42.12:443      1drv.ms                                                 13240  OneDrive
    established  192.168.0.105:53235   20.189.173.12:443     Microsoft Azure                                         13240  OneDrive
    time_wait    192.168.0.105:53248   40.97.116.82:443      outlook.com                                             0      idle
    established  192.168.0.105:53249   192.229.173.16:443    Verizon Business                                        17460  msedge
    time_wait    192.168.0.105:53252   40.97.116.82:443      outlook.com                                             0      idle
    time_wait    192.168.0.105:53253   52.109.6.42:443       Microsoft Azure                                         0      idle
    time_wait    192.168.0.105:53254   40.90.130.197:443     Microsoft Azure                                         0      idle
    time_wait    192.168.0.105:53256   20.60.18.36:443       Microsoft Azure                                         0      idle
    established  192.168.0.105:53259   52.147.223.103:443    wdcp.microsoft.com                                      5460   MsMpEng / Microsoft Defender Antivirus Service
    established  192.168.0.105:53261   13.107.42.12:443      1drv.ms                                                 13240  OneDrive
    established  192.168.0.105:53262   13.107.42.12:443      1drv.ms                                                 13240  OneDrive
        
