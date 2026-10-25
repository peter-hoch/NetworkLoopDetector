# Network Loop Detector

Tests every connected (Up) Ethernet/Wi-Fi interface for Layer-2 loops.

## usage

Run:  

- Windows (admin, Npcap installed):   `LoopDetector.exe`  
- Linux   (root, libpcap installed):  `sudo dotnet loopdetector.dll`  

Options:  

- `--frames <n>`      test frames per interface         (default 3)
- `--baseline <sec>`  broadcast measurement window      (default 3)
- `--wait <sec>`      time to wait for echoes           (default 2)  
- `--threshold <n>`   broadcast pkts/s = storm          (default 1000)

 Exit code: 0 = no loop, 1 = loop / storm detected, 2 = error

## sample output

output with detected loop  

```powershell
PS D:\NetworkLoopDetector> dotnet run --project LoopDetector -- --frames 5
Testing 4 interface(s): 5 frame(s), 3s baseline, 2s echo wait ...

Interface                    MAC               Sent  Seen MaxCopies   Bcast/s  Result
----------------------------------------------------------------------------------------------------
vEthernet (Local 150)        xx:xx:xx:xx:xx:xx    5     5         1      3574  BROADCAST STORM (possible loop)
vEthernet (Local 178)        xx:xx:xx:xx:xx:xx    5     5         1         4  OK
vEthernet (Default Switch)   xx:xx:xx:xx:xx:xx    5     5         1         0  OK
Ethernet 4                   xx:xx:xx:xx:xx:xx    5     5         1         0  OK

==> LOOP / BROADCAST STORM DETECTED
```

output without detected loop  

```powershell
PS D:\NetworkLoopDetector> dotnet run --project LoopDetector -- --frames 5
Testing 4 interface(s): 5 frame(s), 3s baseline, 2s echo wait ...

Interface                    MAC               Sent  Seen MaxCopies   Bcast/s  Result
----------------------------------------------------------------------------------------------------
vEthernet (Local 150)        xx:xx:xx:xx:xx:xx    5     5         1         0  OK
vEthernet (Local 178)        xx:xx:xx:xx:xx:xx    5     5         1         2  OK
vEthernet (Default Switch)   xx:xx:xx:xx:xx:xx    5     5         1         0  OK
Ethernet 4                   xx:xx:xx:xx:xx:xx    5     5         1         0  OK

==> No loop detected
```
