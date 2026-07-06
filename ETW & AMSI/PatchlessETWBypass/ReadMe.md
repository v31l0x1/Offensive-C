### Capture ETW

```batch
logman create trace ETWTest -p "Microsoft-Windows-Kernel-Process" -o C:\Temp\ETWTest.etl
logman start ETWTest

logman stop ETWTest
```

### Verify the etw logs

```powershell
Get-WinEvent -Path C:\Temp\ETWTest.etl | Where-Object { $_.ProcessId -eq $myPid } | Measure-Object
```
