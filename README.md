# BYOVD-Process-Terminator

- Malware authors are using the vulnerabilties in the `zam64.sys` and `zamgaurd64.sys` driver to use them as killing the EDRs/AVs processes.
- These drivers are part of the `ZemannaAntiMalware`. 
- I have taken the driver from [loldrivers](https://www.loldrivers.io/drivers/e5f12b82-8d07-474e-9587-8c7b3714d60c/).

## Usage

- The compiled version of the binary of can be found [here](/BYOVD-Process-Terminator/x64/Debug/process_terminator.exe) 
- run the program as administrator, Don't forgot to copy the driver also.
- Give the pid of the process which you want to be terminated as argument.
```powershell
Usage: process_terminator.exe <pid>
```
<video controls src="video/2024-09-19 23-18-49.mp4" title="Title"></video>

## Writeup