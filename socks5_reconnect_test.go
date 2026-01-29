package wireproxy

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// MockSocks5Server is a simple SOCKS5 server for testing
type MockSocks5Server struct {
	listener net.Listener
	udpConn  *net.UDPConn
	udpAddr  *net.UDPAddr
	tcpConns []net.Conn
}

func NewMockSocks5Server(t *testing.T) *MockSocks5Server {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}

	return &MockSocks5Server{
		listener: l,
		udpConn:  udpConn,
		udpAddr:  udpConn.LocalAddr().(*net.UDPAddr),
	}
}

func (s *MockSocks5Server) Address() string {
	return s.listener.Addr().String()
}

func (s *MockSocks5Server) Close() {
	s.listener.Close()
	s.udpConn.Close()
	for _, c := range s.tcpConns {
		c.Close()
	}
}

func (s *MockSocks5Server) Serve(t *testing.T) {
	go func() {
		for {
			c, err := s.listener.Accept()
			if err != nil {
				return
			}
			s.tcpConns = append(s.tcpConns, c)
			go s.handleConnection(t, c)
		}
	}()

	// Discard UDP packets
	go func() {
		buf := make([]byte, 65535)
		for {
			_, _, err := s.udpConn.ReadFromUDP(buf)
			if err != nil {
				return
			}
		}
	}()
}

func (s *MockSocks5Server) handleConnection(t *testing.T, c net.Conn) {
	// Negotiate
	// 1. Version identifier/method selection
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return
	}
	if n < 2 || buf[0] != 0x05 {
		return
	}
	// No auth
	c.Write([]byte{0x05, 0x00})

	// 2. Request details
	n, err = c.Read(buf)
	if err != nil {
		return
	}
	if n < 3 {
		return
	}
	cmd := buf[1]
	if cmd != 0x03 { // UDP Associate
		return
	}

	// Respond with bind address
	resp := []byte{0x05, 0x00, 0x00, 0x01}
	ip4 := s.udpAddr.IP.To4()
	resp = append(resp, ip4...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(s.udpAddr.Port))
	resp = append(resp, port...)
	c.Write(resp)

	// Keep connection open until closed
	io.Copy(io.Discard, c)
}

func (s *MockSocks5Server) CloseActiveTCPConnections() {
	for _, c := range s.tcpConns {
		c.Close()
	}
	s.tcpConns = nil
}

func TestSocks5Reconnect(t *testing.T) {
	server := NewMockSocks5Server(t)
	defer server.Close()
	server.Serve(t)

	conf := &Socks5ProxyConfig{
		Address: server.Address(),
	}

	bind := NewSocks5ProxyBind(conf)

	// Open bind
	recvFuncs, _, err := bind.Open(0)
	if err != nil {
		t.Fatalf("Failed to open bind: %v", err)
	}
	if len(recvFuncs) == 0 {
		t.Fatal("No receive functions")
	}

	// Send a packet
	ep, err := bind.ParseEndpoint("1.2.3.4:5678")
	if err != nil {
		t.Fatal(err)
	}

	err = bind.Send([][]byte{[]byte("hello")}, ep)
	if err != nil {
		t.Fatalf("Failed to send packet: %v", err)
	}

	// Close TCP connection from server side
	server.CloseActiveTCPConnections()

	// Give it a moment to detect and reconnect
	// If it reconnects, server will have new connections

	// Wait up to 5 seconds for reconnection (checking periodically)
	reconnected := false
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if len(server.tcpConns) > 0 {
			reconnected = true
			break
		}
	}

	if !reconnected {
		t.Error("Did not reconnect within timeout")
	} else {
		t.Log("Reconnected successfully")
	}

	// Ensure we can send again (though Send might return error if caught in between, but after reconnect it should work)
	// Actually Send doesn't check liveness, it just writes to local UDP.
	// But internally if we reconnected, udpRelay should be set.

	err = bind.Send([][]byte{[]byte("hello again")}, ep)
	if err != nil {
		t.Fatalf("Failed to send packet after reconnect: %v", err)
	}

	// Cleanup
	bind.Close()
}
