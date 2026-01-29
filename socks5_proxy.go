package wireproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

const (
	socks5Version         = 0x05
	socks5AuthNone        = 0x00
	socks5AuthUserPass    = 0x02
	socks5AuthNoAccept    = 0xff
	socks5CommandUDPAssoc = 0x03
	socks5AddrIPv4        = 0x01
	socks5AddrDomain      = 0x03
	socks5AddrIPv6        = 0x04
)

type socks5ProxyEndpoint struct {
	dst netip.AddrPort
	src netip.AddrPort
}

func (e *socks5ProxyEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *socks5ProxyEndpoint) SrcToString() string {
	if !e.src.IsValid() {
		return ""
	}
	return e.src.String()
}

func (e *socks5ProxyEndpoint) DstToString() string {
	return e.dst.String()
}

func (e *socks5ProxyEndpoint) DstToBytes() []byte {
	b, _ := e.dst.MarshalBinary()
	return b
}

func (e *socks5ProxyEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *socks5ProxyEndpoint) SrcIP() netip.Addr {
	return e.src.Addr()
}

type socks5ProxyBind struct {
	proxyAddr string
	username  string
	password  string

	mu       sync.Mutex
	tcpConn  net.Conn
	udpConn  *net.UDPConn
	udpRelay *net.UDPAddr

	ctx    context.Context
	cancel context.CancelFunc

	recvBufPool sync.Pool
}

func NewSocks5ProxyBind(config *Socks5ProxyConfig) conn.Bind {
	return &socks5ProxyBind{
		proxyAddr: config.Address,
		username:  config.Username,
		password:  config.Password,
		recvBufPool: sync.Pool{
			New: func() any {
				return make([]byte, 65535)
			},
		},
	}
}

func (b *socks5ProxyBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.udpConn != nil || b.tcpConn != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}

	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(port)})
	if err != nil {
		return nil, 0, err
	}

	tcpConn, udpRelay, err := b.connect()
	if err != nil {
		_ = udpConn.Close()
		return nil, 0, err
	}

	b.ctx, b.cancel = context.WithCancel(context.Background())
	b.tcpConn = tcpConn
	b.udpConn = udpConn
	b.udpRelay = udpRelay

	go b.monitorTCP(tcpConn)

	actualPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)

	return []conn.ReceiveFunc{b.receive}, actualPort, nil
}

func (b *socks5ProxyBind) connect() (net.Conn, *net.UDPAddr, error) {
	tcpConn, err := net.Dial("tcp", b.proxyAddr)
	if err != nil {
		return nil, nil, err
	}

	udpRelay, err := negotiateSocks5UDP(tcpConn, b.username, b.password)
	if err != nil {
		_ = tcpConn.Close()
		return nil, nil, err
	}

	return tcpConn, udpRelay, nil
}

func (b *socks5ProxyBind) monitorTCP(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	for {
		if _, err := conn.Read(buf); err != nil {
			conn.Close()
			b.reconnectLoop()
			return
		}
	}
}

func (b *socks5ProxyBind) reconnectLoop() {
	b.mu.Lock()
	// Check if already closed
	select {
	case <-b.ctx.Done():
		b.mu.Unlock()
		return
	default:
	}
	// Mark as disconnected
	b.tcpConn = nil
	b.udpRelay = nil
	b.mu.Unlock()

	for {
		select {
		case <-b.ctx.Done():
			return
		default:
		}

		tcpConn, udpRelay, err := b.connect()
		if err == nil {
			b.mu.Lock()
			select {
			case <-b.ctx.Done():
				b.mu.Unlock()
				tcpConn.Close()
				return
			default:
				b.tcpConn = tcpConn
				b.udpRelay = udpRelay
			}
			b.mu.Unlock()

			go b.monitorTCP(tcpConn)
			return
		}

		select {
		case <-b.ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
}

func (b *socks5ProxyBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.cancel != nil {
		b.cancel()
	}

	var err error
	if b.tcpConn != nil {
		err = errors.Join(err, b.tcpConn.Close())
		b.tcpConn = nil
	}
	if b.udpConn != nil {
		err = errors.Join(err, b.udpConn.Close())
		b.udpConn = nil
	}
	b.udpRelay = nil
	return err
}

func (b *socks5ProxyBind) SetMark(mark uint32) error {
	return nil
}

func (b *socks5ProxyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	udpConn := b.udpConn
	udpRelay := b.udpRelay
	b.mu.Unlock()

	if udpConn == nil || udpRelay == nil {
		return net.ErrClosed
	}

	endpoint, ok := ep.(*socks5ProxyEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	for _, buf := range bufs {
		packet := buildSocks5UDPPacket(endpoint.dst, buf)
		if _, err := udpConn.WriteToUDP(packet, udpRelay); err != nil {
			return err
		}
	}

	return nil
}

func (b *socks5ProxyBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &socks5ProxyEndpoint{dst: addr}, nil
}

func (b *socks5ProxyBind) BatchSize() int {
	return conn.IdealBatchSize
}

func (b *socks5ProxyBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(packets) == 0 {
		return 0, nil
	}

	b.mu.Lock()
	udpConn := b.udpConn
	b.mu.Unlock()

	if udpConn == nil {
		return 0, net.ErrClosed
	}

	buf := b.recvBufPool.Get().([]byte)
	defer b.recvBufPool.Put(buf)

	n, _, err := udpConn.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}

	addr, payload, err := parseSocks5UDPPacket(buf[:n])
	if err != nil {
		return 0, err
	}

	if len(payload) > len(packets[0]) {
		return 0, io.ErrShortBuffer
	}

	copy(packets[0], payload)
	sizes[0] = len(payload)
	eps[0] = &socks5ProxyEndpoint{dst: addr}

	return 1, nil
}

func negotiateSocks5UDP(conn net.Conn, username, password string) (*net.UDPAddr, error) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := socks5Handshake(conn, username, password); err != nil {
		_ = conn.SetDeadline(time.Time{})
		return nil, err
	}

	udpRelay, err := socks5UDPAssociate(conn)
	_ = conn.SetDeadline(time.Time{})
	return udpRelay, err
}

func socks5Handshake(conn net.Conn, username, password string) error {
	methods := []byte{socks5AuthNone}
	if username != "" || password != "" {
		methods = []byte{socks5AuthUserPass}
	}

	req := append([]byte{socks5Version, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("invalid socks5 version: %d", resp[0])
	}

	switch resp[1] {
	case socks5AuthNone:
		return nil
	case socks5AuthUserPass:
		return socks5UserPassAuth(conn, username, password)
	case socks5AuthNoAccept:
		return errors.New("socks5 proxy rejected authentication methods")
	default:
		return fmt.Errorf("unsupported socks5 auth method: %d", resp[1])
	}
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	if len(username) > 255 || len(password) > 255 {
		return errors.New("socks5 username/password too long")
	}

	req := make([]byte, 0, 3+len(username)+len(password))
	req = append(req, 0x01, byte(len(username)))
	req = append(req, []byte(username)...)
	req = append(req, byte(len(password)))
	req = append(req, []byte(password)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x01 {
		return fmt.Errorf("unexpected socks5 auth version: %d", resp[0])
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 authentication failed")
	}
	return nil
}

func socks5UDPAssociate(conn net.Conn) (*net.UDPAddr, error) {
	req := []byte{
		socks5Version,
		socks5CommandUDPAssoc,
		0x00,
		socks5AddrIPv4,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}

	reply := make([]byte, 4)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if reply[0] != socks5Version {
		return nil, fmt.Errorf("invalid socks5 version: %d", reply[0])
	}
	if reply[1] != 0x00 {
		return nil, fmt.Errorf("socks5 UDP associate failed with code: %d", reply[1])
	}

	addr, port, err := readSocks5Addr(conn, reply[3])
	if err != nil {
		return nil, err
	}

	if !addr.IsValid() {
		return nil, errors.New("socks5 UDP associate returned invalid address")
	}

	if addr.IsUnspecified() {
		remote := conn.RemoteAddr().(*net.TCPAddr)
		if ip, ok := netip.AddrFromSlice(remote.IP); ok {
			addr = ip
		}
	}

	return &net.UDPAddr{IP: addr.AsSlice(), Port: int(port)}, nil
}

func readSocks5Addr(r io.Reader, atyp byte) (netip.Addr, uint16, error) {
	var addr netip.Addr
	switch atyp {
	case socks5AddrIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return addr, 0, err
		}
		addr = netip.AddrFrom4([4]byte{ip[0], ip[1], ip[2], ip[3]})
	case socks5AddrIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return addr, 0, err
		}
		addr = netip.AddrFrom16([16]byte{
			ip[0], ip[1], ip[2], ip[3],
			ip[4], ip[5], ip[6], ip[7],
			ip[8], ip[9], ip[10], ip[11],
			ip[12], ip[13], ip[14], ip[15],
		})
	case socks5AddrDomain:
		nameLen := make([]byte, 1)
		if _, err := io.ReadFull(r, nameLen); err != nil {
			return addr, 0, err
		}
		name := make([]byte, nameLen[0])
		if _, err := io.ReadFull(r, name); err != nil {
			return addr, 0, err
		}
		resolved, err := resolveDomain(string(name))
		if err != nil {
			return addr, 0, err
		}
		addr = resolved
	default:
		return addr, 0, fmt.Errorf("unsupported socks5 address type: %d", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return addr, 0, err
	}
	port := binary.BigEndian.Uint16(portBuf)
	return addr, port, nil
}

func resolveDomain(name string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(context.Background(), name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, addr := range addrs {
		if ip, ok := netip.AddrFromSlice(addr.IP); ok {
			return ip, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IP found for %s", name)
}

func buildSocks5UDPPacket(dst netip.AddrPort, payload []byte) []byte {
	header := make([]byte, 0, 6+len(payload)+16)
	header = append(header, 0x00, 0x00, 0x00)

	if dst.Addr().Is4() {
		header = append(header, socks5AddrIPv4)
		header = append(header, dst.Addr().AsSlice()...)
	} else {
		header = append(header, socks5AddrIPv6)
		header = append(header, dst.Addr().AsSlice()...)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, dst.Port())
	header = append(header, portBytes...)
	header = append(header, payload...)
	return header
}

func parseSocks5UDPPacket(packet []byte) (netip.AddrPort, []byte, error) {
	if len(packet) < 4 {
		return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
	}
	if packet[0] != 0x00 || packet[1] != 0x00 {
		return netip.AddrPort{}, nil, errors.New("invalid socks5 UDP RSV header")
	}
	if packet[2] != 0x00 {
		return netip.AddrPort{}, nil, errors.New("socks5 UDP fragmentation not supported")
	}

	atyp := packet[3]
	offset := 4
	var addr netip.Addr

	switch atyp {
	case socks5AddrIPv4:
		if len(packet) < offset+4+2 {
			return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
		}
		addr = netip.AddrFrom4([4]byte{packet[offset], packet[offset+1], packet[offset+2], packet[offset+3]})
		offset += 4
	case socks5AddrIPv6:
		if len(packet) < offset+16+2 {
			return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
		}
		addr = netip.AddrFrom16([16]byte{
			packet[offset], packet[offset+1], packet[offset+2], packet[offset+3],
			packet[offset+4], packet[offset+5], packet[offset+6], packet[offset+7],
			packet[offset+8], packet[offset+9], packet[offset+10], packet[offset+11],
			packet[offset+12], packet[offset+13], packet[offset+14], packet[offset+15],
		})
		offset += 16
	case socks5AddrDomain:
		if len(packet) < offset+1 {
			return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
		}
		nameLen := int(packet[offset])
		offset++
		if len(packet) < offset+nameLen+2 {
			return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
		}
		name := string(packet[offset : offset+nameLen])
		resolved, err := resolveDomain(name)
		if err != nil {
			return netip.AddrPort{}, nil, err
		}
		addr = resolved
		offset += nameLen
	default:
		return netip.AddrPort{}, nil, fmt.Errorf("unsupported socks5 address type: %d", atyp)
	}

	if len(packet) < offset+2 {
		return netip.AddrPort{}, nil, io.ErrUnexpectedEOF
	}
	port := binary.BigEndian.Uint16(packet[offset : offset+2])
	offset += 2

	addrPort := netip.AddrPortFrom(addr, port)
	return addrPort, packet[offset:], nil
}
