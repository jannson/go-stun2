package stun

import (
	"log"
	"net"
	"os"
	"sync"
)

var debugSTUN = os.Getenv("STUN_DEBUG") != ""

func ListenAndServe(network, laddr string, config *Config) error {
	srv := NewServer(config)
	return srv.ListenAndServe(network, laddr)
}

type Server struct {
	agent *Agent

	mu    sync.RWMutex
	conns []net.PacketConn
}

func NewServer(config *Config) *Server {
	srv := &Server{agent: NewAgent(config)}
	srv.agent.Handler = srv
	return srv
}

func (srv *Server) ListenAndServe(network, laddr string) error {
	c, err := net.ListenPacket(network, laddr)
	if err != nil {
		return err
	}
	srv.addConn(c)
	defer srv.removeConn(c)
	return srv.agent.ServePacket(c)
}

func (srv *Server) Serve(c net.PacketConn) error {
	srv.addConn(c)
	defer srv.removeConn(c)
	return srv.agent.ServePacket(c)
}

func (srv *Server) ServeSTUN(msg *Message, from Transport) {
	if msg.Type == MethodBinding {
		to := from
		mapped := from.RemoteAddr()
		ip, port := SockAddr(from.LocalAddr())
		chVal, _ := msg.GetInt(AttrChangeRequest)
		if debugSTUN {
			log.Printf("[stun] recv binding from=%v local=%v changeReq=%v", mapped, from.LocalAddr(), chVal)
		}

		res := &Message{
			Type:        MethodBinding | KindResponse,
			Transaction: msg.Transaction,
			Attributes: []Attr{
				Addr(AttrXorMappedAddress, mapped),
				Addr(AttrMappedAddress, mapped),
			},
		}

		conns := make([]net.PacketConn, 0, 8)
		srv.mu.RLock()
		for i := 0; i < len(srv.conns); i++ {
			conns = append(conns, srv.conns[i])
		}
		srv.mu.RUnlock()

		var (
			otherConn         net.PacketConn
			sameIPDiffPort    net.PacketConn
			diffIPDiffPort    net.PacketConn
			otherAddrResolved net.Addr
		)

		// Precompute pairs to satisfy RFC5780:
		// a) OTHER-ADDRESS: different IP and different port.
		// b) CHANGE-REQUEST(change IP+port): use the same target as OTHER-ADDRESS when available.
		// c) CHANGE-REQUEST(change port): same IP, different port.
		for _, a := range conns {
			aip, aport := SockAddr(a.LocalAddr())
			if aip.IsUnspecified() {
				continue
			}
			// same IP, different port candidate
			if ip.Equal(aip) && port != aport && sameIPDiffPort == nil {
				sameIPDiffPort = a
			}
			// Look for a pair with different IP and different port.
			if ip.Equal(aip) {
				continue
			}
			if port == aport {
				continue
			}
			// prefer the first different IP+port as diffIPDiffPort
			if diffIPDiffPort == nil {
				diffIPDiffPort = a
			}
			// if we already found a same-IP-diff-port with matching port, set otherConn
			if sameIPDiffPort != nil {
				if _, aport2 := SockAddr(sameIPDiffPort.LocalAddr()); aport2 == aport {
					otherConn = a
					otherAddrResolved = a.LocalAddr()
				}
			}
		}

		// Fallback: if we didn't find paired ports, still set OTHER-ADDRESS to any diff IP+port.
		if otherConn == nil && diffIPDiffPort != nil {
			otherConn = diffIPDiffPort
			otherAddrResolved = diffIPDiffPort.LocalAddr()
		}

		// Apply CHANGE-REQUEST selection.
		if ch, ok := msg.GetInt(AttrChangeRequest); ok && ch != 0 {
			switch {
			case ch&(ChangeIP|ChangePort) == (ChangeIP | ChangePort):
				if otherConn != nil {
					to = &packetConn{otherConn, mapped}
				}
			case ch&ChangeIP != 0:
				if diffIPDiffPort != nil {
					to = &packetConn{diffIPDiffPort, mapped}
				}
			case ch&ChangePort != 0:
				if sameIPDiffPort != nil {
					to = &packetConn{sameIPDiffPort, mapped}
				}
			}
		}

		// Populate OTHER-ADDRESS if available.
		if otherAddrResolved != nil {
			res.Set(Addr(AttrOtherAddress, otherAddrResolved))
		}

		if len(conns) < 2 {
			if debugSTUN {
				log.Printf("[stun] send resp to=%v other=%v", to.LocalAddr(), otherAddrResolved)
			}
			srv.agent.Send(res, to)
			return
		}

		if debugSTUN {
			log.Printf("[stun] send resp to=%v other=%v", to.LocalAddr(), otherAddrResolved)
		}
		srv.agent.Send(res, to)
	}
}

func (srv *Server) addConn(c net.PacketConn) {
	srv.mu.Lock()
	srv.conns = append(srv.conns, c)
	srv.mu.Unlock()
}

func (srv *Server) removeConn(c net.PacketConn) {
	srv.mu.Lock()
	l := srv.conns
	for i, it := range l {
		if it == c {
			srv.conns = append(l[:i], l[i+1:]...)
			break
		}
	}
	srv.mu.Unlock()
}

func (srv *Server) Close() error {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	for _, it := range srv.conns {
		it.Close()
	}
	srv.conns = nil
	return nil
}
