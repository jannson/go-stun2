package stun

import (
	"net"
	"sync"
)

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

		if ch, ok := msg.GetInt(AttrChangeRequest); ok && ch != 0 {
			for _, c := range conns {
				chip, chport := SockAddr(c.LocalAddr())
				if chip.IsUnspecified() {
					continue
				}
				if ch&ChangeIP != 0 {
					if !ip.Equal(chip) {
						to = &packetConn{c, mapped}
						break
					}
				} else if ch&ChangePort != 0 {
					if ip.Equal(chip) && port != chport {
						to = &packetConn{c, mapped}
						break
					}
				}
			}
		}

		if len(conns) < 2 {
			srv.agent.Send(res, to)
			return
		}

	other:
		for _, a := range conns {
			aip, aport := SockAddr(a.LocalAddr())
			if aip.IsUnspecified() || !ip.Equal(aip) || port == aport {
				//找一个 IP 相同但端口不同的本地连接 a
				continue
			}
			for _, b := range conns {
				bip, bport := SockAddr(b.LocalAddr())
				if bip.IsUnspecified() || bip.Equal(ip) || aport != bport {
					//找一个 IP 不同但端口等同于连接 a 的端口
					//最终找到跟自己 IP 不同同时跟自己端口也不同的地址
					continue
				}
				res.Set(Addr(AttrOtherAddress, b.LocalAddr()))
				break other
			}
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
