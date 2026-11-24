package panel

import (
	"crypto/rand"
	"crypto/subtle"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type attempt struct {
	start time.Time
	count int
}
type authGuard struct {
	mu        sync.Mutex
	clients   map[string]attempt
	nextSweep time.Time
	bcrypt    chan struct{}
}

func (g *authGuard) allow(remote string) bool {
	host, _, e := net.SplitHostPort(remote)
	if e != nil {
		host = remote
	}
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if now.After(g.nextSweep) {
		for ip, try := range g.clients {
			if now.Sub(try.start) >= time.Minute {
				delete(g.clients, ip)
			}
		}
		g.nextSweep = now.Add(time.Minute)
	}
	try, ok := g.clients[host]
	if !ok && len(g.clients) >= 4096 {
		return false
	}
	if now.Sub(try.start) >= time.Minute {
		try = attempt{start: now}
	}
	if try.count >= 20 {
		return false
	}
	try.count++
	g.clients[host] = try
	return true
}

// A short-lived arithmetic challenge provides optional registration throttling
// without third-party script dependencies.
type challenge struct {
	Answer byte
	Ends   time.Time
}

type captchaStore struct {
	sync.Mutex
	items map[string]challenge
}

func (s *Server) makeChallenge(w http.ResponseWriter, r *http.Request) {
	config, err := readRegistrationVerification(s.db)
	if err != nil {
		dbFailure(w, err)
		return
	}
	if config.mode == "closed" || config.kind != verificationArithmetic {
		fail(w, 404, "注册验证未开启")
		return
	}
	if !s.guard.allow(r.RemoteAddr) {
		fail(w, 429, "请求过于频繁")
		return
	}
	now := time.Now()
	var data [2]byte
	if _, err := io.ReadFull(rand.Reader, data[:]); err != nil {
		fail(w, 500, "无法生成注册验证")
		return
	}
	a, b := data[0]%15+1, data[1]%15+1
	key := token()
	s.captcha.Lock()
	for k, item := range s.captcha.items {
		if !now.Before(item.Ends) {
			delete(s.captcha.items, k)
		}
	}
	if len(s.captcha.items) >= 4096 {
		s.captcha.Unlock()
		fail(w, 429, "注册验证码繁忙")
		return
	}
	s.captcha.items[key] = challenge{Answer: a + b, Ends: now.Add(5 * time.Minute)}
	s.captcha.Unlock()
	respond(w, 200, map[string]any{"id": key, "left": a, "right": b})
}

func (s *Server) checkChallenge(id string, answer int) bool {
	s.captcha.Lock()
	defer s.captcha.Unlock()
	item, ok := s.captcha.items[id]
	delete(s.captcha.items, id)
	if !ok || answer < 0 || answer > 255 || time.Now().After(item.Ends) {
		return false
	}
	return subtle.ConstantTimeByteEq(item.Answer, byte(answer)) == 1
}
