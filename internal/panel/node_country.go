package panel

import (
	"net"
	"net/netip"

	"hopx/internal/wire"
)

func (s *Server) nodeCountry(reg wire.Registration) string {
	if s.countryDB == nil {
		return ""
	}
	for _, candidate := range [...]string{reg.IPv4, reg.IPv6, reg.Address} {
		address, err := netip.ParseAddr(candidate)
		if err != nil {
			if host, _, err := net.SplitHostPort(candidate); err == nil {
				address, _ = netip.ParseAddr(host)
			}
		}
		address = address.Unmap()
		if !wire.PublicDestination(address) {
			continue
		}
		var code string
		err = s.countryDB.Lookup(address).DecodePath(&code, "country", "iso_code")
		if err == nil && len(code) == 2 && code[0] >= 'A' && code[0] <= 'Z' && code[1] >= 'A' && code[1] <= 'Z' {
			return code
		}
	}
	return ""
}
