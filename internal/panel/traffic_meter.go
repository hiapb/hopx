package panel

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

func (s *Server) loadMeterKey() error {
	var fresh [ed25519.SeedSize]byte
	if _, err := rand.Read(fresh[:]); err != nil {
		return err
	}
	if _, err := s.db.Exec("INSERT OR IGNORE INTO traffic_meter_key(singleton,seed) VALUES(1,?)", fresh[:]); err != nil {
		return err
	}
	var seed []byte
	if err := s.db.QueryRow("SELECT seed FROM traffic_meter_key WHERE singleton=1").Scan(&seed); err != nil {
		return err
	}
	if len(seed) != ed25519.SeedSize {
		return fmt.Errorf("invalid traffic meter signing key")
	}
	s.meterKey = ed25519.NewKeyFromSeed(seed)
	return nil
}
