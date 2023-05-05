package option

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"time"
)

type URL url.URL

func (u *URL) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	u2, err := url.Parse(s)
	if err != nil {
		return err
	}
	*u = URL(*u2)
	return nil
}

func (u URL) MarshalJSON() ([]byte, error) {
	u2 := (url.URL)(u)
	return json.Marshal(u2.String())
}

func (u *URL) String() string {
	return (*url.URL)(u).String()
}

type JWTPublicKey struct {
	file      string
	PublicKey any
}

func (k *JWTPublicKey) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	k.file = s
	f, err := os.ReadFile(s)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(f)
	if block == nil {
		return fmt.Errorf("failed to decode pem file: %s", s)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	k.PublicKey = cert.PublicKey
	return nil
}

func (k JWTPublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.file)
}

type Address netip.AddrPort

func (a *Address) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	var a2 netip.AddrPort
	a2, err = netip.ParseAddrPort(s)
	if err != nil {
		if strings.Contains(err.Error(), "no IP") {
			s = "[::]" + s
			var err2 error
			a2, err2 = netip.ParseAddrPort(s)
			if err2 != nil {
				return err
			}
		} else {
			return err
		}
	}
	*a = Address(a2)
	return nil
}

func (a Address) MarshalJSON() ([]byte, error) {
	a2 := (netip.AddrPort)(a)
	return json.Marshal(a2.String())
}

type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	err := json.Unmarshal(b, &s)
	if err != nil {
		return err
	}
	if s == "" {
		return nil
	}
	d.Duration, err = time.ParseDuration(s)
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Duration.String())
}
