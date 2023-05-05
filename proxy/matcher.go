package proxy

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/netip"
	"path/filepath"
	"strings"
)

type matcher struct {
	Mode  string `json:"mode"` // all / http_method / http_path / src_ip / src_cidr
	Rule  any    `json:"rule"`
	Allow bool   `json:"allow"`
}

func parseToMatcher(str string, allow bool) (*matcher, error) {
	strings.TrimSpace(str)
	if !strings.HasPrefix(str, "casdoor-proxy") {
		return nil, errors.New("invalid matcher")
	}
	str = strings.Replace(str, "casdoor-proxy", "", 1)
	str = strings.TrimSpace(str)
	if len(str) == 0 {
		return &matcher{
			Mode:  "all",
			Allow: allow,
		}, nil
	}
	str = strings.Replace(str, ":", "", 1)
	str = strings.TrimSpace(str)

	switch {
	case strings.HasPrefix(str, "http_method"):
		str = strings.Replace(str, "http_method", "", 1)
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			return nil, errors.New("invalid matcher")
		}
		return &matcher{
			Mode:  "http_method",
			Rule:  strings.ToUpper(str),
			Allow: allow,
		}, nil
	case strings.HasPrefix(str, "http_path"):
		str = strings.Replace(str, "http_path", "", 1)
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			return nil, errors.New("invalid matcher")
		}
		return &matcher{
			Mode:  "http_path",
			Rule:  str,
			Allow: allow,
		}, nil
	case strings.HasPrefix(str, "src_ip"):
		str = strings.Replace(str, "src_ip", "", 1)
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			return nil, errors.New("invalid matcher")
		}
		ips := strings.Split(str, ",")
		rules := make([]netip.Addr, 0)
		for _, ip := range ips {
			ip = strings.TrimSpace(ip)
			rule, err := netip.ParseAddr(ip)
			if err != nil {
				return nil, fmt.Errorf("invalid ip: %s", ip)
			}
			rules = append(rules, rule)
		}
		return &matcher{
			Mode:  "src_ip",
			Rule:  rules,
			Allow: allow,
		}, nil
	case strings.HasPrefix(str, "src_cidr"):
		str = strings.Replace(str, "src_cidr", "", 1)
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			return nil, errors.New("invalid matcher")
		}
		prefixs := strings.Split(str, ",")
		rules := make([]netip.Prefix, 0)
		for _, prefix := range prefixs {
			prefix = strings.TrimSpace(prefix)
			rule, err := netip.ParsePrefix(prefix)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr: %s", prefix)
			}
			rules = append(rules, rule)
		}
		return &matcher{
			Mode:  "src_cidr",
			Rule:  rules,
			Allow: allow,
		}, nil
	default:
		return nil, errors.New("invalid matcher")
	}
}

func (m *matcher) match(ginCtx *gin.Context) bool { // true: allow false: deny
	switch m.Mode {
	case "all":
		return m.Allow
	case "http_method":
		if strings.ToUpper(ginCtx.Request.Method) == m.Rule {
			return m.Allow
		}
	case "http_path":
		match, err := filepath.Match(m.Rule.(string), ginCtx.Request.URL.Path)
		if err == nil {
			if match {
				return m.Allow
			} else {
				return !m.Allow
			}
		}
	case "src_ip":
		clientIPStr := ginCtx.ClientIP()
		clientIP, err := netip.ParseAddr(clientIPStr)
		if err == nil {
			for _, rule := range m.Rule.([]netip.Addr) {
				if rule.Compare(clientIP) == 0 {
					return m.Allow
				}
			}
		}
	case "src_cidr":
		clientIPStr := ginCtx.ClientIP()
		clientIP, err := netip.ParseAddr(clientIPStr)
		if err == nil {
			for _, rule := range m.Rule.([]netip.Prefix) {
				if rule.Contains(clientIP) {
					return m.Allow
				}
			}
		}
	}
	return false
}

func matchRule(ginCtx *gin.Context, rules *[]*matcher) bool {
	for _, rule := range *rules {
		if rule.match(ginCtx) {
			return true
		}
	}
	return false
}
