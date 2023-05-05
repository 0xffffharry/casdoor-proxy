package proxy

import (
	"casdoor-proxy/option"
	"casdoor-proxy/pkg/log"
	"context"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"net/http/httputil"
)

type Proxy struct {
	ctx    context.Context
	logger log.TagLoggerInterface
	//
	option       option.ProxyOption
	oauth2Config *oauth2.Config
	cookieStore  cookie.Store
	rp           *httputil.ReverseProxy
}

type jwtClaims struct {
	jwt.RegisteredClaims
	Owner       string       `json:"owner"`
	Name        string       `json:"name"`
	DisplayName string       `json:"displayName"`
	PMs         []permission `json:"permissions"`
}

type permission struct {
	Name         string   `json:"name"`
	ResourceType string   `json:"resourceType"`
	Enabled      bool     `json:"isEnabled"`
	Resources    []string `json:"resources"`
	Actions      []string `json:"actions"`
	Effect       string   `json:"effect"`
}
