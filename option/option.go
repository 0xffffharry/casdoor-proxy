package option

import (
	"fmt"
	"time"
)

type Option struct {
	LogOption    LogOption     `json:"log"`
	ProxyOptions []ProxyOption `json:"proxies"`
}

type ProxyOption struct {
	Tag             string        `json:"tag"`
	Listen          *Address      `json:"listen"`
	IssueURL        *URL          `json:"issue_url"`
	Upstream        *URL          `json:"upstream"`
	ClientID        string        `json:"client_id"`
	ClientSecret    string        `json:"client_secret"`
	ApplicationName string        `json:"application_name"`
	JWTPublicKey    *JWTPublicKey `json:"jwt_public_key"`
	RedirectURL     *URL          `json:"redirect_url"`
	CookieName      string        `json:"cookie_name"`
	CookieExpire    Duration      `json:"cookie_expire"`
	CookieDomain    string        `json:"cookie_domain"`
	CookieSecret    string        `json:"cookie_secret"`
	//
	RedisOption *RedisOption `json:"redis"`
}

type RedisOption struct {
	Address  *Address `json:"address"`
	Password string   `json:"password"`
	DB       uint     `json:"db"`
}

type LogOption struct {
	Debug       bool   `json:"debug"`
	Output      string `json:"output"`
	DisableTime bool   `json:"disable_time"`
}

func CheckOption(option *Option) error {
	if option.ProxyOptions == nil || len(option.ProxyOptions) == 0 {
		return fmt.Errorf("proxy no found")
	}

	tagMap := make(map[string]bool)
	for i, proxyOption := range option.ProxyOptions {
		if proxyOption.Tag == "" {
			return fmt.Errorf("proxy tag is empty")
		}
		if tagMap[proxyOption.Tag] {
			return fmt.Errorf("proxy tag `%s` is duplicate", proxyOption.Tag)
		} else {
			tagMap[proxyOption.Tag] = true
		}

		if proxyOption.IssueURL == nil {
			return fmt.Errorf("proxy `%s` issue_url is empty", proxyOption.Tag)
		}
		if proxyOption.Upstream == nil {
			return fmt.Errorf("proxy `%s` upstream is empty", proxyOption.Tag)
		}
		if proxyOption.ClientID == "" {
			return fmt.Errorf("proxy `%s` client_id is empty", proxyOption.Tag)
		}
		if proxyOption.ClientSecret == "" {
			return fmt.Errorf("proxy `%s` client_secret is empty", proxyOption.Tag)
		}
		if proxyOption.ApplicationName == "" {
			return fmt.Errorf("proxy `%s` application_name is empty", proxyOption.Tag)
		}
		if proxyOption.RedirectURL == nil {
			return fmt.Errorf("proxy `%s` redirect_url is empty", proxyOption.Tag)
		}
		if proxyOption.CookieName == "" {
			option.ProxyOptions[i].CookieName = "casdoor-proxy-" + proxyOption.Tag
		}
		if proxyOption.CookieExpire.Duration == 0 {
			option.ProxyOptions[i].CookieExpire.Duration = 7 * 24 * time.Hour
		}
		if proxyOption.CookieDomain == "" {
			return fmt.Errorf("proxy `%s` cookie_domain is empty", proxyOption.Tag)
		}
		if proxyOption.CookieSecret == "" {
			return fmt.Errorf("proxy `%s` cookie_secret is empty", proxyOption.Tag)
		}
		if proxyOption.RedisOption != nil {
			if proxyOption.RedisOption.Address == nil {
				return fmt.Errorf("proxy `%s` redis address is empty", proxyOption.Tag)
			}
		}
	}

	return nil
}
