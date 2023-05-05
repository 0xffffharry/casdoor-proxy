package proxy

import (
	"casdoor-proxy/option"
	"casdoor-proxy/pkg"
	"casdoor-proxy/pkg/log"
	"casdoor-proxy/webui"
	"context"
	"encoding/gob"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-contrib/sessions/redis"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	golog "log"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
	gob.Register([]*matcher{})
}

func NewProxy(ctx context.Context, logger log.TagLoggerInterface, option option.ProxyOption) *Proxy {
	if logger == nil {
		logger = log.NewLogger(nil, nil).NewTagLogger(option.Tag)
	}
	return &Proxy{
		ctx:    ctx,
		logger: logger,
		option: option,
	}
}

func (p *Proxy) Run() error {
	p.logger.Infof("proxy `%s `start", p.option.Tag)
	defer p.logger.Infof("proxy `%s `stop", p.option.Tag)

	p.logger.Debugf("request issue url: %s", p.option.IssueURL.String())
	reqIssueCtx, reqIssueCancel := context.WithTimeout(p.ctx, 1*time.Minute)
	oidcProvider, err := oidc.NewProvider(reqIssueCtx, p.option.IssueURL.String())
	reqIssueCancel()
	if err != nil {
		p.logger.Fatalf("create oidc provider error: %s", err.Error())
		return err
	}
	p.oauth2Config = &oauth2.Config{
		ClientID:     p.option.ClientID,
		ClientSecret: p.option.ClientSecret,
		RedirectURL:  p.option.RedirectURL.String(),
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint:     oidcProvider.Endpoint(),
	}
	p.logger.Info("oidc init success")

	p.logger.Debug("init cookie store")
	if p.option.RedisOption != nil {
		p.logger.Info("use redis for cookie store")
		p.cookieStore, err = redis.NewStoreWithDB(64, "tcp", (*netip.AddrPort)(p.option.RedisOption.Address).String(), p.option.RedisOption.Password, strconv.Itoa(int(p.option.RedisOption.DB)), []byte(p.option.CookieSecret))
		if err != nil {
			p.logger.Fatalf("create redis store error: %s", err.Error())
			return err
		}
	} else {
		p.logger.Info("use memory for cookie store")
		p.cookieStore = cookie.NewStore([]byte(p.option.CookieSecret))
	}
	p.cookieStore.Options(sessions.Options{
		Path:   "/",
		Domain: p.option.CookieDomain,
		MaxAge: int(p.option.CookieExpire.Seconds()),
	})
	p.logger.Info("cookie store init success")

	p.logger.Debug("init gin engine")
	engine := gin.New()
	err = p.initHandler(engine)
	if err != nil {
		p.logger.Fatalf("init gin handler error: %s", err.Error())
		return err
	}
	p.logger.Info("gin engine init success")

	server := &http.Server{
		Addr:    (*netip.AddrPort)(p.option.Listen).String(),
		Handler: engine,
	}
	p.logger.Infof("listen on %s", server.Addr)
	go func() {
		<-p.ctx.Done()
		p.logger.Debug("try to shutdown http server")
		server.Shutdown(context.Background())
	}()
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		p.logger.Errorf("server listen error: %s", err.Error())
		return err
	}
	p.logger.Info("http server shutdown")
	return nil
}

func copyURL(src *url.URL) *url.URL {
	dst := &url.URL{
		Scheme:      src.Scheme,
		Opaque:      src.Opaque,
		User:        src.User,
		Host:        src.Host,
		Path:        src.Path,
		RawPath:     src.RawPath,
		OmitHost:    src.OmitHost,
		ForceQuery:  src.ForceQuery,
		RawQuery:    src.RawQuery,
		Fragment:    src.Fragment,
		RawFragment: src.RawFragment,
	}
	return dst
}

func joinURLPath(a, b *url.URL) (path, rawpath string) {
	if a.RawPath == "" && b.RawPath == "" {
		return singleJoiningSlash(a.Path, b.Path), ""
	}
	// Same as singleJoiningSlash, but uses EscapedPath to determine
	// whether a slash should be added
	apath := a.EscapedPath()
	bpath := b.EscapedPath()

	aslash := strings.HasSuffix(apath, "/")
	bslash := strings.HasPrefix(bpath, "/")

	switch {
	case aslash && bslash:
		return a.Path + b.Path[1:], apath + bpath[1:]
	case !aslash && !bslash:
		return a.Path + "/" + b.Path, apath + "/" + bpath
	}
	return a.Path + b.Path, apath + bpath
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func (p *Proxy) initHandler(engine *gin.Engine) error {
	ginLogger := p.logger.NewTagLogger("Gin")
	engine.Use(func(ginCtx *gin.Context) {
		defer func() {
			err := recover()
			if err != nil {
				var buf [4096]byte
				runtime.Stack(buf[:], false)
				ginLogger.Errorf("panic: %s, stack: %s", err, string(buf[:]))
				p.errorInternalServerError(ginCtx.Writer, fmt.Sprintf("%s", err))
			}
		}()
		ginCtx.Next()
	})
	engine.Use(gin.LoggerWithConfig(gin.LoggerConfig{
		Output: log.NewGinLogWriter(ginLogger, log.DebugLevel),
		Formatter: func(params gin.LogFormatterParams) string {
			if params.ErrorMessage != "" {
				return fmt.Sprintf("%s [%s] [%d] %s %s, errmsg: %s", params.ClientIP, params.Method, params.StatusCode, params.Latency, params.Path, params.ErrorMessage)
			} else {
				return fmt.Sprintf("%s [%s] [%d] %s %s", params.ClientIP, params.Method, params.StatusCode, params.Latency, params.Path)
			}
		},
	}))
	engine.Use(sessions.Sessions(fmt.Sprintf("%s-%s", "session", p.option.Tag), p.cookieStore))

	group := engine.Group("/oauth2")
	group.GET("/login", p.login)
	group.GET("/logout", p.logout)
	group.GET("/userinfo", p.userinfo)
	group.GET("/callback", p.callback)
	group.GET("/icon.png", func(c *gin.Context) {
		c.FileFromFS("icon.png", http.FS(webui.Icon))
	})
	engine.NoRoute(p.reverseProxy)

	u := (*url.URL)(p.option.Upstream)
	reverseProxy := httputil.NewSingleHostReverseProxy(u)
	reverseProxy.Director = func(req *http.Request) {
		req.URL.Scheme = u.Scheme
		req.URL.Host = u.Host
		req.Host = u.Host
		req.URL.Path, req.URL.RawPath = joinURLPath(u, req.URL)
		targetQuery := u.RawQuery
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
	}
	reverseProxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		p.logger.Errorf("reverse proxy error: %s", err.Error())
		p.errorBadGateway(w, err.Error())
	}
	reverseProxy.ErrorLog = golog.New(log.NewSimpleWriter(p.logger, log.ErrorLevel), "reverse proxy error: ", 0)
	p.rp = reverseProxy

	return nil
}

func (p *Proxy) login(ginCtx *gin.Context) {
	session := sessions.Default(ginCtx)
	session.Delete("state")
	session.Delete("matchers")
	session.Delete("user")
	state := pkg.Random(64)
	session.Set("state", state)
	err := session.Save()
	if err != nil {
		p.logger.Errorf("save session error: %s", err.Error())
		p.errorInternalServerError(ginCtx.Writer, "save session error")
		return
	}
	ginCtx.Redirect(http.StatusFound, p.oauth2Config.AuthCodeURL(state))
}

func (p *Proxy) logout(ginCtx *gin.Context) {
	session := sessions.Default(ginCtx)
	var user string
	userAny := session.Get("user")
	if userAny != nil {
		user = userAny.(string)
		p.logger.Infof("logout user: `%s`, ip: %s", strings.Split(user, "/")[2], ginCtx.ClientIP())
	} else {
		user = "unknown"
	}
	session.Delete("state")
	session.Delete("matchers")
	session.Delete("user")
	err := session.Save()
	if err != nil {
		p.logger.Errorf("save session error: %s", err.Error())
		p.errorInternalServerError(ginCtx.Writer, "save session error")
		return
	}

	p.logoutPage(ginCtx.Writer, user)
}

func (p *Proxy) callback(ginCtx *gin.Context) {
	queryCode := ginCtx.Query("code")
	queryState := ginCtx.Query("state")
	if queryCode == "" || queryState == "" {
		ginCtx.AbortWithStatus(http.StatusBadRequest)
		return
	}

	session := sessions.Default(ginCtx)

	sessionStateAny := session.Get("state")
	if sessionStateAny == nil {
		session.Delete("state")
		session.Delete("matchers")
		session.Delete("user")
		err := session.Save()
		if err != nil {
			p.logger.Errorf("save session error: %s", err.Error())
			p.errorInternalServerError(ginCtx.Writer, "save session error")
			return
		}
		p.logger.Errorf("session state not found")
		p.errorBadRequest(ginCtx.Writer, "session state not found")
		return
	}
	sessionState := sessionStateAny.(string)
	if sessionState != queryState {
		session.Delete("state")
		session.Delete("matchers")
		session.Delete("user")
		err := session.Save()
		if err != nil {
			p.logger.Errorf("save session error: %s", err.Error())
			p.errorInternalServerError(ginCtx.Writer, "save session error")
			return
		}
		p.logger.Errorf("session state not match")
		p.errorBadRequest(ginCtx.Writer, "session state not match")
		return
	}
	session.Delete("state")
	session.Delete("matchers")
	session.Delete("user")

	exchangeCtx, exchangeCancel := context.WithTimeout(p.ctx, 1*time.Minute)
	oauth2Token, err := p.oauth2Config.Exchange(exchangeCtx, queryCode)
	exchangeCancel()
	if err != nil {
		p.logger.Errorf("exchange token error: %s", err.Error())
		p.errorServiceUnavailable(ginCtx.Writer, "exchange token error")
		return
	}

	var claims jwtClaims
	token, err := jwt.ParseWithClaims(oauth2Token.AccessToken, &claims, func(token *jwt.Token) (interface{}, error) {
		if p.option.JWTPublicKey != nil {
			return p.option.JWTPublicKey.PublicKey, nil
		}
		return nil, nil
	})
	if err != nil {
		if p.option.JWTPublicKey != nil {
			p.logger.Errorf("parse jwt token error: %s", err.Error())
			p.errorServiceUnavailable(ginCtx.Writer, "parse jwt token error")
			return
		} else if !strings.Contains(err.Error(), jwt.ErrInvalidKeyType.Error()) {
			p.logger.Errorf("parse jwt token error: %s", err.Error())
			p.errorServiceUnavailable(ginCtx.Writer, "parse jwt token error")
			return
		}
	}
	if p.option.JWTPublicKey != nil && !token.Valid {
		p.logger.Error("jwt token invalid")
		p.errorServiceUnavailable(ginCtx.Writer, "jwt token invalid")
		return
	}

	if claims.PMs == nil || len(claims.PMs) == 0 {
		p.logger.Error("permissions is empty")
		p.errorServiceUnavailable(ginCtx.Writer, "permissions is empty")
		return
	}

	matchers := make([]*matcher, 0)

	for _, pm := range claims.PMs {
		if !pm.Enabled {
			continue
		}
		if pm.ResourceType != "Application" {
			continue
		}
		if pm.Resources == nil || len(pm.Resources) == 0 {
			continue
		}
		if pm.Actions == nil || len(pm.Actions) == 0 {
			continue
		}
		m := false
		for _, r := range pm.Resources {
			if r == p.option.ApplicationName {
				m = true
				break
			}
		}
		if !m {
			continue
		}
		allow := pm.Effect == "Allow"
		//
		for _, a := range pm.Actions {
			m, err := parseToMatcher(a, allow)
			if err == nil {
				matchers = append(matchers, m)
			}
		}
	}

	if len(matchers) == 0 {
		p.logger.Error("permissions is empty")
		p.errorServiceUnavailable(ginCtx.Writer, "permissions is empty")
		return
	}

	user := fmt.Sprintf("%s/%s/%s", claims.Owner, claims.Name, claims.DisplayName)
	session.Set("matchers", matchers)
	session.Set("user", user)
	err = session.Save()
	if err != nil {
		p.logger.Errorf("save session error: %s", err.Error())
		p.errorInternalServerError(ginCtx.Writer, "save session error")
		return
	}

	p.logger.Infof("user `%s` login success, ip: %s", claims.DisplayName, ginCtx.ClientIP())

	ginCtx.Redirect(http.StatusFound, "/")
}

func (p *Proxy) userinfo(ginCtx *gin.Context) {
	session := sessions.Default(ginCtx)
	userAny := session.Get("user")
	if userAny == nil {
		ginCtx.Writer.WriteHeader(http.StatusOK)
		tml := webui.GetTemplate("userinfo")
		err := tml.Execute(ginCtx.Writer, map[string]interface{}{
			"Organization": "",
			"Name":         "",
			"DisplayName":  "",
		})
		if err != nil {
			p.logger.Errorf("execute template error: %s", err.Error())
			return
		}
		return
	}
	user := userAny.(string)
	users := strings.Split(user, "/")

	ginCtx.Writer.WriteHeader(http.StatusOK)
	tml := webui.GetTemplate("userinfo")
	err := tml.Execute(ginCtx.Writer, map[string]interface{}{
		"Organization": users[0],
		"Name":         users[1],
		"DisplayName":  users[2],
	})
	if err != nil {
		p.logger.Errorf("execute template error: %s", err.Error())
		return
	}
}

func (p *Proxy) auth(ginCtx *gin.Context) bool { // true: allow, false: deny
	session := sessions.Default(ginCtx)
	matchersAny := session.Get("matchers")
	if matchersAny == nil {
		session.Delete("matchers")
		session.Delete("state")
		session.Delete("user")
		err := session.Save()
		if err != nil {
			p.logger.Errorf("save session error: %s", err.Error())
			p.errorInternalServerError(ginCtx.Writer, "save session error")
			return false
		}
		ginCtx.Redirect(http.StatusFound, "/oauth2/login")
		return false
	}
	matchers := matchersAny.([]*matcher)
	if !matchRule(ginCtx, &matchers) {
		p.errorForbidden(ginCtx.Writer, "")
		return false
	}

	return true
}

func (p *Proxy) reverseProxy(ginCtx *gin.Context) {
	if p.auth(ginCtx) {
		p.rp.ServeHTTP(ginCtx.Writer, ginCtx.Request)
	}
}

func (p *Proxy) errorBadGateway(w http.ResponseWriter, errMsg string) {
	w.WriteHeader(http.StatusBadGateway)
	p.errorPage(w, "502 Bad Gateway", errMsg)
}

func (p *Proxy) errorInternalServerError(w http.ResponseWriter, errMsg string) {
	w.WriteHeader(http.StatusInternalServerError)
	p.errorPage(w, "500 Internal Server Error", errMsg)
}

func (p *Proxy) errorServiceUnavailable(w http.ResponseWriter, errMsg string) {
	w.WriteHeader(http.StatusServiceUnavailable)
	p.errorPage(w, "503 Service Unavailable", errMsg)
}

func (p *Proxy) errorForbidden(w http.ResponseWriter, errMsg string) {
	w.WriteHeader(http.StatusForbidden)
	p.errorPage(w, "403 Forbidden", errMsg)
}

func (p *Proxy) errorBadRequest(w http.ResponseWriter, errMsg string) {
	w.WriteHeader(http.StatusBadRequest)
	p.errorPage(w, "400 Bad Request", errMsg)
}

func (p *Proxy) errorPage(w http.ResponseWriter, errHeader string, errMessage string) {
	tml := webui.GetTemplate("error")
	err := tml.Execute(w, map[string]interface{}{
		"Error":        errHeader,
		"ErrorMessage": errMessage,
	})
	if err != nil {
		p.logger.Errorf("execute template error: %s", err.Error())
		return
	}
}

func (p *Proxy) logoutPage(w http.ResponseWriter, user string) {
	w.WriteHeader(http.StatusOK)
	tml := webui.GetTemplate("logout")
	err := tml.Execute(w, nil)
	if err != nil {
		p.logger.Errorf("execute template error: %s", err.Error())
		return
	}
}
