package webui

import (
	"embed"
	"html/template"
)

//go:embed error.html
//go:embed logout.html
//go:embed userinfo.html
var templates embed.FS

var tmls = map[string]*template.Template{}

//go:embed icon.png
var Icon embed.FS

func init() {
	errorTml, err := template.ParseFS(templates, "error.html")
	if err != nil {
		panic(err)
	}
	tmls["error"] = errorTml

	logoutTml, err := template.ParseFS(templates, "logout.html")
	if err != nil {
		panic(err)
	}
	tmls["logout"] = logoutTml

	userinfoTml, err := template.ParseFS(templates, "userinfo.html")
	if err != nil {
		panic(err)
	}
	tmls["userinfo"] = userinfoTml
}

func GetTemplate(name string) *template.Template {
	return tmls[name]
}
