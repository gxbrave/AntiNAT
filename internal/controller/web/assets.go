// UI asset accessors (P17 Story 2). The controller web package embeds the
// P17-owned assets under web/{templates,static,i18n} through the small webui
// package at the module root (go:embed cannot cross parent directories); this
// file is the typed access layer the router and page handlers consume.
package web

import (
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	webui "github.com/gxbrave/AntiNAT/web"
)

// templateRoot returns the embedded Go template subtree.
func templateRoot() (fs.FS, error) {
	return fs.Sub(webui.FS, "templates")
}

// staticRoot returns the embedded static asset subtree.
func staticRoot() (fs.FS, error) {
	return fs.Sub(webui.FS, "static")
}

// i18nRoot returns the embedded bilingual string subtree.
func i18nRoot() (fs.FS, error) {
	return fs.Sub(webui.FS, "i18n")
}

// staticFileServer serves the embedded /static subtree. The caller strips the
// /static/ prefix before this handler.
func staticFileServer() (http.Handler, error) {
	root, err := staticRoot()
	if err != nil {
		return nil, fmt.Errorf("web: static assets: %w", err)
	}
	return http.FileServer(http.FS(root)), nil
}

// parseTemplates parses every template file in the embedded templates dir and
// attaches the shared helper func map (asset URL + i18n key lookup).
func parseTemplates() (*template.Template, *I18N, error) {
	i18n, err := newI18N()
	if err != nil {
		return nil, nil, err
	}
	root, err := templateRoot()
	if err != nil {
		return nil, nil, err
	}
	// t(key) resolves the current language; by default the template funcs are
	// bound per request via template.Funcs in the page handlers.
	tmpl, err := template.New("antinat").Funcs(template.FuncMap{
		"t": func(key string) string { return key },
	}).ParseFS(root, "*.html")
	if err != nil {
		return nil, nil, fmt.Errorf("web: parse templates: %w", err)
	}
	return tmpl, i18n, nil
}
