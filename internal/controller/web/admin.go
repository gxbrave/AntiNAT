// Admin shell (P17 Story 3). Four-tab operator console: Home Settings,
// Forwards, Nodes, Global Settings. The page is server-rendered chrome + i18n
// blob; the tabs are driven by admin.js over the frozen API. When no session
// is present the same route renders the login form (Story 2 uses this for the
// private-site redirect target).
package web

import (
	"encoding/json"
	"html/template"
	"net/http"
)

// adminView is the admin shell render model.
type adminView struct {
	Lang        string
	I18NJSON    template.JS
	AppName     string
	Title       string
	LoggedIn    bool
	Username    string
	TabHome     string
	TabForwards string
	TabNodes    string
	TabGlobal   string
	LoginTitle  string
	LoginUser   string
	LoginPass   string
	LoginSubmit string
	Welcome     string
	Logout      string
}

func (h *uiHandlers) handleAdmin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}
	settings, err := h.readHomeSettings()
	if err != nil {
		settings = homeSettings{Language: "zh"}
	}
	lang := normalizeLang(settings.Language)
	user, loggedIn := h.currentUser(r)

	var username string
	if loggedIn {
		username = user.Username
	}
	t := h.i18n.makeT(lang)
	view := adminView{
		Lang:        lang,
		I18NJSON:    h.i18nJSON(lang),
		AppName:     t("app.name"),
		Title:       t("admin.title"),
		LoggedIn:    loggedIn,
		Username:    username,
		TabHome:     t("admin.tab.home"),
		TabForwards: t("admin.tab.forwards"),
		TabNodes:    t("admin.tab.nodes"),
		TabGlobal:   t("admin.tab.global"),
		LoginTitle:  t("admin.login.title"),
		LoginUser:   t("admin.login.username"),
		LoginPass:   t("admin.login.password"),
		LoginSubmit: t("admin.login.submit"),
		Welcome:     t("admin.welcome"),
		Logout:      t("admin.logout"),
	}
	h.renderTemplate(w, "admin.html", lang, view)
}

// adminSettingsJSON is a helper used by Story 3 to expose the settings record
// to the shell. Kept here so the admin page has a single settings source.
func (h *uiHandlers) adminSettingsJSON(r *http.Request) (template.JS, error) {
	rec, err := h.store.GetSettingsRecord()
	if err != nil {
		return template.JS("{}"), err
	}
	if rec.JSON == "" {
		return template.JS("{}"), nil
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(rec.JSON), &obj); err != nil {
		return template.JS("{}"), err
	}
	obj["etag"] = etagString(rec.Revision)
	raw, err := json.Marshal(obj)
	if err != nil {
		return template.JS("{}"), err
	}
	return template.JS(raw), nil
}

func etagString(rev uint64) string {
	return `"rev-` + itoa(rev) + `"`
}

func itoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}
