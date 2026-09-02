// Public home page (P17 Story 2). Server-rendered card directory of published
// services. Each card derives its durable status from real forward/node
// evidence:
//
//   - PUBLISHED_VERIFIED is the only default-clickable link
//   - PUBLISHED_UNVERIFIED keeps showing risk continuously
//   - offline/stale/failed cards are grayed with a red indicator and their
//     last-known address is copyable only after explicit risk confirmation
//   - a pending forward deletion with an offline node is DELETE_PENDING_OFFLINE
//
// No status is ever color-only: every card renders an icon shape + label + an
// evidence detail line.
package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/gxbrave/AntiNAT/internal/controller/store"
	"github.com/gxbrave/AntiNAT/internal/protocol"
)

// homeSettings is the subset of the settings record the home page reads.
type homeSettings struct {
	PrivateSite        bool   `json:"private_site"`
	Language           string `json:"language"`
	ControllerEndpoint string `json:"controller_endpoint"`
}

// homeItemView is one card on the home page.
type homeItemView struct {
	ID          string
	Name        string
	Description string
	Protocol    string // tcp|udp
	ProtocolTxt string // localized label
	Status      string // verified|unverified|stale|offline|failed|delete_pending_offline|unknown
	StatusLabel string // localized durable label
	StatusShape string // css suffix: ok|warn|bad|neutral
	Clickable   bool   // PUBLISHED_VERIFIED only
	Href        string // published URL; empty when unknown
	RiskNote    string // localized risk explanation ("" when verified)
	LastAddress string // last known published address (localized prefix rendered in template)
	LastSeenRaw string // RFC3339 UTC
	LastSeenTxt string // localized display string
}

// homeCategoryView is one section of the card directory.
type homeCategoryView struct {
	ID    string
	Name  string
	Items []homeItemView
}

// homeView is the whole-home render model.
type homeView struct {
	Lang        string
	I18NJSON    template.JS
	AppName     string
	Tagline     string
	Title       string
	Admin       string
	PrivateSite bool
	Categories  []homeCategoryView
	HasItems    bool
}

// handleHome renders the public card directory.
func (h *uiHandlers) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	settings, err := h.readHomeSettings()
	if err != nil {
		// Missing settings row is a normal first boot; render defaults.
		settings = homeSettings{Language: "zh"}
		if !errors.Is(err, store.ErrNotFound) {
			renderPageError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "settings unavailable")
			return
		}
	}
	lang := normalizeLang(settings.Language)
	if settings.PrivateSite {
		if _, ok := h.currentUser(r); !ok {
			http.Redirect(w, r, "/admin", http.StatusFound)
			return
		}
	}
	categories, err := h.buildHomeCategories(lang)
	if err != nil {
		renderPageError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "home data unavailable")
		return
	}
	view := homeView{
		Lang:        lang,
		I18NJSON:    h.i18nJSON(lang),
		AppName:     h.i18n.resolve(lang, "app.name"),
		Title:       h.i18n.resolve(lang, "home.title"),
		Tagline:     h.i18n.resolve(lang, "home.tagline"),
		Admin:       h.i18n.resolve(lang, "home.admin"),
		PrivateSite: settings.PrivateSite,
		Categories:  categories,
		HasItems:    false,
	}
	for _, c := range categories {
		if len(c.Items) > 0 {
			view.HasItems = true
			break
		}
	}
	h.renderTemplate(w, "home.html", lang, view)
}

// readHomeSettings loads and decodes the settings record.
func (h *uiHandlers) readHomeSettings() (homeSettings, error) {
	rec, err := h.store.GetSettingsRecord()
	if err != nil {
		return homeSettings{}, err
	}
	var s homeSettings
	if rec.JSON == "" || rec.JSON == "{}" {
		return s, nil
	}
	if err := json.Unmarshal([]byte(rec.JSON), &s); err != nil {
		return s, fmt.Errorf("web: settings decode: %w", err)
	}
	return s, nil
}

// buildHomeCategories assembles the card directory from navigation + forwards.
func (h *uiHandlers) buildHomeCategories(lang string) ([]homeCategoryView, error) {
	categories, err := h.store.ListNavigationCategories()
	if err != nil {
		return nil, err
	}
	items, err := h.store.ListNavigationItems()
	if err != nil {
		return nil, err
	}
	byCat := map[string][]homeItemView{}
	var catOrder []string
	for _, c := range categories {
		catOrder = append(catOrder, c.ID)
		byCat[c.ID] = []homeItemView{}
	}
	for _, item := range items {
		view, ok := h.resolveHomeItem(lang, item)
		if !ok {
			continue
		}
		byCat[item.CategoryID] = append(byCat[item.CategoryID], view)
	}
	out := make([]homeCategoryView, 0, len(catOrder))
	for _, id := range catOrder {
		out = append(out, homeCategoryView{ID: id, Name: nameOf(h, categories, id), Items: byCat[id]})
	}
	return out, nil
}

func (h *uiHandlers) resolveHomeItem(lang string, item store.NavigationItem) (homeItemView, bool) {
	t := h.i18n.makeT(lang)
	fwd, err := h.store.GetForward(item.ForwardID)
	if err != nil {
		return homeItemView{}, false
	}
	node, err := h.store.GetNode(fwd.NodeID)
	if err != nil {
		return homeItemView{}, false
	}
	spec, err := h.store.LatestForwardSpec(fwd.ID)
	var publishedHost, scheme string
	if err == nil {
		if s, derr := decodeSpec(spec.SpecJSON); derr == nil {
			publishedHost = strings.TrimSpace(s.PublishedHost)
			scheme = strings.TrimSpace(s.PublishScheme)
		}
	}
	status, shape, reason := deriveHomeStatus(h.store, node, fwd)
	view := homeItemView{
		ID:          item.ID,
		Name:        item.Name,
		Description: item.Description,
		Protocol:    item.Protocol,
		ProtocolTxt: protocolTxt(t, item.Protocol),
		Status:      status,
		StatusLabel: statusLabel(t, status),
		StatusShape: shape,
		Clickable:   status == "verified",
		RiskNote:    riskNote(t, status),
		LastAddress: publishedHost,
	}
	if publishedHost != "" {
		view.Href = combinedURL(scheme, publishedHost)
	}
	if st, err := h.store.GetForwardRuntimeStatus(fwd.ID); err == nil {
		view.LastSeenRaw = formatUTC(st.UpdatedAt)
		view.LastSeenTxt = view.LastSeenRaw
	}
	if status == "offline" || status == "stale" || status == "failed" {
		view.LastSeenTxt = t("home.lastSeenAt") + " " + view.LastSeenRaw
		_ = reason
	}
	return view, true
}

// deriveHomeStatus classifies a card. Priority: delete-pending-offline >
// offline > failed > unverified > stale > verified > unknown. verified is only
// ever derived from a real PUBLISHED_VERIFIED snapshot; all other values name
// the current risk honestly.
func deriveHomeStatus(st *store.Store, node store.Node, fwd store.Forward) (status, shape, reason string) {
	pending := deletionPending(st, fwd.ID)
	if pending && node.ControlState == "OFFLINE" {
		return "delete_pending_offline", "bad", "offline node with queued deletion"
	}
	if node.ControlState == "OFFLINE" {
		return "offline", "bad", "node offline"
	}
	states, err := st.GetForwardRuntimeStatus(fwd.ID)
	if err != nil {
		if pending {
			return "unknown", "neutral", "no runtime evidence"
		}
		return "unknown", "neutral", "no runtime evidence"
	}
	var axes protocol.ActivationStates
	if err := decodeStates(states.SnapshotJSON, &axes); err != nil {
		return "unknown", "neutral", "undecodable runtime evidence"
	}
	if pending {
		return "delete_pending_offline", "bad", "deletion queued"
	}
	if axisBroken(axes) {
		return "failed", "bad", "an axis is broken"
	}
	switch axes.PublicationState {
	case "PUBLISHED_VERIFIED":
		return "verified", "ok", "open from vantage"
	case "PUBLISHED_UNVERIFIED":
		return "unverified", "warn", "not vantage-verified"
	case "STALE", "UNPUBLISHED":
		return "stale", "warn", "publication marked stale/unpublished"
	default:
		if axes.WanReachabilityState == "" {
			return "unknown", "neutral", "no WAN evidence"
		}
		return "unverified", "warn", "publication state missing"
	}
}

func deletionPending(st *store.Store, forwardID string) bool {
	op, err := st.LatestForwardDeletion(forwardID)
	if err != nil {
		return false
	}
	switch op.Status {
	case "", "PENDING", "IN_PROGRESS", "RECEIVED", "APPLYING", "INTENT_PERSISTED":
		return true
	}
	return false
}

func axisBroken(axes protocol.ActivationStates) bool {
	switch axes.ListenerState {
	case "ERROR":
		return true
	}
	switch axes.MappingState {
	case "LOST", "ERROR":
		return true
	}
	switch axes.KeepaliveState {
	case "LOST":
		return true
	}
	switch axes.WanReachabilityState {
	case "REJECTED", "TIMEOUT":
		return true
	}
	switch axes.ReturnPathState {
	case "FAILED":
		return true
	}
	switch axes.TargetHealthState {
	case "FAIL":
		return true
	}
	switch axes.DataPlaneState {
	case "ERROR":
		return true
	}
	return false
}

func decodeSpec(raw string) (protocol.ForwardSpec, error) {
	var s protocol.ForwardSpec
	if err := protocol.DecodeStrictJSONInto([]byte(raw), &s); err != nil {
		return s, err
	}
	return s, nil
}

func decodeStates(raw string, out *protocol.ActivationStates) error {
	return protocol.DecodeStrictJSONInto([]byte(raw), out)
}

// combinedURL builds scheme://host, defaulting to http.
func combinedURL(scheme, host string) string {
	s := strings.TrimSpace(scheme)
	if s != "http" && s != "https" {
		s = "http"
	}
	return s + "://" + host
}

func protocolTxt(t func(string) string, p string) string {
	switch p {
	case "tcp":
		return t("home.protocolTcp")
	case "udp":
		return t("home.protocolUdp")
	}
	return strings.ToUpper(p)
}

func statusLabel(t func(string) string, status string) string {
	switch status {
	case "verified":
		return t("home.verified")
	case "unverified":
		return t("home.unverified")
	case "stale":
		return t("home.stale")
	case "offline":
		return t("home.offline")
	case "failed":
		return t("state.failed")
	case "delete_pending_offline":
		return t("home.deletePendingOffline")
	}
	return t("home.unknown")
}

func riskNote(t func(string) string, status string) string {
	switch status {
	case "unverified":
		return t("home.unverifiedRisk")
	case "stale":
		return t("home.staleRisk")
	case "offline":
		return t("home.offlineRisk")
	case "failed":
		return t("state.failed")
	case "delete_pending_offline":
		return t("home.offlineRisk")
	}
	return ""
}

func nameOf(h *uiHandlers, categories []store.NavigationCategory, id string) string {
	for _, c := range categories {
		if c.ID == id {
			return c.Name
		}
	}
	return id
}

// formatUTC renders a unix timestamp as a UTC display string.
func formatUTC(unix int64) string {
	if unix <= 0 {
		return ""
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05")
}

func (h *uiHandlers) i18nJSON(lang string) template.JS {
	m := h.i18n.zh
	if lang == "en" {
		m = h.i18n.en
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return template.JS("{}")
	}
	return template.JS(raw)
}

// renderTemplate executes named with the per-language helper funcs.
func (h *uiHandlers) renderTemplate(w http.ResponseWriter, name, lang string, data any) {
	clone, err := h.tmpl.Clone()
	if err != nil {
		renderPageError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "template unavailable")
		return
	}
	clone = clone.Funcs(template.FuncMap{"t": h.i18n.makeT(lang)})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := clone.ExecuteTemplate(w, name, data); err != nil {
		// Header may already be written; log-free minimal fallback.
		_ = err
	}
}

// renderPageError writes a plain JSON error envelope for failed page fetches.
func renderPageError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "message": message})
}
