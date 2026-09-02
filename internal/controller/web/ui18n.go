// Bilingual system strings (P17 Story 2). Per v0.8 §9.4 the UI system copy is
// bilingual CN=default, EN alternate; user content is single-value and never
// translated here. Strings are JSON keyed by a stable dot key; the active
// language comes from the controller settings record (default zh).
package web

import (
	"encoding/json"
	"fmt"
	"io/fs"
)

// I18N is the loaded bilingual catalog.
type I18N struct {
	zh map[string]string
	en map[string]string
}

// newI18N loads zh.json and en.json from the embedded web/i18n subtree.
func newI18N() (*I18N, error) {
	root, err := i18nRoot()
	if err != nil {
		return nil, fmt.Errorf("web: i18n subtree: %w", err)
	}
	zh, err := loadStringMap(root, "zh.json")
	if err != nil {
		return nil, err
	}
	en, err := loadStringMap(root, "en.json")
	if err != nil {
		return nil, err
	}
	return &I18N{zh: zh, en: en}, nil
}

func loadStringMap(root fs.FS, name string) (map[string]string, error) {
	raw, err := fs.ReadFile(root, name)
	if err != nil {
		return nil, fmt.Errorf("web: read %s: %w", name, err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("web: parse %s: %w", name, err)
	}
	if m == nil {
		m = map[string]string{}
	}
	return m, nil
}

// resolve returns the translation for key in lang, falling back zh then en, then
// the key itself so a missing string is visible rather than empty.
func (i *I18N) resolve(lang, key string) string {
	if i == nil {
		return key
	}
	table := i.zh
	if lang == "en" {
		table = i.en
	}
	if v, ok := table[key]; ok {
		return v
	}
	if v, ok := i.zh[key]; ok {
		return v
	}
	if v, ok := i.en[key]; ok {
		return v
	}
	return key
}

// makeT returns a per-language t(key) lookup bound to lang.
func (i *I18N) makeT(lang string) func(string) string {
	return func(key string) string { return i.resolve(lang, key) }
}

// normalizeLang maps an empty or invalid language to the default zh.
func normalizeLang(lang string) string {
	if lang == "en" {
		return "en"
	}
	return "zh"
}
