// Package webui embeds the P17-owned UI assets: Go templates under
// web/templates, static CSS/JS under web/static, and bilingual system strings
// under web/i18n. The controller web package imports this embed because the
// //go:embed directive cannot cross into parent directories; see
// internal/controller/web/assets.go for the accessors.
package webui

import "embed"

// FS is the embedded UI asset tree.
//
//go:embed templates static i18n
var FS embed.FS
