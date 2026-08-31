// Package migrations embeds the owned Controller migration SQL files so the
// store can apply them hermetically. The canonical SQL lives in this
// directory as 0001_core.sql and 0002_control.sql (plan 06 owns both),
// 0003_enrollment.sql (plan 08 owns it), 0004_probe.sql through
// 0006_r13_hardening.sql (plan 10 owns them), and 0007_traversal.sql
// (plan 12 owns it); the installer may still read them as plain files.
// 0008_lifecycle.sql is owned by plan 14.
package migrations

import "embed"

//go:embed 0001_core.sql 0002_control.sql 0003_enrollment.sql 0004_probe.sql 0005_probe_hardening.sql 0006_r13_hardening.sql 0007_traversal.sql 0008_lifecycle.sql
var FS embed.FS

// Names is the ordered migration list; the index (1-based) is the schema
// version recorded in schema_migrations.
var Names = []string{"0001_core.sql", "0002_control.sql", "0003_enrollment.sql", "0004_probe.sql", "0005_probe_hardening.sql", "0006_r13_hardening.sql", "0007_traversal.sql", "0008_lifecycle.sql"}