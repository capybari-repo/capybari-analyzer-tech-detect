package techdetect_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	fingerprint "github.com/capybari/capybari-analyzer-fingerprint"
	techdetect "github.com/capybari/capybari-analyzer-tech-detect"
	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/analyzertest"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-schemas"
	"gopkg.in/yaml.v3"
)

const fixtures = "../capybari-fixtures"

func TestCapabilityMetadata(t *testing.T) {
	b, err := os.ReadFile("capability.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := analyzer.ParseCapability(b); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if err := schemas.ValidateValue("capability.schema.json", doc); err != nil {
		t.Fatal(err)
	}
}

func TestFixtures(t *testing.T) {
	a := &techdetect.Analyzer{Today: func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) }}
	for _, name := range []string{"node-express-legacy", "python-flask-app", "go-service"} {
		t.Run(name, func(t *testing.T) {
			r := analyzertest.Run(t, a, analyzertest.Repo(t, filepath.Join(fixtures, name)), analyzertest.Options{Deps: []analyzer.Analyzer{fingerprint.New()}})
			tech := analyzertest.Fact[facts.Technologies](t, r, facts.KeyTechnologies)
			type row struct{ Name, Category, Version, EOL string }
			var rows []row
			for _, it := range tech.Items {
				rows = append(rows, row{it.Name, it.Category, it.Version, it.EOL})
			}
			var eol []string
			for _, f := range r.Findings {
				if f.Source.Capability != "tech-detect" {
					continue
				}
				eol = append(eol, string(f.Severity)+" "+string(f.Confidence)+" "+f.Title)
			}
			analyzertest.Golden(t, name, map[string]any{"technologies": rows, "findings": eol})
		})
	}
}
