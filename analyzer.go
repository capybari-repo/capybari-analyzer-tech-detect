// Package techdetect implements the Technology & Version Detector: which
// languages, runtimes, frameworks, libraries, databases and services a
// repository is built from, at which versions, and which of them are past
// end-of-life.
package techdetect

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/capybari/capybari-core/analyzer"
	"github.com/capybari/capybari-core/facts"
	"github.com/capybari/capybari-core/finding"
	"github.com/capybari/capybari-core/fsutil"
)

//go:embed capability.yaml
var capabilityYAML []byte

//go:embed rules/technologies.yaml
var technologiesYAML []byte

//go:embed rules/eol.yaml
var eolYAML []byte

var capability = analyzer.MustParseCapability(capabilityYAML)

// Signature describes how to recognise one technology.
type Signature struct {
	Name     string `yaml:"name"`
	Category string `yaml:"category"`
	Website  string `yaml:"website"`
	Match    struct {
		NPM       []string `yaml:"npm"`
		PyPI      []string `yaml:"pypi"`
		Go        []string `yaml:"go"`
		Maven     []string `yaml:"maven"`
		NuGet     []string `yaml:"nuget"`
		Packagist []string `yaml:"packagist"`
		RubyGems  []string `yaml:"rubygems"`
		Cargo     []string `yaml:"cargo"`
		Files     []string `yaml:"files"`
		Images    []string `yaml:"images"`
	} `yaml:"match"`
}

// EOLTable is the bundled end-of-life data.
type EOLTable struct {
	AsOf     string                `yaml:"as_of"`
	Products map[string]EOLProduct `yaml:"products"`
}

// EOLProduct is the lifecycle of one product.
type EOLProduct struct {
	Source string            `yaml:"source"`
	Kind   string            `yaml:"kind"`
	Note   string            `yaml:"note"`
	Cycles map[string]string `yaml:"cycles"`
}

var (
	signatures = mustYAML[[]Signature](technologiesYAML)
	eolTable   = mustYAML[EOLTable](eolYAML)
)

func mustYAML[T any](b []byte) T {
	var v T
	if err := yaml.Unmarshal(b, &v); err != nil {
		panic(err)
	}
	return v
}

// Analyzer implements the capability.
type Analyzer struct {
	// Today is used for EOL comparisons; nil means the scan clock.
	Today func() time.Time
}

// New returns the capability.
func New() *Analyzer { return &Analyzer{} }

// Capability implements analyzer.Analyzer.
func (*Analyzer) Capability() analyzer.Capability { return capability }

// pkg is a dependency observation: ecosystem, name, version and where.
type pkg struct {
	eco, name, version, where string
}

// Analyze implements analyzer.Analyzer.
func (a *Analyzer) Analyze(ctx context.Context, in *analyzer.Input) (*analyzer.Result, error) {
	var inv facts.Inventory
	if _, err := in.Evidence.Get(facts.KeyInventory, &inv); err != nil {
		return nil, err
	}
	var fp facts.Fingerprint
	hasFP, _ := in.Evidence.Get(facts.KeyFingerprint, &fp)
	var deps facts.Dependencies
	hasDeps, _ := in.Evidence.Get(facts.KeyDependencies, &deps)

	root := in.Target.Root
	var pkgs []pkg
	if hasDeps && len(deps.Packages) > 0 {
		for _, p := range deps.Packages {
			where := ""
			if len(p.Locations) > 0 {
				where = p.Locations[0]
			}
			pkgs = append(pkgs, pkg{eco: normEco(p.Ecosystem), name: strings.ToLower(p.Name), version: p.Version, where: where})
		}
	}
	// Direct manifest parsing: covers standalone use and manifests that
	// have no lockfile, and gives declared (not only resolved) versions.
	pkgs = append(pkgs, parseManifests(root, &inv)...)
	images := containerImages(root, &inv)

	det := newDetector()
	for _, sig := range signatures {
		for _, p := range pkgs {
			if matchPkg(sig, p) {
				det.add(sig, p.version, p.where)
			}
		}
		for _, img := range images {
			for _, m := range sig.Match.Images {
				if img.name == m {
					det.add(sig, img.tag, img.where)
				}
			}
		}
		for _, f := range inv.Files {
			if f.Kind == facts.KindVendored || f.Kind == facts.KindGenerated {
				continue
			}
			for _, m := range sig.Match.Files {
				if (strings.HasPrefix(m, ".") && strings.HasSuffix(f.Path, m)) || f.Path == m || strings.HasSuffix(f.Path, "/"+m) {
					det.add(sig, "", f.Path)
				}
			}
		}
	}
	// WordPress version from wp-includes/version.php.
	if b, _, err := fsutil.ReadFile(root, "wp-includes/version.php", 64<<10); err == nil {
		if m := regexp.MustCompile(`\$wp_version\s*=\s*'([^']+)'`).FindSubmatch(b); m != nil {
			det.setVersion("WordPress", string(m[1]))
		}
	}
	// Languages with a meaningful share, and runtimes from the fingerprint.
	for _, l := range inv.Languages {
		if l.Share >= 0.05 || l.Lines >= 500 {
			det.addRaw(facts.Technology{Name: l.Language, Category: "language", Confidence: "high", Evidence: []string{fmt.Sprintf("%d files, %d lines", l.Files, l.Lines)}})
		}
	}
	if hasFP {
		for _, r := range fp.Runtimes {
			ev := r.Source
			if ev == "" {
				ev = "primary language"
			}
			det.addRaw(facts.Technology{Name: r.Name, Category: "runtime", Version: r.Version, Confidence: "high", Evidence: []string{ev}})
		}
	}

	today := in.Now()
	if a.Today != nil {
		today = a.Today()
	}
	items := det.items()
	var findings []finding.Finding
	for i := range items {
		if f := eolFinding(&items[i], today); f != nil {
			findings = append(findings, *f)
		}
	}
	if slices.ContainsFunc(items, func(t facts.Technology) bool { return t.Name == "Moment.js" }) {
		findings = append(findings, finding.Finding{
			Dimension: finding.DimEvolution, Category: "deprecated-library", Severity: finding.Low, Confidence: finding.ConfidenceHigh,
			Title:       "Moment.js is in maintenance mode",
			Description: "The Moment.js maintainers consider it a legacy project and recommend Luxon, date-fns, Day.js or the Temporal API for new work.",
			Component:   "moment",
			Rule:        &finding.Rule{ID: "deprecated-moment", References: []string{"https://momentjs.com/docs/#/-project-status/"}},
			Remediation: &finding.Remediation{Summary: "Plan a gradual migration to a maintained date library.", Automatable: false},
		})
	}

	names := make([]string, 0, len(items))
	for _, t := range items {
		if t.Category != "language" {
			names = append(names, t.Name)
		}
	}
	summary := fmt.Sprintf("%d technologies detected", len(items))
	if len(names) > 0 {
		summary += ": " + strings.Join(names[:min(len(names), 8)], ", ")
		if len(names) > 8 {
			summary += ", …"
		}
	}
	res := &analyzer.Result{
		Evidence: map[string]any{facts.KeyTechnologies: &facts.Technologies{Items: items}},
		Findings: findings,
		Summary:  summary,
		Limitations: []string{
			fmt.Sprintf("End-of-life data is bundled (as of %s) so detection works offline; newer releases or policy changes after that date are not reflected.", eolTable.AsOf),
		},
	}
	return res, nil
}

func normEco(e string) string {
	switch strings.ToLower(e) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "go":
		return "go"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "packagist":
		return "packagist"
	case "rubygems":
		return "rubygems"
	case "crates.io":
		return "cargo"
	}
	return strings.ToLower(e)
}

func matchPkg(sig Signature, p pkg) bool {
	var list []string
	switch p.eco {
	case "npm":
		list = sig.Match.NPM
	case "pypi":
		list = sig.Match.PyPI
	case "go":
		list = sig.Match.Go
	case "maven":
		list = sig.Match.Maven
	case "nuget":
		list = sig.Match.NuGet
	case "packagist":
		list = sig.Match.Packagist
	case "rubygems":
		list = sig.Match.RubyGems
	case "cargo":
		list = sig.Match.Cargo
	}
	name := p.name
	if p.eco == "maven" {
		// Maven coordinates may be group:artifact; match on the artifact.
		if i := strings.LastIndex(name, ":"); i >= 0 {
			name = name[i+1:]
		}
	}
	for _, m := range list {
		if strings.EqualFold(m, name) {
			return true
		}
		if p.eco == "pypi" && strings.EqualFold(strings.ReplaceAll(m, "_", "-"), strings.ReplaceAll(name, "_", "-")) {
			return true
		}
	}
	return false
}

// detector merges observations per technology.
type detector struct {
	byName map[string]*facts.Technology
}

func newDetector() *detector { return &detector{byName: map[string]*facts.Technology{}} }

func (d *detector) add(sig Signature, version, where string) {
	t := d.byName[sig.Name]
	if t == nil {
		t = &facts.Technology{Name: sig.Name, Category: sig.Category, Website: sig.Website, Confidence: "high"}
		d.byName[sig.Name] = t
	}
	if v := cleanVersion(version); v != "" && (t.Version == "" || isRangeish(t.Version)) {
		t.Version = v
	}
	if where != "" && !slices.Contains(t.Evidence, where) && len(t.Evidence) < 5 {
		t.Evidence = append(t.Evidence, where)
	}
}

func (d *detector) addRaw(t facts.Technology) {
	if old, ok := d.byName[t.Name]; ok {
		if old.Version == "" {
			old.Version = t.Version
		}
		return
	}
	cp := t
	d.byName[t.Name] = &cp
}

func (d *detector) setVersion(name, v string) {
	if t, ok := d.byName[name]; ok {
		t.Version = v
	}
}

var categoryOrder = []string{"language", "runtime", "web-framework", "ui-framework", "mobile-framework", "desktop-framework", "cms", "database", "orm", "queue", "search", "api", "cloud-sdk", "backend-service", "payments", "ai", "monitoring", "server", "infrastructure", "build", "testing", "quality", "ui", "templating", "library"}

func (d *detector) items() []facts.Technology {
	out := make([]facts.Technology, 0, len(d.byName))
	for _, t := range d.byName {
		out = append(out, *t)
	}
	rank := func(c string) int {
		if i := slices.Index(categoryOrder, c); i >= 0 {
			return i
		}
		return len(categoryOrder)
	}
	sort.Slice(out, func(i, j int) bool {
		if rank(out[i].Category) != rank(out[j].Category) {
			return rank(out[i].Category) < rank(out[j].Category)
		}
		return out[i].Name < out[j].Name
	})
	return out
}

var leadingVersion = regexp.MustCompile(`\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.]+)?`)

// cleanVersion turns "^4.17.1", "==2.0.1", "v1.7.0" or ">=12" into a
// version string. Ranges keep their operator so they are not mistaken for
// exact pins.
func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || v == "*" || v == "latest" {
		return ""
	}
	if strings.HasPrefix(v, "==") || strings.HasPrefix(v, "=") && !strings.HasPrefix(v, "=>") {
		v = strings.TrimLeft(v, "=")
	}
	v = strings.TrimPrefix(v, "v")
	if isRangeish(v) {
		return v
	}
	return leadingVersion.FindString(v)
}

func isRangeish(v string) bool { return strings.ContainsAny(v, "^~<>*| ,") }

// cycleKey returns the release-cycle key for a product and version.
func cycleKey(product, version string) (key string, exact bool) {
	v := strings.TrimSpace(version)
	if v == "" {
		return "", false
	}
	exact = !isRangeish(v)
	if product == ".NET" {
		return strings.ToLower(strings.SplitN(v, ";", 2)[0]), exact
	}
	nums := regexp.MustCompile(`\d+`).FindAllString(v, 3)
	if len(nums) == 0 {
		return "", false
	}
	p := eolTable.Products[product]
	// Try major.minor first (Python 3.7, Go 1.19, Django 4.2), then major.
	if len(nums) >= 2 {
		if _, ok := p.Cycles[nums[0]+"."+nums[1]]; ok {
			return nums[0] + "." + nums[1], exact
		}
	}
	return nums[0], exact
}

func eolFinding(t *facts.Technology, today time.Time) *finding.Finding {
	p, ok := eolTable.Products[t.Name]
	if !ok {
		return nil
	}
	key, exact := cycleKey(t.Name, t.Version)
	if key == "" {
		return nil
	}
	date, ok := p.Cycles[key]
	if !ok {
		return nil
	}
	var when string
	switch {
	case date == "unsupported":
		when = "no longer supported by its maintainers"
	default:
		d, err := time.Parse("2006-01-02", date)
		if err != nil || !today.After(d) {
			return nil
		}
		when = "reached end-of-life on " + date
	}
	t.EOL = date
	sev := finding.Medium
	if p.Kind == "runtime" {
		sev = finding.High
	}
	if p.Kind == "library" {
		sev = finding.Low
	}
	conf := finding.ConfidenceHigh
	if !exact {
		conf = finding.ConfidenceMedium
	}
	desc := fmt.Sprintf("%s %s (release line %s) %s. It no longer receives security fixes, so known vulnerabilities in it stay unpatched.", t.Name, t.Version, key, when)
	if p.Note != "" {
		desc += " " + p.Note
	}
	var ev []finding.Evidence
	for _, e := range t.Evidence {
		if strings.Contains(e, "/") || strings.Contains(e, ".") {
			ev = append(ev, finding.Evidence{Location: finding.Location{Path: e}, Detail: "declares " + t.Name + " " + t.Version})
		}
	}
	return &finding.Finding{
		Dimension: finding.DimEvolution, Category: "end-of-life", Severity: sev, Confidence: conf,
		Title:                 fmt.Sprintf("%s %s is end-of-life", t.Name, key),
		Description:           desc,
		Evidence:              ev,
		Component:             t.Name,
		Rule:                  &finding.Rule{ID: "eol-" + strings.ToLower(strings.ReplaceAll(t.Name, " ", "-")), References: []string{p.Source}},
		Impact:                &finding.Impact{Technical: "Unpatched vulnerabilities and increasing incompatibility with current libraries and platforms.", Business: "Security and compliance exposure that grows over time, and upgrades that get larger the longer they are postponed."},
		Remediation:           &finding.Remediation{Summary: fmt.Sprintf("Upgrade %s to a supported release line (see %s) and test the application against it.", t.Name, p.Source), Automatable: false},
		FalsePositiveGuidance: "If the declared version is only a minimum (e.g. >=12) and production runs a newer release, update the declaration to match.",
	}
}

// parseManifests extracts direct dependencies with declared versions.
func parseManifests(root string, inv *facts.Inventory) []pkg {
	var out []pkg
	for _, f := range inv.Files {
		if f.Kind == facts.KindVendored || f.Kind == facts.KindGenerated {
			continue
		}
		base := strings.ToLower(path.Base(f.Path))
		read := func() []byte {
			b, _, err := fsutil.ReadFile(root, f.Path, 1<<20)
			if err != nil {
				return nil
			}
			return b
		}
		switch {
		case base == "package.json":
			var pj struct {
				Dependencies    map[string]string `json:"dependencies"`
				DevDependencies map[string]string `json:"devDependencies"`
			}
			if json.Unmarshal(read(), &pj) == nil {
				for n, v := range pj.Dependencies {
					out = append(out, pkg{"npm", strings.ToLower(n), v, f.Path})
				}
				for n, v := range pj.DevDependencies {
					out = append(out, pkg{"npm", strings.ToLower(n), v, f.Path})
				}
			}
		case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			re := regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<)?\s*([0-9][^\s;#,]*)?`)
			sc := bufio.NewScanner(bytes.NewReader(read()))
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
					continue
				}
				if m := re.FindStringSubmatch(line); m != nil {
					v := m[3]
					if m[2] != "" && m[2] != "==" {
						v = m[2] + v
					}
					out = append(out, pkg{"pypi", strings.ToLower(m[1]), v, f.Path})
				}
			}
		case base == "go.mod":
			sc := bufio.NewScanner(bytes.NewReader(read()))
			in := false
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				switch {
				case line == "require (":
					in = true
				case line == ")":
					in = false
				case in || strings.HasPrefix(line, "require "):
					fields := strings.Fields(strings.TrimPrefix(line, "require "))
					if len(fields) >= 2 {
						out = append(out, pkg{"go", strings.ToLower(fields[0]), fields[1], f.Path})
					}
				}
			}
		case base == "composer.json":
			var cj struct {
				Require map[string]string `json:"require"`
			}
			if json.Unmarshal(read(), &cj) == nil {
				for n, v := range cj.Require {
					out = append(out, pkg{"packagist", strings.ToLower(n), v, f.Path})
				}
			}
		case base == "gemfile":
			re := regexp.MustCompile(`^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?`)
			for _, line := range strings.Split(string(read()), "\n") {
				if m := re.FindStringSubmatch(line); m != nil {
					out = append(out, pkg{"rubygems", strings.ToLower(m[1]), m[2], f.Path})
				}
			}
		case base == "pom.xml":
			re := regexp.MustCompile(`(?s)<(?:dependency|parent)>.*?<artifactId>([^<]+)</artifactId>(?:\s*<version>([^<$]+)</version>)?`)
			for _, m := range re.FindAllStringSubmatch(string(read()), -1) {
				out = append(out, pkg{"maven", strings.ToLower(m[1]), m[2], f.Path})
			}
		case strings.HasSuffix(base, ".csproj"):
			body := string(read())
			for _, m := range regexp.MustCompile(`<PackageReference\s+Include="([^"]+)"(?:\s+Version="([^"]+)")?`).FindAllStringSubmatch(body, -1) {
				out = append(out, pkg{"nuget", strings.ToLower(m[1]), m[2], f.Path})
			}
			if strings.Contains(body, `Sdk="Microsoft.NET.Sdk.Web"`) {
				out = append(out, pkg{"nuget", "aspnetcore", "", f.Path})
			}
		case base == "cargo.toml":
			inDeps := false
			re := regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(?:"([^"]+)"|\{.*version\s*=\s*"([^"]+)")`)
			for _, line := range strings.Split(string(read()), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[") {
					inDeps = strings.HasSuffix(line, "dependencies]")
					continue
				}
				if m := re.FindStringSubmatch(line); inDeps && m != nil {
					out = append(out, pkg{"cargo", strings.ToLower(m[1]), m[2] + m[3], f.Path})
				}
			}
		}
	}
	return out
}

type image struct{ name, tag, where string }

var (
	fromLine  = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s@]+)`)
	imageLine = regexp.MustCompile(`(?m)^\s*image:\s*["']?([^\s"'#]+)`)
)

// containerImages lists base and service images from Dockerfiles and
// compose/Kubernetes files.
func containerImages(root string, inv *facts.Inventory) []image {
	var out []image
	for _, f := range inv.Files {
		if f.Kind != facts.KindContainer && f.Kind != facts.KindIaC {
			continue
		}
		b, _, err := fsutil.ReadFile(root, f.Path, 1<<20)
		if err != nil {
			continue
		}
		var refs [][]string
		refs = append(refs, fromLine.FindAllStringSubmatch(string(b), -1)...)
		refs = append(refs, imageLine.FindAllStringSubmatch(string(b), -1)...)
		for _, m := range refs {
			ref := m[1]
			name, tag := ref, ""
			if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
				name, tag = ref[:i], ref[i+1:]
			}
			name = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(name), "docker.io/"), "library/")
			out = append(out, image{name: name, tag: tag, where: f.Path})
		}
	}
	return out
}
