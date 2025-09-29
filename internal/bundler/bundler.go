package bundler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path"
	"path/filepath"
	"strings"

	"github.com/open-policy-agent/eopa/pkg/iropt"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/bundle"
	"github.com/open-policy-agent/opa/v1/compile"
	"github.com/open-policy-agent/opa/v1/ir"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

type copyJob struct {
	from string
	to   string
}

// FileFilter is a function that determines whether a given file path
// should be included (returns true) or excluded (returns false) from the bundle.
type FileFilter func(path string) bool

// Bundler is responsible for preparing and archiving a bundle of files from a root directory
type Bundler struct {
	root       string
	fsys       fs.FS
	prefix     string // Prefix path inside the archive, e.g. "bundle"
	githubRef  string // GitHub ref string, e.g. "refs/tags/v1.2.3"
	irPlan     bool
	irOptimize bool
	filters    []FileFilter

	jobs     []copyJob
	files    map[string]string // map of source file paths to their relative destination paths in the bundle
	manifest []byte            // prepared manifest content with placeholders replaced
}

type Option func(*Bundler)

// WithFilters adds additional FileFilters to control which files are included.
func WithFilters(filters ...FileFilter) Option {
	return func(b *Bundler) {
		b.filters = append(b.filters, filters...)
	}
}

// WithGithubRef sets the GitHub ref string to be used for manifest substitution.
// The ref should be in the format "refs/tags/v1.2.3".
func WithGithubRef(ref string) Option {
	return func(b *Bundler) {
		b.githubRef = ref
	}
}

// WithIRPlan enables generation of an intermediate representation (IR) plan.
// When enabled, Bundler will produce an additional planning file inside the `ir/` directory
// together with other copied files.
func WithIRPlan(enable bool) Option {
	return func(b *Bundler) {
		b.irPlan = enable
	}
}

// WithIROptimization enables optimizations for the generated intermediate representation (IR).
// This option has an effect only when IR plan generation is enabled.
func WithIROptimization(enable bool) Option {
	return func(b *Bundler) {
		b.irOptimize = enable
	}
}

// New creates a new Bundler instance rooted at at the given directory and using the provided fs.FS.
func New(root string, fsys fs.FS, opts ...Option) *Bundler {
	b := &Bundler{
		root:    root,
		fsys:    fsys,
		prefix:  "",
		filters: defaultFilters(),
		jobs: []copyJob{
			{"checks/kubernetes", "policies/kubernetes/policies"},
			{"checks/cloud", "policies/cloud/policies"},
			{"checks/docker", "policies/docker/policies"},

			{"lib/kubernetes", "policies/kubernetes/lib"},
			{"lib/cloud", "policies/cloud/lib"},
			{"lib/docker", "policies/docker/lib"},
			{"lib/test", "policies/test/lib"},

			{"commands/kubernetes", "commands/kubernetes"},
			{"commands/config", "commands/config"},

			{"pkg/compliance", "specs/compliance"},
		},
	}

	for _, opt := range opts {
		opt(b)
	}
	return b
}

func defaultFilters() []FileFilter {
	return []FileFilter{
		func(path string) bool {
			// Excluding YAML only for the checks directory
			if !strings.HasPrefix(path, "checks") {
				return true
			}
			ext := filepath.Ext(path)
			return ext == ".rego"
		},
		func(path string) bool {
			ext := filepath.Ext(path)
			return ext != ".go" && ext != ".md"
		},
		func(path string) bool {
			return !strings.HasSuffix(path, "_test.rego")
		},
	}
}

// Build prepares the list of files to archive, processes the manifest, and writes
// the resulting archive as a compressed tar.gz to the provided io.Writer.
func (b *Bundler) Build(w io.Writer) error {
	if err := b.prepareFiles(); err != nil {
		return err
	}
	if err := b.prepareManifest(); err != nil {
		return err
	}
	return b.archive(w)
}

// prepareFiles scans the root directory, applies filters, and prepares the list of files to be archived
func (b *Bundler) prepareFiles() error {
	b.files = make(map[string]string)
	for _, job := range b.jobs {
		rootPath := filepath.Join(b.root, job.from)
		var jobCount int
		walkFn := func(path string, info fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			rel, err := filepath.Rel(b.root, path)
			if err != nil {
				return err
			}

			for _, f := range b.filters {
				if !f(rel) {
					return nil
				}
			}

			relToJobFrom, err := filepath.Rel(rootPath, path)
			if err != nil {
				return err
			}
			b.files[path] = filepath.ToSlash(filepath.Join(job.to, relToJobFrom))
			jobCount++
			return nil
		}

		if err := fs.WalkDir(b.fsys, rootPath, walkFn); err != nil {
			return err
		}

		log.Printf("Prepared %d files from %q to %q", jobCount, rootPath, job.to)
	}

	return nil
}

// prepareManifest reads the manifest template file, replaces the placeholder
// "[GITHUB_SHA]" with the GitHub release version extracted from b.githubRef
func (b *Bundler) prepareManifest() error {
	const (
		placeholder = "[GITHUB_SHA]"
		prefix      = "refs/tags/v"
	)

	data, err := fs.ReadFile(b.fsys, filepath.Join(b.root, "checks", ".manifest"))
	if err != nil {
		return fmt.Errorf("read .manifest: %w", err)
	}

	if b.githubRef != "" {
		releaseVersion, ok := strings.CutPrefix(b.githubRef, prefix)
		if !ok {
			log.Printf("GitHub ref %q does not start with %q — using unchanged value", b.githubRef, prefix)
		}
		log.Printf("Using GitHub ref %q -> release version %q", b.githubRef, releaseVersion)
		data = bytes.ReplaceAll(data, []byte(placeholder), []byte(releaseVersion))
	}

	b.manifest = data
	return nil
}

// archive writes all prepared files and the manifest into a compressed tar.gz archive
func (b *Bundler) archive(w io.Writer) error {
	gw := gzip.NewWriter(w)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	if err := b.writeManifest(tw); err != nil {
		return fmt.Errorf("write manifest: %w", err)
	}

	var added int
	for src, dst := range b.files {
		err := b.addFileToTar(tw, src, path.Join(b.prefix, dst))
		if err != nil {
			return fmt.Errorf("add file to tar: %w", err)
		}
		added++
	}

	log.Printf("Added %d files to archive", added)

	if b.irPlan {
		opaBundle, err := createOpaBundle(b.fsys, b.root)
		if err != nil {
			return err
		}

		for _, planned := range opaBundle.PlanModules {
			out := planned.Raw
			if b.irOptimize {
				optimized, err := optimizePlannedModule(planned.Raw)
				if err != nil {
					return err
				}
				out = optimized
			}
			dst := path.Join(b.prefix, "ir", planned.Path)
			header := tar.Header{
				Name:     dst,
				Mode:     int64(fs.ModePerm),
				Typeflag: tar.TypeReg,
				Size:     int64(len(out)),
			}

			if err := b.addDataToTar(tw, out, &header); err != nil {
				return fmt.Errorf("add file to tar: %w", err)
			}
		}

		checksMetadata := make(map[string]*ast.Annotations)

		for _, module := range opaBundle.Modules {
			annotations := metadata.PackageAnnotations(module.Parsed)
			if len(annotations) != 1 {
				continue
			}

			modulePkg := module.Parsed.Package.Path.String()
			checksMetadata[modulePkg] = annotations[0]
		}

		metadataBytes, err := json.Marshal(checksMetadata)
		if err != nil {
			return nil
		}

		dst := path.Join(b.prefix, "ir", "metadata.json")
		header := tar.Header{
			Name:     dst,
			Mode:     int64(fs.ModePerm),
			Typeflag: tar.TypeReg,
			Size:     int64(len(metadataBytes)),
		}

		if err := b.addDataToTar(tw, metadataBytes, &header); err != nil {
			return fmt.Errorf("add file to tar: %w", err)
		}

	}
	return nil
}

func optimizePlannedModule(data []byte) ([]byte, error) {
	var policy ir.Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, err
	}
	optimizationSchedule := iropt.NewIROptLevel0Schedule(
		&iropt.OptimizationPassFlags{
			LoopInvariantCodeMotion: true,
		},
		&iropt.OptimizationPassFlags{},
	)
	optimizedPolicy, err := iropt.RunPasses(&policy, optimizationSchedule)
	if err != nil {
		return nil, err
	}
	bs, err := json.Marshal(optimizedPolicy)
	if err != nil {
		return nil, err
	}
	return bs, nil
}

func (b *Bundler) writeManifest(tw *tar.Writer) error {
	hdr := &tar.Header{
		Name: b.prefix + ".manifest",
		Mode: 0o644,
		Size: int64(len(b.manifest)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("write manifest header: %w", err)
	}
	if _, err := tw.Write(b.manifest); err != nil {
		return fmt.Errorf("write manifest content: %w", err)
	}
	return nil
}

func (b *Bundler) addFileToTar(tw *tar.Writer, src, dst string) error {
	fi, err := fs.Stat(b.fsys, src)
	if err != nil {
		return err
	}

	header, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return err
	}
	header.Name = dst

	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	f, err := b.fsys.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = io.Copy(tw, f)
	return err
}

func (b *Bundler) addDataToTar(tw *tar.Writer, data []byte, header *tar.Header) error {
	if err := tw.WriteHeader(header); err != nil {
		return err
	}

	if _, err := tw.Write(data); err != nil {
		return err
	}

	return nil
}

func createOpaBundle(fsys fs.FS, root string) (*bundle.Bundle, error) {
	filter := func(abspath string, info fs.FileInfo, depth int) bool {
		if info.IsDir() {
			if abspath == "." {
				return false
			}
			return !strings.HasPrefix(abspath, "checks") && !strings.HasPrefix(abspath, "lib")
		}
		return isNotRegoFile(info)
	}

	b, err := loader.NewFileLoader().
		WithFS(fsys).
		WithFilter(filter).
		WithProcessAnnotation(true).
		AsBundle(root)
	if err != nil {
		return nil, err
	}

	b.Modules = lo.Filter(b.Modules, func(m bundle.ModuleFile, _ int) bool {
		return len(m.Parsed.Rules) != 0
	})

	compiled, err := compileBundle(b)
	if err != nil {
		return nil, err
	}
	return compiled, nil
}

func isNotRegoFile(fi fs.FileInfo) bool {
	return !fi.IsDir() && (!isRegoFile(fi.Name()) || isDotFile(fi.Name()))
}

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, ".rego") && !strings.HasSuffix(name, "_test.rego")
}

func isDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

func compileBundle(opaBundle *bundle.Bundle) (*bundle.Bundle, error) {
	entrypoints := make([]string, 0, len(opaBundle.Modules))

	for _, m := range opaBundle.Modules {
		modulePackage := m.Parsed.Package.Path.String()
		if strings.HasPrefix(modulePackage, "data.lib") {
			continue
		}

		// entrypoint is the full path to rule, constructed from package name and rule name,
		// and looks like "mypackage/mypolicy/myrule"
		entrypoint := strings.ReplaceAll(strings.TrimPrefix(modulePackage, "data."), ".", "/") + "/deny"
		entrypoints = append(entrypoints, entrypoint)
	}

	c := compile.New().
		WithBundle(opaBundle).
		WithTarget(compile.TargetPlan).
		WithEntrypoints(entrypoints...)

	if err := c.Build(context.TODO()); err != nil {
		return nil, fmt.Errorf("compile: %w", err)
	}
	bundle := c.Bundle()
	return bundle, nil
}
