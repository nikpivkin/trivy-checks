package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/trivy-checks/internal/bundler"
	"github.com/aquasecurity/trivy-checks/pkg/rego"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego" // register Built-in Functions from Trivy
)

func main() {
	log.SetOutput(os.Stdout)
	rego.RegisterBuiltins()

	root := flag.String("root", ".", "Root directory containing files to bundle")
	output := flag.String("out", "bundle.tar.gz", "Output archive file path")
	ir := flag.Bool("ir", false, "compile Rego into IR")
	flag.Parse()

	githubRef := os.Getenv("GITHUB_REF")
	if githubRef == "" {
		log.Println("GITHUB_REF environment variable is not provided")
	}

	log.Printf("Building bundle from root %q to %q", *root, *output)
	if err := buildBundle(*root, *output,
		bundler.WithGithubRef(githubRef),
		bundler.WithIRPlan(*ir),
	); err != nil {
		log.Fatalf("Error: %s", err.Error())
	}
	log.Printf("Bundle %q successfully created", *output)
}

func buildBundle(root, outFile string, opts ...bundler.Option) error {
	b := bundler.New(".", os.DirFS(root), opts...)

	f, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("create archive file: %w", err)
	}
	defer f.Close()

	if err := b.Build(f); err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	return nil
}
