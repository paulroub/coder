package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/gohugoio/hugo/parser/pageparser"
	"golang.org/x/xerrors"

	"github.com/coder/coder/v2/codersdk"
)

const (
	examplesDir = "examples"
	examplesSrc = "examples.go"
)

func main() {
	lint := flag.Bool("lint", false, "Lint **all** the examples instead of generating the examples.gen.json file")
	flag.Parse()

	if err := run(*lint); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %+v\n", err)
		os.Exit(1)
	}
}

//nolint:revive // This is a script, not a library.
func run(lint bool) error {
	fset := token.NewFileSet()
	src, err := parser.ParseFile(fset, filepath.Join(examplesDir, examplesSrc), nil, parser.ParseComments)
	if err != nil {
		return err
	}

	projectFS := os.DirFS(".")
	examplesFS := os.DirFS(examplesDir)

	var paths []string
	if lint {
		files, err := fs.ReadDir(examplesFS, "templates")
		if err != nil {
			return err
		}

		for _, f := range files {
			if !f.IsDir() {
				continue
			}
			paths = append(paths, filepath.Join("templates", f.Name()))
		}
	} else {
		for _, comment := range src.Comments {
			for _, line := range comment.List {
				if s, ok := parseEmbedTag(line.Text); ok && !strings.HasSuffix(s, ".json") {
					paths = append(paths, s)
				}
			}
		}
	}

	var examples []codersdk.TemplateExample
	var errs []error
	for _, name := range paths {
		te, err := parseTemplateExample(projectFS, examplesFS, name)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if te != nil {
			examples = append(examples, *te)
		}
	}

	if len(errs) > 0 {
		return xerrors.Errorf("parse failed: %w", errors.Join(errs...))
	}

	var w io.Writer = os.Stdout
	if lint {
		w = io.Discard
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	return enc.Encode(examples)
}

func parseTemplateExample(projectFS, examplesFS fs.FS, name string) (te *codersdk.TemplateExample, err error) {
	var errs []error
	defer func() {
		if err != nil {
			errs = append([]error{err}, errs...)
		}
		if len(errs) > 0 {
			err = xerrors.Errorf("example %q has errors", name)
			for _, e := range errs {
				err = errors.Join(err, e)
			}
		}
	}()

	dir, err := fs.Stat(examplesFS, name)
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() {
		//nolint:nilnil // This is a script, not a library.
		return nil, nil
	}

	exampleID := dir.Name()
	// Each one of these is a example!
	readme, err := fs.ReadFile(examplesFS, path.Join(name, "README.md"))
	if err != nil {
		return nil, xerrors.New("missing README.md")
	}

	frontMatter, err := pageparser.ParseFrontMatterAndContent(bytes.NewReader(readme))
	if err != nil {
		return nil, xerrors.Errorf("parse front matter: %w", err)
	}

	// Make sure validation here is in sync with requirements for
	// coder/registry.
	displayName, err := getString(frontMatter.FrontMatter, "display_name")
	if err != nil {
		errs = append(errs, err)
	}

	description, err := getString(frontMatter.FrontMatter, "description")
	if err != nil {
		errs = append(errs, err)
	}

	_, err = getString(frontMatter.FrontMatter, "maintainer_github")
	if err != nil {
		errs = append(errs, err)
	}

	tags := []string{}
	tagsRaw, exists := frontMatter.FrontMatter["tags"]
	if exists {
		tagsI, valid := tagsRaw.([]interface{})
		if !valid {
			errs = append(errs, xerrors.Errorf("tags isn't a slice: type %T", tagsRaw))
		} else {
			for _, tagI := range tagsI {
				tag, valid := tagI.(string)
				if !valid {
					errs = append(errs, xerrors.Errorf("tag isn't a string: type %T", tagI))
					continue
				}
				tags = append(tags, tag)
			}
		}
	}

	var icon string
	icon, err = getString(frontMatter.FrontMatter, "icon")
	if err != nil {
		errs = append(errs, err)
	} else {
		cleanPath := filepath.Clean(filepath.Join(examplesDir, name, icon))
		_, err := fs.Stat(projectFS, cleanPath)
		if err != nil {
			errs = append(errs, xerrors.Errorf("icon does not exist: %w", err))
		}
		if !strings.HasPrefix(cleanPath, filepath.Join("site", "static")) {
			errs = append(errs, xerrors.Errorf("icon is not in site/static/: %q", icon))
		}
		icon, err = filepath.Rel(filepath.Join("site", "static"), cleanPath)
		if err != nil {
			errs = append(errs, xerrors.Errorf("cannot make icon relative to site/static: %w", err))
		}
	}

	if len(errs) > 0 {
		return nil, xerrors.New("front matter validation failed")
	}

	return &codersdk.TemplateExample{
		ID:          exampleID,
		Name:        displayName,
		Description: description,
		Icon:        "/" + icon, // The FE needs a static path!
		Tags:        tags,
		Markdown:    string(frontMatter.Content),

		// URL is set by examples/examples.go.
	}, nil
}

func getString(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", xerrors.Errorf("front matter does not contain %q", key)
	}
	vv, ok := v.(string)
	if !ok {
		return "", xerrors.Errorf("%q isn't a string", key)
	}
	return vv, nil
}

func parseEmbedTag(s string) (string, bool) {
	if !strings.HasPrefix(s, "//go:embed") {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(s, "//go:embed")), true
}
