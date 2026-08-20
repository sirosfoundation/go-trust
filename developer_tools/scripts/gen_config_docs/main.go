// Package main generates docs/CONFIGURATION.md from the Go-Trust config structs.
//
// Unlike vc/go-wallet-backend, go-trust's config has no `envconfig`-style
// struct tags — environment variable overrides are hand-written in
// pkg/config/config.go's applyEnvOverrides(), and only cover a subset of
// fields (Server/Logging/Security; Registries/Policies have no env
// override support at all). So this tool parses applyEnvOverrides itself
// to build the real GT_* mapping, instead of mechanically constructing an
// env var name for every field — fabricating one for a field that isn't
// actually overridable would be documenting something false.
//
// It parses config struct files using go/ast and extracts YAML keys,
// types, and comments (both doc comments and inline comments) to produce
// a Markdown configuration reference.
//
// Usage:
//
//	go run developer_tools/scripts/gen_config_docs/main.go [-root /path/to/project] [-out docs/CONFIGURATION.md]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// FieldDoc represents one documented config field.
type FieldDoc struct {
	YAMLPath    string
	EnvVar      string // "" if this field has no real environment variable override
	GoType      string
	Description string
}

// SectionDoc represents a top-level config section (one rendered table).
type SectionDoc struct {
	Title       string
	Description string
	Fields      []FieldDoc
}

// StructInfo holds parsed struct metadata.
type StructInfo struct {
	Name   string
	Doc    string
	Fields []FieldInfo
}

// FieldInfo holds parsed field metadata.
type FieldInfo struct {
	GoName    string
	GoType    string
	YAMLTag   string
	Doc       string
	InlineDoc string
	TypeName  string // resolved struct type name, if this field references another struct
}

// Registry of all parsed struct types, keyed by simple type name (single package in scope).
type Registry struct {
	types map[string]*StructInfo
	fset  *token.FileSet
}

func NewRegistry() *Registry {
	return &Registry{types: make(map[string]*StructInfo), fset: token.NewFileSet()}
}

func (r *Registry) ParseDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", dir, err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := parser.ParseFile(r.fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", path, err)
		}
		r.extractStructs(file)
	}
	return nil
}

func (r *Registry) extractStructs(file *ast.File) {
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				continue
			}
			info := &StructInfo{Name: ts.Name.Name, Doc: cleanDoc(gd.Doc)}
			if info.Doc == "" {
				info.Doc = cleanDoc(ts.Doc)
			}
			for _, field := range st.Fields.List {
				if len(field.Names) == 0 {
					continue // skip embedded
				}
				fi := FieldInfo{
					GoName:    field.Names[0].Name,
					GoType:    typeString(field.Type),
					Doc:       cleanDoc(field.Doc),
					InlineDoc: cleanInlineComment(field.Comment),
					TypeName:  resolveTypeName(field.Type),
				}
				if field.Tag != nil {
					tag := strings.Trim(field.Tag.Value, "`")
					fi.YAMLTag = strings.Split(extractTag(tag, "yaml"), ",")[0]
				}
				if fi.YAMLTag == "-" || !ast.IsExported(fi.GoName) {
					continue
				}
				info.Fields = append(info.Fields, fi)
			}
			r.types[info.Name] = info
		}
	}
}

// resolveTypeName returns the referenced struct type name for fields that
// point at another struct (directly or via a pointer), so the caller can
// decide whether to recurse. Slices/maps are deliberately not unwrapped
// here (see flattenStruct) — go-trust has no nested slice-of-struct field
// that needs per-element expansion in the generated doc.
func resolveTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		if ast.IsExported(t.Name) {
			return t.Name
		}
	case *ast.StarExpr:
		return resolveTypeName(t.X)
	}
	return ""
}

func typeString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		if x, ok := t.X.(*ast.Ident); ok {
			return x.Name + "." + t.Sel.Name
		}
		return t.Sel.Name
	case *ast.StarExpr:
		return "*" + typeString(t.X)
	case *ast.ArrayType:
		return "[]" + typeString(t.Elt)
	case *ast.MapType:
		return "map[" + typeString(t.Key) + "]" + typeString(t.Value)
	default:
		return "unknown"
	}
}

func extractTag(tag, key string) string {
	search := key + `:"`
	idx := strings.Index(tag, search)
	if idx < 0 {
		return ""
	}
	rest := tag[idx+len(search):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

func cleanDoc(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var lines []string
	for _, c := range cg.List {
		text := strings.TrimPrefix(c.Text, "//")
		text = strings.TrimPrefix(text, " ")
		lines = append(lines, text)
	}
	return strings.TrimSpace(strings.Join(lines, " "))
}

func cleanInlineComment(cg *ast.CommentGroup) string {
	if cg == nil {
		return ""
	}
	var parts []string
	for _, c := range cg.List {
		text := strings.TrimSpace(strings.TrimPrefix(c.Text, "//"))
		if text != "" {
			parts = append(parts, text)
		}
	}
	return strings.Join(parts, " ")
}

func (r *Registry) Lookup(name string) *StructInfo {
	if name == "" {
		return nil
	}
	return r.types[name]
}

// extractEnvMappings parses pkg/config/config.go's applyEnvOverrides function
// and returns a map from Go field path (e.g. "Server.TLS.Enabled", dot-joined,
// no leading "cfg.") to the real GT_* environment variable that overrides it.
// Fields absent from this map have no environment variable override at all —
// the caller must not invent one.
func extractEnvMappings(fset *token.FileSet, path string) (map[string]string, error) {
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	mapping := make(map[string]string)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "applyEnvOverrides" || fn.Body == nil {
			continue
		}
		for _, stmt := range fn.Body.List {
			ifStmt, ok := stmt.(*ast.IfStmt)
			if !ok || ifStmt.Init == nil {
				continue
			}
			envVar, ok := getenvArg(ifStmt.Init)
			if !ok {
				continue
			}
			if path := firstCfgAssignPath(ifStmt.Body); path != "" {
				mapping[path] = envVar
			}
		}
	}
	return mapping, nil
}

// getenvArg matches `v := os.Getenv("GT_X")` and returns "GT_X".
func getenvArg(init ast.Stmt) (string, bool) {
	assign, ok := init.(*ast.AssignStmt)
	if !ok || len(assign.Rhs) != 1 {
		return "", false
	}
	call, ok := assign.Rhs[0].(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	xIdent, ok := sel.X.(*ast.Ident)
	if !ok || xIdent.Name != "os" || sel.Sel.Name != "Getenv" {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(lit.Value, `"`), true
}

// firstCfgAssignPath finds the first `cfg.X.Y = ...` assignment anywhere in
// block (including inside nested ifs, for the ParseDuration/Atoi-guarded
// cases) and returns "X.Y".
func firstCfgAssignPath(block *ast.BlockStmt) string {
	var path string
	ast.Inspect(block, func(n ast.Node) bool {
		if path != "" {
			return false
		}
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) == 0 {
			return true
		}
		if p := cfgSelectorPath(assign.Lhs[0]); p != "" {
			path = p
			return false
		}
		return true
	})
	return path
}

// cfgSelectorPath turns `cfg.Server.TLS.Enabled` into "Server.TLS.Enabled",
// or "" if expr isn't a selector chain rooted at the identifier "cfg".
func cfgSelectorPath(expr ast.Expr) string {
	var parts []string
	cur := expr
	for {
		sel, ok := cur.(*ast.SelectorExpr)
		if !ok {
			break
		}
		parts = append([]string{sel.Sel.Name}, parts...)
		cur = sel.X
	}
	if id, ok := cur.(*ast.Ident); ok && id.Name == "cfg" && len(parts) > 0 {
		return strings.Join(parts, ".")
	}
	return ""
}

// buildSections expands each direct field of the named root struct into its
// own section (or, for scalar root fields, a single "general" section).
func buildSections(reg *Registry, rootName string, envMap map[string]string) []SectionDoc {
	root := reg.Lookup(rootName)
	if root == nil {
		log.Fatalf("root struct %q not found in parsed types", rootName)
	}

	var sections []SectionDoc
	var rootFields []FieldDoc

	for _, field := range root.Fields {
		yamlKey := field.YAMLTag
		if yamlKey == "" {
			yamlKey = strings.ToLower(field.GoName)
		}
		if sub := reg.Lookup(field.TypeName); sub != nil {
			sections = append(sections, SectionDoc{
				Title:       yamlKey,
				Description: fieldDescription(field),
				Fields:      flattenStruct(reg, sub, yamlKey, field.GoName, envMap, 0),
			})
		} else {
			rootFields = append(rootFields, FieldDoc{
				YAMLPath:    yamlKey,
				EnvVar:      envMap[field.GoName],
				GoType:      friendlyType(field.GoType),
				Description: fieldDescription(field),
			})
		}
	}

	if len(rootFields) > 0 {
		sections = append([]SectionDoc{{Title: "general", Fields: rootFields}}, sections...)
	}
	return sections
}

func flattenStruct(reg *Registry, info *StructInfo, yamlPrefix, goPrefix string, envMap map[string]string, depth int) []FieldDoc {
	if depth > 5 {
		return nil // guard against cycles
	}
	var docs []FieldDoc
	for _, f := range info.Fields {
		yamlKey := f.YAMLTag
		if yamlKey == "" {
			yamlKey = strings.ToLower(f.GoName)
		}
		fullYAML := yamlPrefix + "." + yamlKey
		fullGo := goPrefix + "." + f.GoName

		if sub := reg.Lookup(f.TypeName); sub != nil {
			docs = append(docs, flattenStruct(reg, sub, fullYAML, fullGo, envMap, depth+1)...)
		} else {
			docs = append(docs, FieldDoc{
				YAMLPath:    fullYAML,
				EnvVar:      envMap[fullGo],
				GoType:      friendlyType(f.GoType),
				Description: fieldDescription(f),
			})
		}
	}
	return docs
}

func fieldDescription(f FieldInfo) string {
	if f.Doc != "" {
		return f.Doc
	}
	return f.InlineDoc
}

func friendlyType(goType string) string {
	switch goType {
	case "time.Duration":
		return "duration"
	case "int", "int64":
		return "integer"
	case "bool":
		return "boolean"
	case "string":
		return "string"
	case "[]string":
		return "string list"
	default:
		if strings.HasPrefix(goType, "map[") {
			return goType + " (object)"
		}
		if strings.HasPrefix(goType, "[]") {
			return goType[2:] + " list"
		}
		if strings.HasPrefix(goType, "*") {
			return friendlyType(goType[1:])
		}
		return goType
	}
}

func renderMarkdown(sections []SectionDoc) string {
	var b strings.Builder
	b.WriteString("<!-- Regenerate with: go run developer_tools/scripts/gen_config_docs/main.go -->\n\n")
	b.WriteString("# Configuration Reference\n\n")
	b.WriteString("This document describes all configuration options for go-trust (`gt`).\n")
	b.WriteString("Configuration is loaded from a YAML file, then a handful of settings can be overridden by `GT_*` environment variables — most fields (all registries and policies) are YAML-only.\n\n")
	b.WriteString("A few `server` settings can also be set via CLI flag (`gt -host`, `-port`, `-external-url`, `-log-level`, `-log-format`) — see `gt -h`.\n\n")
	b.WriteString("## Table of Contents\n\n")

	for _, sec := range sections {
		if sec.Title == "general" {
			continue
		}
		anchor := strings.ToLower(sec.Title)
		anchor = strings.ReplaceAll(anchor, ".", "")
		anchor = strings.ReplaceAll(anchor, " ", "-")
		fmt.Fprintf(&b, "- [%s](#%s)\n", sec.Title, anchor)
	}
	b.WriteString("\n---\n\n")

	for _, sec := range sections {
		if sec.Title == "general" {
			b.WriteString("## General\n\n")
		} else {
			b.WriteString("## " + sec.Title + "\n\n")
		}
		if sec.Description != "" {
			b.WriteString(sec.Description + "\n\n")
		}
		if len(sec.Fields) > 0 {
			b.WriteString("| YAML Key | Env Variable | Type | Description |\n")
			b.WriteString("|----------|-------------|------|-------------|\n")
			for _, f := range sec.Fields {
				desc := strings.ReplaceAll(f.Description, "|", "\\|")
				desc = strings.ReplaceAll(desc, "\n", " ")
				envVar := f.EnvVar
				if envVar == "" {
					envVar = "—"
				} else {
					envVar = "`" + envVar + "`"
				}
				fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.YAMLPath, envVar, f.GoType, desc)
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

func main() {
	rootFlag := flag.String("root", "", "workspace root (auto-detected from cwd if empty)")
	outFlag := flag.String("out", "docs/CONFIGURATION.md", "output path relative to root")
	flag.Parse()

	root := *rootFlag
	if root == "" {
		wd, err := os.Getwd()
		if err != nil {
			log.Fatalf("cannot get working directory: %v", err)
		}
		root = wd
	}

	reg := NewRegistry()
	pkgDir := filepath.Join(root, "pkg/config")
	if err := reg.ParseDir(pkgDir); err != nil {
		log.Fatalf("error parsing %s: %v", pkgDir, err)
	}

	envMap, err := extractEnvMappings(reg.fset, filepath.Join(pkgDir, "config.go"))
	if err != nil {
		log.Fatalf("error parsing env overrides: %v", err)
	}

	rootSections := buildSections(reg, "Config", envMap)

	// "registries" is one struct field on Config but really 11 independent
	// registry types — expand it as its own set of sections (one per
	// registry) instead of one giant merged table.
	var sections []SectionDoc
	for _, s := range rootSections {
		if s.Title == "registries" {
			continue
		}
		sections = append(sections, s)
	}
	registrySections := buildSections(reg, "RegistriesConfig", envMap)
	for i := range registrySections {
		registrySections[i].Title = "registries." + registrySections[i].Title
	}
	sections = append(sections, registrySections...)

	markdown := renderMarkdown(sections)

	outPath := filepath.Join(root, *outFlag)
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		log.Fatalf("creating output dir: %v", err)
	}
	if err := os.WriteFile(outPath, []byte(markdown), 0o644); err != nil {
		log.Fatalf("writing %s: %v", outPath, err)
	}

	totalFields := 0
	for _, sec := range sections {
		totalFields += len(sec.Fields)
	}
	fmt.Printf("Generated %s (%d sections, %d fields, %d env overrides found)\n", outPath, len(sections), totalFields, len(envMap))
}
