package rpcert

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOnlyDocGoCarriesThePackageComment guards the consolidation in doc.go.
//
// Go concatenates every file's package comment into one godoc entry, in
// filename order. This package previously had eight of them, which buried
// the real one. A file comment placed directly above the package clause -
// with no blank line between - silently rejoins that pile, and nothing about
// the source looks wrong when it happens.
func TestOnlyDocGoCarriesThePackageComment(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ParseComments)
	require.NoError(t, err)

	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if file.Doc == nil || name == "doc.go" {
				continue
			}
			t.Errorf("%s: this file's header comment is attached to the package clause, "+
				"so godoc will append it to doc.go's package documentation. "+
				"Insert a blank line between the comment and %q.\n\ngot:\n%s",
				name, "package rpcert", commentText(file.Doc))
		}
	}
}

func commentText(g *ast.CommentGroup) string {
	if g == nil {
		return ""
	}
	return g.Text()
}
