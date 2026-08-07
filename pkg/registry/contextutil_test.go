package registry

import "testing"

func TestExtractStringList(t *testing.T) {
	if got := ExtractStringList(map[string]interface{}{}, "allowed"); got != nil {
		t.Errorf("expected nil for missing key, got %v", got)
	}
	if got := ExtractStringList(map[string]interface{}{"allowed": []string{"a", "b"}}, "allowed"); len(got) != 2 {
		t.Errorf("expected []string passthrough, got %v", got)
	}
	if got := ExtractStringList(map[string]interface{}{"allowed": []interface{}{"a", "b"}}, "allowed"); len(got) != 2 {
		t.Errorf("expected []interface{} to convert to []string, got %v", got)
	}
	if got := ExtractStringList(map[string]interface{}{"allowed": []interface{}{"a", 1, "b"}}, "allowed"); len(got) != 2 {
		t.Errorf("expected non-string elements to be dropped, got %v", got)
	}
}
