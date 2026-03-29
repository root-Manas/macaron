package cfg

import "testing"

func TestSaveLoadAPIKeys(t *testing.T) {
	d := t.TempDir()
	c := &Config{APIKeys: map[string]string{"securitytrails": "abc123"}}
	if err := Save(d, c); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(d)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.APIKeys["securitytrails"] != "abc123" {
		t.Fatalf("unexpected loaded value: %#v", loaded.APIKeys)
	}
}
