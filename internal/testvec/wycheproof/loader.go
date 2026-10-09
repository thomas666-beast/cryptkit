// Package wycheproof loads and runs Google Project Wycheproof test vectors.
package wycheproof

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type TestFile struct {
	Algorithm string     `json:"algorithm"`
	TestGroups []Group   `json:"testGroups"`
}

type Group struct {
	Type       string      `json:"type"`
	KeySize    int         `json:"keySize"`
	IVSize     int         `json:"ivSize"`
	TagSize    int         `json:"tagSize"`
	Tests      []Test      `json:"tests"`
}

type Test struct {
	TCID      int      `json:"tcId"`
	Comment   string   `json:"comment"`
	Key       string   `json:"key"`
	IV        string   `json:"iv"`
	AAD       string   `json:"aad"`
	Msg       string   `json:"msg"`
	Ct        string   `json:"ct"`
	Tag       string   `json:"tag"`
	Result    string   `json:"result"` // "valid", "invalid", "acceptable"
	Flags     []string `json:"flags"`
}

func Load(path string) (*TestFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tf TestFile
	if err := json.Unmarshal(raw, &tf); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &tf, nil
}

func Hex(s string) ([]byte, error) { return hex.DecodeString(s) }
