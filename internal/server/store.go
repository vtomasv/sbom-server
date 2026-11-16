package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

var errConflict = errors.New("report_id already has a different payload for this client")

type key struct {
	client string
	report string
}

type manifest struct {
	Summary summary `json:"summary"`
	Digest  string  `json:"sha256"`
}

type store struct {
	root    string
	mu      sync.RWMutex
	reports map[key]manifest
}

func openStore(dataDir string) (*store, error) {
	root := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	db := &store{root: root, reports: make(map[key]manifest)}
	tenants, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, tenant := range tenants {
		client, decodeErr := hex.DecodeString(tenant.Name())
		if !tenant.IsDir() || decodeErr != nil || !slugPattern.Match(client) || tenant.Name() != hex.EncodeToString(client) {
			return nil, fmt.Errorf("unexpected path in storage: %s", tenant.Name())
		}
		if err := db.loadClient(string(client)); err != nil {
			return nil, err
		}
	}
	return db, nil
}

func (db *store) loadClient(client string) error {
	entries, err := os.ReadDir(db.clientDir(client))
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		if !entry.IsDir() || !uuidPattern.MatchString(entry.Name()) {
			return fmt.Errorf("unexpected path in client %s: %s", client, entry.Name())
		}
		id := key{client: client, report: entry.Name()}
		path := filepath.Join(db.reportDir(id), "manifest.json")
		contents, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var record manifest
		if err := json.Unmarshal(contents, &record); err != nil {
			return fmt.Errorf("read manifest %s: %w", path, err)
		}
		digest, err := hex.DecodeString(record.Digest)
		if record.Summary.ClientID != client || record.Summary.ReportID != id.report || err != nil || len(digest) != sha256.Size {
			return fmt.Errorf("invalid manifest %s", path)
		}
		file, err := os.Lstat(filepath.Join(db.reportDir(id), "sbom.json"))
		if err != nil {
			return err
		}
		if !file.Mode().IsRegular() {
			return fmt.Errorf("invalid SBOM file for %s", path)
		}
		db.reports[id] = record
	}
	return nil
}

func (db *store) clientDir(client string) string {
	// Hex keeps identifiers distinct on case-insensitive filesystems as well.
	return filepath.Join(db.root, hex.EncodeToString([]byte(client)))
}

func (db *store) reportDir(id key) string {
	return filepath.Join(db.clientDir(id.client), id.report)
}

func (db *store) save(info summary, sbom []byte, hash [sha256.Size]byte) (summary, bool, error) {
	id := key{client: info.ClientID, report: info.ReportID}
	digest := hex.EncodeToString(hash[:])
	db.mu.Lock()
	defer db.mu.Unlock()

	parent := db.clientDir(id.client)
	if existing, found := db.reports[id]; found {
		if existing.Digest != digest {
			return summary{}, false, errConflict
		}
		return existing.Summary, false, syncDirectory(parent)
	}
	if err := os.MkdirAll(parent, 0700); err != nil {
		return summary{}, false, err
	}
	if err := syncDirectory(db.root); err != nil {
		return summary{}, false, err
	}
	pending, err := os.MkdirTemp(parent, ".pending-")
	if err != nil {
		return summary{}, false, err
	}
	defer os.RemoveAll(pending)
	record := manifest{Summary: info, Digest: digest}
	encoded, err := json.Marshal(record)
	if err != nil {
		return summary{}, false, err
	}
	if err := writeSynced(filepath.Join(pending, "manifest.json"), encoded); err != nil {
		return summary{}, false, err
	}
	if err := writeSynced(filepath.Join(pending, "sbom.json"), sbom); err != nil {
		return summary{}, false, err
	}
	if err := syncDirectory(pending); err != nil {
		return summary{}, false, err
	}
	if err := os.Rename(pending, db.reportDir(id)); err != nil {
		return summary{}, false, err
	}
	db.reports[id] = record
	return info, true, syncDirectory(parent)
}

func writeSynced(name string, payload []byte) error {
	file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(payload); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func (db *store) summaries(who principal) []summary {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]summary, 0)
	for id, record := range db.reports {
		if who.admin || who.client == id.client {
			result = append(result, record.Summary)
		}
	}
	return result
}

func (db *store) lookup(who principal, report, client string) (summary, string, bool, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if !who.admin {
		if client != "" && client != who.client {
			return summary{}, "", false, false
		}
		client = who.client
	}
	if client != "" {
		id := key{client: client, report: report}
		entry, found := db.reports[id]
		return entry.Summary, filepath.Join(db.reportDir(id), "sbom.json"), found, false
	}
	var result summary
	var file string
	for id, entry := range db.reports {
		if id.report != report {
			continue
		}
		if file != "" {
			return summary{}, "", false, true
		}
		result = entry.Summary
		file = filepath.Join(db.reportDir(id), "sbom.json")
	}
	return result, file, file != "", false
}
