package server

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var (
	slugPattern = regexp.MustCompile(`^[A-Za-z0-9][-A-Za-z0-9_.]{0,63}$`)
	uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type metadata struct {
	Group      string            `json:"group,omitempty"`
	Zone       string            `json:"zone,omitempty"`
	Department string            `json:"department,omitempty"`
	Tags       map[string]string `json:"tags,omitempty"`
}

type submission struct {
	SchemaVersion int             `json:"schema_version"`
	ReportID      string          `json:"report_id"`
	MachineID     string          `json:"machine_id"`
	ClientID      string          `json:"client_id"`
	CollectedAt   time.Time       `json:"collected_at"`
	Hostname      string          `json:"hostname"`
	OS            string          `json:"os"`
	Arch          string          `json:"arch"`
	Source        string          `json:"source"`
	Metadata      metadata        `json:"metadata"`
	SBOM          json.RawMessage `json:"sbom"`
}

type summary struct {
	SchemaVersion int       `json:"schema_version"`
	ReportID      string    `json:"report_id"`
	MachineID     string    `json:"machine_id"`
	ClientID      string    `json:"client_id"`
	CollectedAt   time.Time `json:"collected_at"`
	ReceivedAt    time.Time `json:"received_at"`
	Hostname      string    `json:"hostname"`
	OS            string    `json:"os"`
	Arch          string    `json:"arch"`
	Source        string    `json:"source"`
	Metadata      metadata  `json:"metadata"`
	SpecVersion   string    `json:"spec_version"`
	PackageCount  int       `json:"package_count"`
}

type component struct {
	Type       string      `json:"type,omitempty"`
	Name       string      `json:"name"`
	Version    string      `json:"version,omitempty"`
	Group      string      `json:"group,omitempty"`
	PURL       string      `json:"purl,omitempty"`
	BOMRef     string      `json:"bom-ref,omitempty"`
	Components []component `json:"components,omitempty"`
}

type cyclonedx struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Components  []component `json:"components"`
}

func validate(report submission) (summary, error) {
	if report.SchemaVersion != 1 {
		return summary{}, fmt.Errorf("schema_version must be 1")
	}
	if !uuidPattern.MatchString(report.ReportID) || !uuidPattern.MatchString(report.MachineID) {
		return summary{}, fmt.Errorf("report_id and machine_id must be lowercase UUIDs")
	}
	if !slugPattern.MatchString(report.ClientID) || report.CollectedAt.IsZero() {
		return summary{}, fmt.Errorf("invalid client_id or collected_at")
	}
	if !validText(report.Hostname, 255, true) || !validText(report.OS, 64, true) ||
		!validText(report.Arch, 64, true) || !validText(report.Source, 2048, true) {
		return summary{}, fmt.Errorf("invalid hostname, os, arch or source")
	}
	if !validText(report.Metadata.Group, 128, false) || !validText(report.Metadata.Zone, 128, false) ||
		!validText(report.Metadata.Department, 128, false) || len(report.Metadata.Tags) > 32 {
		return summary{}, fmt.Errorf("invalid group, zone, department or tag count")
	}
	for key, value := range report.Metadata.Tags {
		if !slugPattern.MatchString(key) || !validText(value, 256, true) {
			return summary{}, fmt.Errorf("invalid tag key or value")
		}
	}
	var sbom cyclonedx
	if err := json.Unmarshal(report.SBOM, &sbom); err != nil || sbom.BOMFormat != "CycloneDX" ||
		!validText(sbom.SpecVersion, 32, true) {
		return summary{}, fmt.Errorf("sbom must be a CycloneDX JSON document with a specVersion")
	}
	count := 0
	if !eachComponent(sbom.Components, func(item component) bool {
		count++
		return item.Name != ""
	}) {
		return summary{}, fmt.Errorf("CycloneDX components must have a name")
	}
	return summary{
		SchemaVersion: report.SchemaVersion,
		ReportID:      report.ReportID,
		MachineID:     report.MachineID,
		ClientID:      report.ClientID,
		CollectedAt:   report.CollectedAt.UTC(),
		ReceivedAt:    time.Now().UTC(),
		Hostname:      report.Hostname,
		OS:            report.OS,
		Arch:          report.Arch,
		Source:        report.Source,
		Metadata:      report.Metadata,
		SpecVersion:   sbom.SpecVersion,
		PackageCount:  count,
	}, nil
}

func validText(value string, maximum int, required bool) bool {
	return len(value) <= maximum && (!required || strings.TrimSpace(value) != "") &&
		strings.IndexFunc(value, unicode.IsControl) == -1
}

func eachComponent(components []component, visit func(component) bool) bool {
	for _, item := range components {
		if !visit(item) || !eachComponent(item.Components, visit) {
			return false
		}
	}
	return true
}

func decodeJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return fmt.Errorf("expected exactly one JSON object")
		}
		return err
	}
	return nil
}
