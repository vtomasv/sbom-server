package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
)

type api struct {
	data   *store
	auth   map[[sha256.Size]byte]principal
	max    int64
	logger *slog.Logger
}

func New(config Config, logger *slog.Logger) (http.Handler, error) {
	identities, err := credentials(config)
	if err != nil {
		return nil, err
	}
	if config.MaxReportBytes == 0 {
		config.MaxReportBytes = defaultMaxReportBytes
	}
	if config.MaxReportBytes < 1024 || config.MaxReportBytes > 128<<20 {
		return nil, fmt.Errorf("max_report_bytes must be between 1024 and 134217728")
	}
	data, err := openStore(config.DataDir)
	if err != nil {
		return nil, fmt.Errorf("open report storage: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	service := &api{data: data, auth: identities, max: config.MaxReportBytes, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		respond(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/reports", service.ingest)
	mux.HandleFunc("GET /v1/reports", service.read(service.reports))
	mux.HandleFunc("GET /v1/machines", service.read(service.machines))
	mux.HandleFunc("GET /v1/reports/{report}", service.read(service.detail))
	mux.HandleFunc("GET /v1/reports/{report}/sbom", service.read(service.download))
	mux.HandleFunc("GET /v1/reports/{report}/packages", service.read(service.packages))
	mux.HandleFunc("GET /reports/{report}", service.read(service.reportView))
	mux.HandleFunc("GET /{$}", service.read(service.dashboard))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		mux.ServeHTTP(w, r)
	}), nil
}

func (service *api) authenticate(r *http.Request, allowBasic bool) (principal, bool) {
	kind, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if found && strings.EqualFold(kind, "Bearer") && validToken(token) {
		who, ok := service.auth[sha256.Sum256([]byte(token))]
		return who, ok
	}
	if allowBasic {
		name, token, found := r.BasicAuth()
		if found && validToken(token) {
			who, ok := service.auth[sha256.Sum256([]byte(token))]
			return who, ok && ((who.admin && name == "admin") || (!who.admin && name == who.client))
		}
	}
	return principal{}, false
}

func (service *api) read(handler func(http.ResponseWriter, *http.Request, principal)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		who, ok := service.authenticate(r, true)
		if !ok {
			if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/reports/") {
				w.Header().Set("WWW-Authenticate", `Basic realm="SBOM", charset="UTF-8"`)
			} else {
				w.Header().Set("WWW-Authenticate", `Bearer realm="SBOM"`)
			}
			problem(w, http.StatusUnauthorized, "authentication required")
			return
		}
		handler(w, r, who)
	}
}

func (service *api) ingest(w http.ResponseWriter, r *http.Request) {
	who, ok := service.authenticate(r, false)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="SBOM"`)
		problem(w, http.StatusUnauthorized, "client token required")
		return
	}
	if who.admin {
		problem(w, http.StatusForbidden, "use a client token to submit reports")
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		problem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if r.ContentLength > service.max {
		problem(w, http.StatusRequestEntityTooLarge, "report exceeds max_report_bytes")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, service.max)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var sizeError *http.MaxBytesError
		if errors.As(err, &sizeError) {
			problem(w, http.StatusRequestEntityTooLarge, "report exceeds max_report_bytes")
			return
		}
		problem(w, http.StatusBadRequest, "failed to read report")
		return
	}
	var report submission
	if err := decodeJSON(bytes.NewReader(body), &report); err != nil {
		problem(w, http.StatusBadRequest, "invalid JSON report envelope")
		return
	}
	if report.ClientID != who.client {
		problem(w, http.StatusForbidden, "client_id does not match the token")
		return
	}
	info, err := validate(report)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	stored, created, err := service.data.save(info, report.SBOM, sha256.Sum256(body))
	if errors.Is(err, errConflict) {
		problem(w, http.StatusConflict, errConflict.Error())
		return
	}
	if err != nil {
		service.internal(w, "save report", err)
		return
	}
	if created {
		w.Header().Set("Location", "/v1/reports/"+stored.ReportID+"?client_id="+url.QueryEscape(stored.ClientID))
		respond(w, http.StatusCreated, stored)
		return
	}
	respond(w, http.StatusOK, stored)
}

type listFilters struct {
	client     string
	machine    string
	group      string
	zone       string
	department string
	tags       map[string]string
}

func filters(values url.Values) (listFilters, error) {
	query := listFilters{
		client:     values.Get("client_id"),
		machine:    values.Get("machine_id"),
		group:      values.Get("group"),
		zone:       values.Get("zone"),
		department: values.Get("department"),
		tags:       make(map[string]string),
	}
	if (query.client != "" && !slugPattern.MatchString(query.client)) ||
		(query.machine != "" && !uuidPattern.MatchString(query.machine)) {
		return listFilters{}, fmt.Errorf("invalid client_id or machine_id filter")
	}
	if !validText(query.group, 128, false) || !validText(query.zone, 128, false) ||
		!validText(query.department, 128, false) || len(values["tag"]) > 32 {
		return listFilters{}, fmt.Errorf("invalid group, zone, department or tag count")
	}
	for _, tag := range values["tag"] {
		if tag == "" {
			continue
		}
		key, value, ok := strings.Cut(tag, "=")
		if !ok || !slugPattern.MatchString(key) || !validText(value, 256, true) || query.tags[key] != "" {
			return listFilters{}, fmt.Errorf("tags must use unique keys and the form key=value")
		}
		query.tags[key] = value
	}
	return query, nil
}

func (query listFilters) matches(item summary) bool {
	if (query.client != "" && query.client != item.ClientID) ||
		(query.machine != "" && query.machine != item.MachineID) ||
		(query.group != "" && query.group != item.Metadata.Group) ||
		(query.zone != "" && query.zone != item.Metadata.Zone) ||
		(query.department != "" && query.department != item.Metadata.Department) {
		return false
	}
	for name, value := range query.tags {
		if item.Metadata.Tags[name] != value {
			return false
		}
	}
	return true
}

func recentlyCollected(first, second summary) bool {
	if !first.CollectedAt.Equal(second.CollectedAt) {
		return first.CollectedAt.After(second.CollectedAt)
	}
	if !first.ReceivedAt.Equal(second.ReceivedAt) {
		return first.ReceivedAt.After(second.ReceivedAt)
	}
	if first.ClientID != second.ClientID {
		return first.ClientID < second.ClientID
	}
	return first.ReportID < second.ReportID
}

func (service *api) list(who principal, query listFilters, machines bool) []summary {
	items := service.data.summaries(who)
	if machines {
		type machineKey struct {
			client string
			id     string
		}
		latest := make(map[machineKey]summary)
		for _, item := range items {
			id := machineKey{client: item.ClientID, id: item.MachineID}
			if previous, found := latest[id]; !found || recentlyCollected(item, previous) {
				latest[id] = item
			}
		}
		items = items[:0]
		for _, item := range latest {
			items = append(items, item)
		}
	}
	filtered := items[:0]
	for _, item := range items {
		if query.matches(item) {
			filtered = append(filtered, item)
		}
	}
	sort.Slice(filtered, func(a, b int) bool { return recentlyCollected(filtered[a], filtered[b]) })
	return filtered
}

type page[T any] struct {
	Items  []T `json:"items"`
	Total  int `json:"total"`
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
}

func newPage[T any](items []T, limit, offset int) page[T] {
	start := min(offset, len(items))
	end := start + min(limit, len(items)-start)
	return page[T]{Items: items[start:end], Total: len(items), Limit: limit, Offset: offset}
}

func pagination(values url.Values) (limit, offset int, err error) {
	limit = 100
	if raw := values.Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 1 || limit > 500 {
			return 0, 0, fmt.Errorf("limit must be an integer between 1 and 500")
		}
	}
	if raw := values.Get("offset"); raw != "" {
		offset, err = strconv.Atoi(raw)
		if err != nil || offset < 0 {
			return 0, 0, fmt.Errorf("offset must be a nonnegative integer")
		}
	}
	return limit, offset, nil
}

func (service *api) reports(w http.ResponseWriter, r *http.Request, who principal) {
	service.respondList(w, r, who, false)
}

func (service *api) machines(w http.ResponseWriter, r *http.Request, who principal) {
	service.respondList(w, r, who, true)
}

func (service *api) respondList(w http.ResponseWriter, r *http.Request, who principal, machines bool) {
	values := r.URL.Query()
	query, err := filters(values)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	limit, offset, err := pagination(values)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	respond(w, http.StatusOK, newPage(service.list(who, query, machines), limit, offset))
}

func (service *api) find(w http.ResponseWriter, r *http.Request, who principal) (summary, string, bool) {
	id := r.PathValue("report")
	client := r.URL.Query().Get("client_id")
	if !uuidPattern.MatchString(id) || (client != "" && !slugPattern.MatchString(client)) {
		problem(w, http.StatusBadRequest, "invalid report id or client_id")
		return summary{}, "", false
	}
	info, file, found, ambiguous := service.data.lookup(who, id, client)
	if ambiguous {
		problem(w, http.StatusConflict, "multiple reports with this id; specify client_id")
		return summary{}, "", false
	}
	if !found {
		problem(w, http.StatusNotFound, "report not found")
		return summary{}, "", false
	}
	return info, file, true
}

func (service *api) detail(w http.ResponseWriter, r *http.Request, who principal) {
	info, _, found := service.find(w, r, who)
	if found {
		respond(w, http.StatusOK, info)
	}
}

func (service *api) download(w http.ResponseWriter, r *http.Request, who principal) {
	info, path, found := service.find(w, r, who)
	if !found {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		service.internal(w, "open SBOM", err)
		return
	}
	defer file.Close()
	w.Header().Set("Content-Type", "application/vnd.cyclonedx+json")
	w.Header().Set("Content-Disposition", `attachment; filename="`+info.ReportID+`.cdx.json"`)
	http.ServeContent(w, r, info.ReportID+".cdx.json", info.ReceivedAt, file)
}

func (service *api) packages(w http.ResponseWriter, r *http.Request, who principal) {
	_, path, found := service.find(w, r, who)
	if !found {
		return
	}
	values := r.URL.Query()
	limit, offset, err := pagination(values)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.ToLower(values.Get("name"))
	if !validText(name, 256, false) {
		problem(w, http.StatusBadRequest, "invalid package name filter")
		return
	}
	result, err := packagePage(path, name, limit, offset)
	if err != nil {
		service.internal(w, "read CycloneDX components", err)
		return
	}
	respond(w, http.StatusOK, result)
}

func packagePage(path, name string, limit, offset int) (page[component], error) {
	file, err := os.Open(path)
	if err != nil {
		return page[component]{}, err
	}
	defer file.Close()
	var document cyclonedx
	if err := json.NewDecoder(file).Decode(&document); err != nil {
		return page[component]{}, err
	}
	result := page[component]{Items: make([]component, 0), Limit: limit, Offset: offset}
	eachComponent(document.Components, func(item component) bool {
		if !strings.Contains(strings.ToLower(item.Name), name) {
			return true
		}
		if result.Total >= offset && len(result.Items) < limit {
			item.Components = nil
			result.Items = append(result.Items, item)
		}
		result.Total++
		return true
	})
	return result, nil
}

func (service *api) internal(w http.ResponseWriter, action string, err error) {
	service.logger.Error(action, "error", err)
	problem(w, http.StatusInternalServerError, "server failed to process request")
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]string{"error": message})
}
