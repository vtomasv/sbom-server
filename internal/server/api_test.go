package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	adminToken = "test-admin-4c09e2f98fd9c5f888df"
	alphaToken = "test-alpha-185b772dcf6193bedff7"
	betaToken  = "test-beta-6765b7614823f084a5f4"
	machineID  = "5f99021c-bd52-49b2-89ee-2eeba1bb7704"
	reportID   = "9f6a5d73-36ef-4585-aa60-d7af0ecbdc43"
	reportID2  = "c5b04916-6c97-41e5-9c59-64223f1d825c"
)

func configForTest(t *testing.T) Config {
	t.Helper()
	return Config{DataDir: t.TempDir(), AdminToken: adminToken, Clients: map[string]string{"alpha": alphaToken, "beta": betaToken}}
}

func newAPI(t *testing.T, config Config) http.Handler {
	t.Helper()
	handler, err := New(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func example(client, id, group string) submission {
	return submission{
		SchemaVersion: 1, ReportID: id, MachineID: machineID, ClientID: client,
		CollectedAt: time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC),
		Hostname:    "<script>machine</script>", OS: "linux", Arch: "arm64", Source: "/",
		Metadata: metadata{Group: group, Zone: "sur", Department: "Plataforma", Tags: map[string]string{"tipo": "desarrollo"}},
		SBOM:     json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6","components":[{"type":"library","name":"bash","version":"5.2","purl":"pkg:deb/debian/bash@5.2","components":[{"name":"libreadline"}]}],"properties":[{"name":"keep","value":"full SBOM"}]}`),
	}
}

func request(handler http.Handler, method, target, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	return resp
}

func post(handler http.Handler, token string, sample submission) *httptest.ResponseRecorder {
	body, err := json.Marshal(sample)
	if err != nil {
		panic(err)
	}
	return request(handler, http.MethodPost, "/v1/reports", token, body)
}

func expect(t *testing.T, response *httptest.ResponseRecorder, want int) {
	t.Helper()
	if response.Code != want {
		t.Fatalf("got %d, want %d: %s", response.Code, want, response.Body)
	}
}

func parsePage[T any](t *testing.T, response *httptest.ResponseRecorder) page[T] {
	t.Helper()
	expect(t, response, http.StatusOK)
	var result page[T]
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestReportLifecycleAndTenantIsolation(t *testing.T) {
	config := configForTest(t)
	handler := newAPI(t, config)
	alpha := example("alpha", reportID, "operaciones")
	beta := example("beta", reportID, "desarrollo")

	expect(t, request(handler, http.MethodGet, "/healthz", "", nil), http.StatusOK)
	expect(t, post(handler, "", alpha), http.StatusUnauthorized)
	expect(t, post(handler, adminToken, alpha), http.StatusForbidden)
	expect(t, post(handler, betaToken, alpha), http.StatusForbidden)
	created := post(handler, alphaToken, alpha)
	expect(t, created, http.StatusCreated)
	if !strings.HasSuffix(created.Header().Get("Location"), "?client_id=alpha") {
		t.Fatal("report location lacks client scope")
	}
	expect(t, post(handler, alphaToken, alpha), http.StatusOK)
	modified := alpha
	modified.Hostname = "someone else"
	expect(t, post(handler, alphaToken, modified), http.StatusConflict)
	expect(t, post(handler, betaToken, beta), http.StatusCreated)

	handler = newAPI(t, config)
	base := "/v1/reports/" + reportID
	expect(t, post(handler, alphaToken, alpha), http.StatusOK)
	expect(t, request(handler, http.MethodGet, base, adminToken, nil), http.StatusConflict)
	expect(t, request(handler, http.MethodGet, base+"?client_id=beta", alphaToken, nil), http.StatusNotFound)
	result := parsePage[summary](t, request(handler, http.MethodGet, "/v1/machines", alphaToken, nil))
	if result.Total != 1 || result.Items[0].ClientID != "alpha" || result.Items[0].PackageCount != 2 {
		t.Fatalf("unexpected tenant list: %+v", result)
	}
	result = parsePage[summary](t, request(handler, http.MethodGet, "/v1/machines?department=Plataforma&zone=sur&tag=tipo%3Ddesarrollo&group=desarrollo", adminToken, nil))
	if result.Total != 1 || result.Items[0].ClientID != "beta" {
		t.Fatalf("unexpected filtered list: %+v", result)
	}
	result = parsePage[summary](t, request(handler, http.MethodGet, "/v1/machines?limit=1&offset=9223372036854775807", adminToken, nil))
	if result.Total != 2 || result.Items == nil || len(result.Items) != 0 {
		t.Fatalf("unexpected out-of-range page: %+v", result)
	}
	components := parsePage[component](t, request(handler, http.MethodGet, base+"/packages?client_id=alpha&name=READLINE", adminToken, nil))
	if components.Total != 1 || components.Items[0].Name != "libreadline" {
		t.Fatalf("unexpected component list: %+v", components)
	}
	download := request(handler, http.MethodGet, base+"/sbom?client_id=alpha", alphaToken, nil)
	expect(t, download, http.StatusOK)
	if !bytes.Equal(download.Body.Bytes(), alpha.SBOM) || download.Header().Get("Content-Type") != "application/vnd.cyclonedx+json" {
		t.Fatal("download did not preserve the original CycloneDX document")
	}
}

func TestLatestMachineUsesCollectionTime(t *testing.T) {
	handler := newAPI(t, configForTest(t))
	older := example("alpha", reportID, "antiguo")
	newer := example("alpha", reportID2, "vigente")
	newer.CollectedAt = older.CollectedAt.Add(time.Hour)
	expect(t, post(handler, alphaToken, newer), http.StatusCreated)
	expect(t, post(handler, alphaToken, older), http.StatusCreated)
	machines := parsePage[summary](t, request(handler, http.MethodGet, "/v1/machines?group=antiguo", alphaToken, nil))
	if machines.Total != 0 {
		t.Fatalf("machine returned with a superseded group: %+v", machines)
	}
	reports := parsePage[summary](t, request(handler, http.MethodGet, "/v1/reports?machine_id="+machineID, alphaToken, nil))
	if reports.Total != 2 || reports.Items[0].ReportID != reportID2 {
		t.Fatalf("unexpected history ordering: %+v", reports)
	}
}

func TestConcurrentRetriesCreateOneReport(t *testing.T) {
	handler := newAPI(t, configForTest(t))
	item := example("alpha", reportID, "grupo")
	var group sync.WaitGroup
	codes := make(chan int, 8)
	for range cap(codes) {
		group.Add(1)
		go func() {
			defer group.Done()
			codes <- post(handler, alphaToken, item).Code
		}()
	}
	group.Wait()
	close(codes)
	created := 0
	for code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusOK:
		default:
			t.Fatalf("unexpected retry status %d", code)
		}
	}
	if created != 1 {
		t.Fatalf("created %d reports, want 1", created)
	}
}

func TestRejectsInvalidInputsAndOversizedReports(t *testing.T) {
	config := configForTest(t)
	config.MaxReportBytes = 1024
	handler := newAPI(t, config)
	body := []byte(strings.Repeat("x", 1025))
	expect(t, request(handler, http.MethodPost, "/v1/reports", alphaToken, body), http.StatusRequestEntityTooLarge)
	chunked := httptest.NewRequest(http.MethodPost, "/v1/reports", bytes.NewReader(body))
	chunked.ContentLength = -1
	chunked.Header.Set("Content-Type", "application/json")
	chunked.Header.Set("Authorization", "Bearer "+alphaToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, chunked)
	expect(t, recorder, http.StatusRequestEntityTooLarge)
	bad := example("alpha", reportID, "grupo")
	bad.SBOM = json.RawMessage(`{"bomFormat":"SPDX","specVersion":"2.3"}`)
	expect(t, post(handler, alphaToken, bad), http.StatusBadRequest)
	bad.SBOM = json.RawMessage(`{"bomFormat":"CycloneDX","specVersion":"1.6"}`)
	bad.Metadata.Tags = map[string]string{"bad tag": "value"}
	expect(t, post(handler, alphaToken, bad), http.StatusBadRequest)
	expect(t, request(handler, http.MethodGet, "/v1/machines?tag=foo", adminToken, nil), http.StatusBadRequest)
	expect(t, request(handler, http.MethodGet, "/v1/machines?limit=501", adminToken, nil), http.StatusBadRequest)
}

func TestDashboardUsesBasicAuthAndEscapesReportValues(t *testing.T) {
	handler := newAPI(t, configForTest(t))
	expect(t, post(handler, alphaToken, example("alpha", reportID, "grupo")), http.StatusCreated)
	denied := request(handler, http.MethodGet, "/", "", nil)
	expect(t, denied, http.StatusUnauthorized)
	if !strings.HasPrefix(denied.Header().Get("WWW-Authenticate"), "Basic ") {
		t.Fatal("missing Basic challenge")
	}
	for _, path := range []string{"/", fmt.Sprintf("/reports/%s?client_id=alpha", reportID)} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.SetBasicAuth("admin", adminToken)
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		expect(t, resp, http.StatusOK)
		if !strings.Contains(resp.Body.String(), "&lt;script&gt;machine&lt;/script&gt;") || strings.Contains(resp.Body.String(), "<script>") {
			t.Fatal("dashboard did not HTML-escape the hostname")
		}
	}
}
