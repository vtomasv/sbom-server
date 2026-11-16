package server

import (
	"bytes"
	_ "embed"
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

//go:embed dashboard.html
var dashboardHTML string

var views = template.Must(template.New("sbom").Parse(dashboardHTML))

type pageLinks struct {
	Previous string
	Next     string
}

func links(r *http.Request, total, limit, offset int) pageLinks {
	var result pageLinks
	params := r.URL.Query()
	params.Set("limit", strconv.Itoa(limit))
	if offset > 0 {
		params.Set("offset", strconv.Itoa(max(0, min(offset, total)-limit)))
		result.Previous = "?" + params.Encode()
	}
	if offset < total && total-offset > limit {
		params.Set("offset", strconv.Itoa(offset+limit))
		result.Next = "?" + params.Encode()
	}
	return result
}

func (service *api) dashboard(w http.ResponseWriter, r *http.Request, who principal) {
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
	items := newPage(service.list(who, query, true), limit, offset)
	service.render(w, "machines", struct {
		Admin   bool
		Client  string
		Group   string
		Zone    string
		Dept    string
		Tag     string
		Tags    []string
		Machine string
		Items   page[summary]
		Links   pageLinks
	}{
		Admin: who.admin, Client: query.client, Group: query.group, Zone: query.zone, Dept: query.department,
		Tag: values.Get("tag"), Tags: values["tag"][min(1, len(values["tag"])):],
		Machine: query.machine, Items: items, Links: links(r, items.Total, limit, offset),
	})
}

func (service *api) reportView(w http.ResponseWriter, r *http.Request, who principal) {
	info, path, found := service.find(w, r, who)
	if !found {
		return
	}
	params := r.URL.Query()
	limit, offset, err := pagination(params)
	if err != nil {
		problem(w, http.StatusBadRequest, err.Error())
		return
	}
	name := strings.ToLower(params.Get("name"))
	if !validText(name, 256, false) {
		problem(w, http.StatusBadRequest, "invalid package name filter")
		return
	}
	items, err := packagePage(path, name, limit, offset)
	if err != nil {
		service.internal(w, "read CycloneDX components", err)
		return
	}
	endpoint := "/v1/reports/" + info.ReportID
	clientQuery := "?client_id=" + url.QueryEscape(info.ClientID)
	history := clientQuery + "&machine_id=" + url.QueryEscape(info.MachineID)
	service.render(w, "report", struct {
		Info     summary
		Items    page[component]
		Links    pageLinks
		Download string
		History  string
		Name     string
	}{
		Info: info, Items: items, Links: links(r, items.Total, limit, offset),
		Download: endpoint + "/sbom" + clientQuery, History: "/v1/reports" + history, Name: params.Get("name"),
	})
}

func (service *api) render(w http.ResponseWriter, name string, data any) {
	var contents bytes.Buffer
	if err := views.ExecuteTemplate(&contents, name, data); err != nil {
		service.internal(w, "render dashboard", err)
		return
	}
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(contents.Bytes())
}
