package main

import (
	"encoding/json"
	"net/http"

	"github.com/gorilla/mux"
)

type apiF func(http.ResponseWriter, *http.Request)
type apiE struct {
	Error string
}

type ListenAddress struct {
	Address string
}

func WriteJson(w http.ResponseWriter, status int, v any) error {
	w.WriteHeader(status)
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

func makeHTTPHandleF(f apiF) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			writeJSON(w, http.StatusBadRequest, apiE{Error: err.Error()})
		}
	}
}

func run() {
	router := mux.NewRouter()
	router.Handle("account")
}
