package main

import (
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"example.com/secretseal"
	"example.com/secretseal/internal/cipher"
)

func main() {
	addr := flag.String("addr", ":8104", "listen")
	web := flag.String("web", "web", "web")
	data := flag.String("data", "data", "data")
	flag.Parse()
	_ = os.MkdirAll(*data, 0o755)
	box, err := secretseal.New(secretseal.Options{
		Cipher: cipher.NewAESGCM(), PersistPath: filepath.Join(*data, "ring.json"),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer box.Close()
	// 默认种子密钥
	_ = box.Add("k1", "default", []byte("0123456789abcdef0123456789abcdef"))

	var mu sync.Mutex
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.Dir(*web)))
	mux.HandleFunc("/api/keys", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, box.ListKeys())
	})
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		writeJSON(w, box.Stats())
	})
	mux.HandleFunc("/api/seal", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		var body struct {
			AAD   string `json:"aad"`
			Plain string `json:"plain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		bl, err := box.Seal([]byte(body.AAD), []byte(body.Plain))
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, bl)
	})
	mux.HandleFunc("/api/open", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		var bl secretseal.Blob
		if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		plain, err := box.Open(bl)
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]string{"plain": string(plain)})
	})
	mux.HandleFunc("/api/rotate", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST", 405)
			return
		}
		var body struct {
			ID    string `json:"id"`
			Label string `json:"label"`
			Key   string `json:"key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		mu.Lock()
		err := box.Rotate(body.ID, body.Label, []byte(body.Key))
		active := box.ActiveKid()
		mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]string{"active": active})
	})
	log.Printf("seald on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
