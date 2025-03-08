package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"context"
	"encoding/json"
	"time"
	"regexp"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/cvanloo/parsenv"
	_ "github.com/joho/godotenv/autoload"
)

type (
	HandlerWithError func(http.ResponseWriter, *http.Request) error
	ErrorResponder interface {
		RespondError(w http.ResponseWriter, r *http.Request) (wasHandled bool)
	}
	BadRequest struct {
		Inner error
	}
	Forbidden struct{}
	ErrorBuildScript struct {
		Inner error
	}
	Env struct {
		BindAddress string     `cfg:"default=:8080"`
		ClientSecret string    `cfg:"required"`
		BuildScriptPath string `cfg:"required"`
	}
	Whitelist struct {
		allowedSubnets []*net.IPNet
	}
)

func retrieveGitHubWhitelist(ctx context.Context) (w Whitelist, err error) {
	githubURI := "https://api.github.com/meta"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubURI, nil)
	if err != nil {
		panic(err) // programmer error
	}
	h := req.Header
	h.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return w, err
	}
	defer resp.Body.Close()
	var githubResponse struct {
		Hooks []string
		//Actions []string
	}
	if err := json.NewDecoder(resp.Body).Decode(&githubResponse); err != nil {
		return w, err
	}
	w.allowedSubnets = make([]*net.IPNet, 0, len(githubResponse.Hooks))
	for _, ip := range githubResponse.Hooks {
		_, subnet, err := net.ParseCIDR(ip)
		if err != nil {
			log.Printf("github sent us a weird ip: %v", err)
			continue
		}
		w.allowedSubnets = append(w.allowedSubnets, subnet)
	}
	return w, nil
}

func (w Whitelist) Contains(ip net.IP) bool {
	for _, subnet := range w.allowedSubnets {
		if subnet.Contains(ip) {
			return true
		}
	}
	return false
}

func (h HandlerWithError) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := h(w, r); err != nil {
		if err, ok := err.(ErrorResponder); ok {
			if err.RespondError(w, r) {
				return
			}
		}
		status := http.StatusInternalServerError
		http.Error(w, http.StatusText(status), status)
		log.Printf("request: %s %s, by: %s, internal error: %v", r.Method, r.URL.Path, r.RemoteAddr, err)
	}
}

func (err BadRequest) RespondError(w http.ResponseWriter, r *http.Request) bool {
	http.Error(w, err.Error(), http.StatusBadRequest)
	return true
}

func (err BadRequest) Error() string {
	return fmt.Sprintf("%s: %s", http.StatusText(http.StatusBadRequest), err.Inner)
}

func (err Forbidden) RespondError(w http.ResponseWriter, r *http.Request) bool {
	http.Error(w, err.Error(), http.StatusForbidden)
	return true
}

func (err Forbidden) Error() string {
	return http.StatusText(http.StatusForbidden)
}

func (err ErrorBuildScript) RespondError(w http.ResponseWriter, r *http.Request) bool {
	if err, ok := err.Inner.(*exec.ExitError); ok {
		http.Error(w, fmt.Sprintf("build script exited with status code: %d", err.ExitCode()), http.StatusInternalServerError)
		return true
	}
	return false
}

func (err ErrorBuildScript) Error() string {
	return err.Inner.Error()
}

func main() {
	env := Env{}
	if err := parsenv.Load(&env); err != nil {
		log.Fatal(err)
	}
	if _, err := exec.LookPath(env.BuildScriptPath); err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	whitelist, err := retrieveGitHubWhitelist(ctx)
	if err != nil {
		log.Fatal(err)
	}
	{ // whitelist local host for testing
		_, localhost6, err := net.ParseCIDR("::1/128")
		_, localhost4, err := net.ParseCIDR("127.0.0.1/24")
		if err != nil {
			panic(err)
		}
		whitelist.allowedSubnets = append(whitelist.allowedSubnets, localhost4, localhost6)
	}
	mux := &http.ServeMux{}
	mux.Handle("GET /pub", HandlerWithError(serveUpdateInfo))
	mux.Handle("POST /pub", routeUpdate(env, whitelist))
	if err := http.ListenAndServe(env.BindAddress, mux); err != nil {
		panic(err)
	}
}

func serveUpdateInfo(w http.ResponseWriter, r *http.Request) error {
	w.WriteHeader(http.StatusMethodNotAllowed)
	w.Write([]byte("POST /pub expected"))
	return nil
}

var remoteAddrRegex = regexp.MustCompile("(\\[([A-Fa-f0-9:]*)\\]|[^:]*):\\d*")

func routeUpdate(env Env, allowedIPs Whitelist) HandlerWithError {
	return func(w http.ResponseWriter, r *http.Request) error {
		addrMatches := remoteAddrRegex.FindStringSubmatch(r.RemoteAddr)
		log.Printf("%#v", addrMatches)
		if len(addrMatches) != 2 && len(addrMatches) != 3 {
			return fmt.Errorf("regex match failed to extract ip address: %#v", addrMatches)
		}
		clientIPString := addrMatches[1]
		if len(addrMatches) == 3 {
			clientIPString = addrMatches[2]
		}
		clientIP := net.ParseIP(clientIPString)
		if clientIP == nil {
			return fmt.Errorf("invalid ip: %s", clientIPString)
		}
		if !allowedIPs.Contains(clientIP) {
			return Forbidden{}
		}
		fullBody, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		messageMac := r.Header.Get("X-Hub-Signature-256")
		if messageMac == "" {
			return BadRequest{fmt.Errorf("missing hmac sha256 signature")}
		}
		mac := hmac.New(sha256.New, []byte(env.ClientSecret))
		mac.Write(fullBody)
		expectedMac := mac.Sum(nil)
		if !hmac.Equal([]byte(messageMac), expectedMac) {
			return Forbidden{}
		}
		cmd := exec.Command(env.BuildScriptPath)
		out, err := cmd.CombinedOutput()
		log.Printf("build script exited with: %v, log output: %s", err, out)
		if err != nil {
			return ErrorBuildScript{err}
		}
		w.WriteHeader(http.StatusOK)
		return nil
	}
}
