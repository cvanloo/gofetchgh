package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/cvanloo/parsenv"
	_ "github.com/joho/godotenv/autoload"
)

type (
	HandlerWithError func(http.ResponseWriter, *http.Request) error
	ErrorResponder   interface {
		RespondError(w http.ResponseWriter, r *http.Request) (wasHandled bool)
	}
	BadRequest struct {
		Inner error
	}
	Forbidden        struct{}
	ErrorBuildScript struct {
		Inner error
	}
	Env struct {
		BindAddress     string `cfg:"default=:8080"`
		ClientSecret    string `cfg:"required"`
		BuildScriptPath string `cfg:"required"`
	}
	Whitelist struct {
		allowedSubnets []*net.IPNet
	}
	BuildStatus struct {
		sync.RWMutex
		Cancel    context.CancelFunc
		CmdOut    []byte
		CmdErr    error
		UpdatedAt time.Time
		Reason    CompletedReason
	}
	CompletedReason string
)

var (
	ReasonRunning   CompletedReason = "Build Currently Running"
	ReasonDeadline  CompletedReason = "Build Deadline Exceeded"
	ReasonFailed    CompletedReason = "Build Failed"
	ReasonCompleted CompletedReason = "Build Completed"
)

func (b *BuildStatus) RunCommand(cmdline string) {
	b.Lock()
	defer b.Unlock()
	if b.Cancel != nil {
		b.Cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	cmd := exec.CommandContext(ctx, cmdline)
	b.Cancel = cancel
	b.UpdatedAt = time.Now()
	b.Reason = ReasonRunning
	b.CmdOut = []byte{}
	b.CmdErr = nil
	go func() {
		out, err := cmd.CombinedOutput()
		if errors.Is(err, context.Canceled) { // build is only canceled when a new build is invoked
			log.Printf("build cancelled: %v, log output: %s", err, out)
			return
		}
		b.Lock()
		b.Cancel()
		b.UpdatedAt = time.Now()
		if err == nil {
			b.Reason = ReasonCompleted
		} else if errors.Is(err, context.DeadlineExceeded) {
			b.Reason = ReasonDeadline
		} else {
			b.Reason = ReasonFailed
		}
		b.CmdOut = out
		b.CmdErr = err
		b.Unlock()
	}()
}

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
	buildStatus := &BuildStatus{}
	mux := &http.ServeMux{}
	mux.Handle("GET /pub", HandlerWithError(serveUpdateInfo))
	mux.Handle("POST /pub", routeUpdate(env, whitelist, buildStatus))
	mux.Handle("GET /status", routeStatus(env, buildStatus))
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

func routeUpdate(env Env, allowedIPs Whitelist, buildStatus *BuildStatus) HandlerWithError {
	return func(w http.ResponseWriter, r *http.Request) error {
		addrMatches := remoteAddrRegex.FindStringSubmatch(r.RemoteAddr)
		log.Printf("%#v", addrMatches)
		if len(addrMatches) != 3 {
			return fmt.Errorf("regex match failed to extract ip address: %#v", addrMatches)
		}
		clientIPString := addrMatches[2]
		if clientIPString == "" {
			clientIPString = addrMatches[1]
		}
		clientIP := net.ParseIP(clientIPString)
		if clientIP == nil {
			return fmt.Errorf("invalid ip: %s", clientIPString)
		}
		if !allowedIPs.Contains(clientIP) {
			log.Println("forbidden: remoteaddr")
			return Forbidden{}
		}
		fullBody, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		signature := r.Header.Get("X-Hub-Signature-256")
		if signature == "" {
			return BadRequest{fmt.Errorf("missing hmac sha256 signature")}
		}
		signaturePrefix := "sha256="
		if !strings.HasPrefix(signature, signaturePrefix) {
			return BadRequest{fmt.Errorf("malformed hmac sha256 signature")}
		}
		messageMac, err := hex.DecodeString(strings.TrimPrefix(signature, signaturePrefix))
		if err != nil {
			return BadRequest{fmt.Errorf("encoding invalid for hmac sha256 signature")}
		}
		mac := hmac.New(sha256.New, []byte(env.ClientSecret))
		mac.Write(fullBody)
		expectedMac := mac.Sum(nil)
		if !hmac.Equal([]byte(messageMac), expectedMac) {
			log.Println("forbidden: hmac")
			return Forbidden{}
		}
		buildStatus.RunCommand(env.BuildScriptPath)
		h := w.Header()
		h.Set("Location", "/status")
		w.WriteHeader(http.StatusCreated)
		return nil
	}
}

func routeStatus(env Env, buildStatus *BuildStatus) HandlerWithError {
	return func(w http.ResponseWriter, r *http.Request) error {
		buildStatus.RLock()
		defer buildStatus.RUnlock()
		statusResponse := struct {
			Status      string
			UpdatedTime time.Time
			Out         string
			Err         string
		}{
			Status:      string(buildStatus.Reason),
			UpdatedTime: buildStatus.UpdatedAt,
			Out:         string(buildStatus.CmdOut),
			Err:         fmt.Sprintf("%v", buildStatus.CmdErr),
		}
		h := w.Header()
		h.Set("Content-Type", "application/json")
		return json.NewEncoder(w).Encode(statusResponse)
	}
}
