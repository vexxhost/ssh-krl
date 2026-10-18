// Command ssh-krl publishes an OpenSSH key revocation list (KRL) built from
// revocation entries stored in OpenBao, HashiCorp Vault or a file.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/vexxhost/ssh-krl/internal/server"
	"github.com/vexxhost/ssh-krl/internal/source"
)

var version = "dev"

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envDuration(name string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(name); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

func envBool(name string, def bool) bool {
	if v, ok := os.LookupEnv(name); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ssh-krl:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		listen      = flag.String("listen", env("SSH_KRL_LISTEN", ":8080"), "address to serve HTTP on")
		sourceKind  = flag.String("source", env("SSH_KRL_SOURCE", "kv"), "where revocations are read from: kv or file")
		file        = flag.String("file", env("SSH_KRL_FILE", ""), "file source: path to a YAML or JSON file")
		mount       = flag.String("kv-mount", env("SSH_KRL_KV_MOUNT", "ssh-krl"), "kv source: KV secrets engine mount")
		kvVersion   = flag.Int("kv-version", envInt("SSH_KRL_KV_VERSION", 2), "kv source: KV engine version (1 or 2)")
		prefix      = flag.String("kv-prefix", env("SSH_KRL_KV_PREFIX", "revocations"), "kv source: path under the mount holding one entry per secret")
		authMethod  = flag.String("auth-method", env("SSH_KRL_AUTH_METHOD", "token"), "kv source: token, kubernetes or approle")
		authMount   = flag.String("auth-mount", env("SSH_KRL_AUTH_MOUNT", ""), "kv source: auth method mount path (default: the method name)")
		role        = flag.String("auth-role", env("SSH_KRL_AUTH_ROLE", ""), "kv source: Kubernetes auth role")
		jwtPath     = flag.String("auth-jwt-path", env("SSH_KRL_AUTH_JWT_PATH", ""), "kv source: service account token path for Kubernetes auth")
		roleIDPath  = flag.String("auth-role-id-path", env("SSH_KRL_AUTH_ROLE_ID_PATH", ""), "kv source: file holding the AppRole role ID")
		secretIDPth = flag.String("auth-secret-id-path", env("SSH_KRL_AUTH_SECRET_ID_PATH", ""), "kv source: file holding the AppRole secret ID")
		interval    = flag.Duration("interval", envDuration("SSH_KRL_INTERVAL", 30*time.Second), "how often to refresh from the source")
		skipInvalid = flag.Bool("skip-invalid", envBool("SSH_KRL_SKIP_INVALID", false), "publish valid entries when some are invalid, instead of keeping the last good KRL")
		comment     = flag.String("comment", env("SSH_KRL_COMMENT", "ssh-krl"), "comment stored in the KRL header")
		logFormat   = flag.String("log-format", env("SSH_KRL_LOG_FORMAT", "text"), "log format: text or json")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return nil
	}

	var handler slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logFormat == "json" {
		handler = slog.NewJSONHandler(os.Stderr, nil)
	}
	logger := slog.New(handler)

	var src source.Source
	switch *sourceKind {
	case "file":
		if *file == "" {
			return errors.New("-file is required with -source=file")
		}
		src = &source.File{Path: *file}
	case "kv":
		kv, err := source.NewKV(source.KVConfig{
			Mount:        *mount,
			Version:      *kvVersion,
			Prefix:       *prefix,
			AuthMethod:   *authMethod,
			AuthMount:    *authMount,
			Role:         *role,
			JWTPath:      *jwtPath,
			RoleIDPath:   *roleIDPath,
			SecretIDPath: *secretIDPth,
		})
		if err != nil {
			return err
		}
		src = kv
	default:
		return fmt.Errorf("unknown source %q", *sourceKind)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(server.Config{
		Source:      src,
		Interval:    *interval,
		SkipInvalid: *skipInvalid,
		Comment:     *comment,
		Logger:      logger,
	})
	go srv.Run(ctx)

	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting", "version", version, "listen", *listen, "source", src.String(), "interval", *interval)
		errCh <- httpServer.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpServer.Shutdown(shutdown)
}
