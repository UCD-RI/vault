package command

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/kr/pretty"
	"github.com/mitchellh/cli"
	"github.com/posener/complete"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/command/agent/auth"
	"github.com/hashicorp/vault/command/agent/auth/alicloud"
	"github.com/hashicorp/vault/command/agent/auth/approle"
	"github.com/hashicorp/vault/command/agent/auth/aws"
	"github.com/hashicorp/vault/command/agent/auth/azure"
	"github.com/hashicorp/vault/command/agent/auth/gcp"
	"github.com/hashicorp/vault/command/agent/auth/jwt"
	"github.com/hashicorp/vault/command/agent/auth/kubernetes"
	"github.com/hashicorp/vault/command/agent/cache"
	"github.com/hashicorp/vault/command/agent/config"
	"github.com/hashicorp/vault/command/agent/sink"
	"github.com/hashicorp/vault/command/agent/sink/file"
	gatedwriter "github.com/hashicorp/vault/helper/gated-writer"
	"github.com/hashicorp/vault/helper/jsonutil"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/helper/parseutil"
	"github.com/hashicorp/vault/helper/reload"
	"github.com/hashicorp/vault/helper/tlsutil"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/version"
)

var _ cli.Command = (*AgentCommand)(nil)
var _ cli.CommandAutocomplete = (*AgentCommand)(nil)

type AgentCommand struct {
	*BaseCommand

	ShutdownCh chan struct{}
	SighupCh   chan struct{}

	logWriter io.Writer
	logGate   *gatedwriter.Writer
	logger    log.Logger

	cleanupGuard sync.Once

	startedCh chan (struct{}) // for tests

	flagConfigs  []string
	flagLogLevel string

	flagTestVerifyOnly bool
	flagCombineLogs    bool
}

func (c *AgentCommand) Synopsis() string {
	return "Start a Vault agent"
}

func (c *AgentCommand) Help() string {
	helpText := `
Usage: vault agent [options]

  This command starts a Vault agent that can perform automatic authentication
  in certain environments.

  Start an agent with a configuration file:

      $ vault agent -config=/etc/vault/config.hcl

  For a full list of examples, please see the documentation.

` + c.Flags().Help()
	return strings.TrimSpace(helpText)
}

func (c *AgentCommand) Flags() *FlagSets {
	set := c.flagSet(FlagSetHTTP)

	f := set.NewFlagSet("Command Options")

	f.StringSliceVar(&StringSliceVar{
		Name:   "config",
		Target: &c.flagConfigs,
		Completion: complete.PredictOr(
			complete.PredictFiles("*.hcl"),
			complete.PredictFiles("*.json"),
		),
		Usage: "Path to a configuration file. This configuration file should " +
			"contain only agent directives.",
	})

	f.StringVar(&StringVar{
		Name:       "log-level",
		Target:     &c.flagLogLevel,
		Default:    "info",
		EnvVar:     "VAULT_LOG_LEVEL",
		Completion: complete.PredictSet("trace", "debug", "info", "warn", "err"),
		Usage: "Log verbosity level. Supported values (in order of detail) are " +
			"\"trace\", \"debug\", \"info\", \"warn\", and \"err\".",
	})

	// Internal-only flags to follow.
	//
	// Why hello there little source code reader! Welcome to the Vault source
	// code. The remaining options are intentionally undocumented and come with
	// no warranty or backwards-compatability promise. Do not use these flags
	// in production. Do not build automation using these flags. Unless you are
	// developing against Vault, you should not need any of these flags.

	// TODO: should the below flags be public?
	f.BoolVar(&BoolVar{
		Name:    "combine-logs",
		Target:  &c.flagCombineLogs,
		Default: false,
		Hidden:  true,
	})

	f.BoolVar(&BoolVar{
		Name:    "test-verify-only",
		Target:  &c.flagTestVerifyOnly,
		Default: false,
		Hidden:  true,
	})

	// End internal-only flags.

	return set
}

func (c *AgentCommand) AutocompleteArgs() complete.Predictor {
	return complete.PredictNothing
}

func (c *AgentCommand) AutocompleteFlags() complete.Flags {
	return c.Flags().Completions()
}

func (c *AgentCommand) Run(args []string) int {
	f := c.Flags()

	if err := f.Parse(args); err != nil {
		c.UI.Error(err.Error())
		return 1
	}

	// Create a logger. We wrap it in a gated writer so that it doesn't
	// start logging too early.
	c.logGate = &gatedwriter.Writer{Writer: os.Stderr}
	c.logWriter = c.logGate
	if c.flagCombineLogs {
		c.logWriter = os.Stdout
	}
	var level log.Level
	c.flagLogLevel = strings.ToLower(strings.TrimSpace(c.flagLogLevel))
	switch c.flagLogLevel {
	case "trace":
		level = log.Trace
	case "debug":
		level = log.Debug
	case "notice", "info", "":
		level = log.Info
	case "warn", "warning":
		level = log.Warn
	case "err", "error":
		level = log.Error
	default:
		c.UI.Error(fmt.Sprintf("Unknown log level: %s", c.flagLogLevel))
		return 1
	}

	if c.logger == nil {
		c.logger = logging.NewVaultLoggerWithWriter(c.logWriter, level)
	}

	// Validation
	if len(c.flagConfigs) != 1 {
		c.UI.Error("Must specify exactly one config path using -config")
		return 1
	}

	// Load the configuration
	config, err := config.LoadConfig(c.flagConfigs[0], c.logger)
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error loading configuration from %s: %s", c.flagConfigs[0], err))
		return 1
	}

	// Ensure at least one config was found.
	if config == nil {
		c.UI.Output(wrapAtLength(
			"No configuration read. Please provide the configuration with the " +
				"-config flag."))
		return 1
	}
	if config.AutoAuth == nil {
		c.UI.Error("No auto_auth block found in config file")
		return 1
	}

	infoKeys := make([]string, 0, 10)
	info := make(map[string]string)
	info["log level"] = c.flagLogLevel
	infoKeys = append(infoKeys, "log level")

	infoKeys = append(infoKeys, "version")
	verInfo := version.GetVersion()
	info["version"] = verInfo.FullVersionNumber(false)
	if verInfo.Revision != "" {
		info["version sha"] = strings.Trim(verInfo.Revision, "'")
		infoKeys = append(infoKeys, "version sha")
	}
	infoKeys = append(infoKeys, "cgo")
	info["cgo"] = "disabled"
	if version.CgoEnabled {
		info["cgo"] = "enabled"
	}

	// Server configuration output
	padding := 24
	sort.Strings(infoKeys)
	c.UI.Output("==> Vault agent configuration:\n")
	for _, k := range infoKeys {
		c.UI.Output(fmt.Sprintf(
			"%s%s: %s",
			strings.Repeat(" ", padding-len(k)),
			strings.Title(k),
			info[k]))
	}
	c.UI.Output("")

	// Tests might not want to start a vault server and just want to verify
	// the configuration.
	if c.flagTestVerifyOnly {
		if os.Getenv("VAULT_TEST_VERIFY_ONLY_DUMP_CONFIG") != "" {
			c.UI.Output(fmt.Sprintf(
				"\nConfiguration:\n%s\n",
				pretty.Sprint(*config)))
		}
		return 0
	}

	client, err := c.Client()
	if err != nil {
		c.UI.Error(fmt.Sprintf(
			"Error fetching client: %v",
			err))
		return 1
	}

	ctx, cancelFunc := context.WithCancel(context.Background())

	var sinks []*sink.SinkConfig
	for _, sc := range config.AutoAuth.Sinks {
		switch sc.Type {
		case "file":
			config := &sink.SinkConfig{
				Logger:  c.logger.Named("sink.file"),
				Config:  sc.Config,
				Client:  client,
				WrapTTL: sc.WrapTTL,
				DHType:  sc.DHType,
				DHPath:  sc.DHPath,
				AAD:     sc.AAD,
			}
			s, err := file.NewFileSink(config)
			if err != nil {
				c.UI.Error(errwrap.Wrapf("Error creating file sink: {{err}}", err).Error())
				return 1
			}
			config.Sink = s
			sinks = append(sinks, config)
		default:
			c.UI.Error(fmt.Sprintf("Unknown sink type %q", sc.Type))
			return 1
		}
	}

	var method auth.AuthMethod
	authConfig := &auth.AuthConfig{
		Logger:    c.logger.Named(fmt.Sprintf("auth.%s", config.AutoAuth.Method.Type)),
		MountPath: config.AutoAuth.Method.MountPath,
		Config:    config.AutoAuth.Method.Config,
	}
	switch config.AutoAuth.Method.Type {
	case "alicloud":
		method, err = alicloud.NewAliCloudAuthMethod(authConfig)
	case "aws":
		method, err = aws.NewAWSAuthMethod(authConfig)
	case "azure":
		method, err = azure.NewAzureAuthMethod(authConfig)
	case "gcp":
		method, err = gcp.NewGCPAuthMethod(authConfig)
	case "jwt":
		method, err = jwt.NewJWTAuthMethod(authConfig)
	case "kubernetes":
		method, err = kubernetes.NewKubernetesAuthMethod(authConfig)
	case "approle":
		method, err = approle.NewApproleAuthMethod(authConfig)
	default:
		c.UI.Error(fmt.Sprintf("Unknown auth method %q", config.AutoAuth.Method.Type))
		return 1
	}
	if err != nil {
		c.UI.Error(errwrap.Wrapf(fmt.Sprintf("Error creating %s auth method: {{err}}", config.AutoAuth.Method.Type), err).Error())
		return 1
	}

	// Output the header that the server has started
	if !c.flagCombineLogs {
		c.UI.Output("==> Vault server started! Log data will stream in below:\n")
	}

	// Inform any tests that the server is ready
	select {
	case c.startedCh <- struct{}{}:
	default:
	}

	ss := sink.NewSinkServer(&sink.SinkServerConfig{
		Logger:        c.logger.Named("sink.server"),
		Client:        client,
		ExitAfterAuth: config.ExitAfterAuth,
	})

	ah := auth.NewAuthHandler(&auth.AuthHandlerConfig{
		Logger:                       c.logger.Named("auth.handler"),
		Client:                       c.client,
		WrapTTL:                      config.AutoAuth.Method.WrapTTL,
		EnableReauthOnNewCredentials: config.AutoAuth.EnableReauthOnNewCredentials,
	})

	// Start auto-auth and sink servers
	go ah.Run(ctx, method)
	go ss.Run(ctx, ah.OutputCh, sinks)

	// Start agent listeners
	var listeners []net.Listener
	if len(config.Cache.Listeners) != 0 {
		listeners, err = serverListeners(config.Cache.Listeners, c.logWriter, c.UI)
		if err != nil {
			c.UI.Error(fmt.Sprintf("Error running listeners: %v", err))
			return 1
		}
	}

	// Initialize cache and indexer
	proxyCache, err := cache.NewCache()
	if err != nil {
		c.UI.Error(fmt.Sprintf("Error creating cache: %v", err))
		return 1
	}

	for _, ln := range listeners {
		mux := http.NewServeMux()
		mux.Handle("/v1/agent/cache-clear", handleCacheClear(proxyCache))
		mux.Handle("/", handleRequest(client, proxyCache))
		go http.Serve(ln, mux)
	}

	// Release the log gate.
	c.logGate.Flush()

	// Write out the PID to the file now that server has successfully started
	if err := c.storePidFile(config.PidFile); err != nil {
		c.UI.Error(fmt.Sprintf("Error storing PID: %s", err))
		return 1
	}

	defer func() {
		if err := c.removePidFile(config.PidFile); err != nil {
			c.UI.Error(fmt.Sprintf("Error deleting the PID file: %s", err))
		}
	}()

	select {
	case <-ss.DoneCh:
		// This will happen if we exit-on-auth
		c.logger.Info("sinks finished, exiting")
	case <-c.ShutdownCh:
		c.UI.Output("==> Vault agent shutdown triggered")
		cancelFunc()
		<-ah.DoneCh
		<-ss.DoneCh
		for _, ln := range listeners {
			ln.Close()
		}
	}

	return 0
}

// storePidFile is used to write out our PID to a file if necessary
func (c *AgentCommand) storePidFile(pidPath string) error {
	// Quit fast if no pidfile
	if pidPath == "" {
		return nil
	}

	// Open the PID file
	pidFile, err := os.OpenFile(pidPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return errwrap.Wrapf("could not open pid file: {{err}}", err)
	}
	defer pidFile.Close()

	// Write out the PID
	pid := os.Getpid()
	_, err = pidFile.WriteString(fmt.Sprintf("%d", pid))
	if err != nil {
		return errwrap.Wrapf("could not write to pid file: {{err}}", err)
	}
	return nil
}

// removePidFile is used to cleanup the PID file if necessary
func (c *AgentCommand) removePidFile(pidPath string) error {
	if pidPath == "" {
		return nil
	}
	return os.Remove(pidPath)
}

func handleRequest(client *api.Client, proxyCache *cache.Cache) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("req: %#v\n", r)

		cacheKey, err := cache.ComputeCacheKey(r)
		if err != nil {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to compute cache key: {{err}}", err))
			return
		}

		// Attempt to get a cached response for this cache key before forwarding the request
		data, err := proxyCache.Get(client.Token(), cacheKey)
		if err != nil {
			fmt.Println("error getting cached request:", err)
			w.WriteHeader(400)
			return
		}
		if data != nil {
			fmt.Println("got cached request!")
			fmt.Println(string(data.Data))
			return
		}

		fmt.Println("forwarding request...")

		// Secret is not present in the cache. Forward the request to Vault.
		fwReq := client.NewRequest(r.Method, r.URL.Path)

		var out map[string]interface{}
		err = jsonutil.DecodeJSONFromReader(r.Body, &out)
		if err != nil && err != io.EOF {
			respondError(w, http.StatusInternalServerError, errwrap.Wrapf("failed to decode request: {{err}}", err))
			return
		}

		fwReq.SetJSONBody(out)

		ctx, cancelFunc := context.WithCancel(context.Background())
		defer cancelFunc()

		resp, err := client.RawRequestWithContext(ctx, fwReq)
		if resp != nil {
			defer resp.Body.Close()
		}
		if err != nil {
			respondError(w, http.StatusInternalServerError, err)
			return
		}

		// Cache the response
		// TODO: Cache the actual body
		if err := proxyCache.Insert(cacheKey, client.Token(), nil); err != nil {
			fmt.Println("could not insert into cache", err)
			return
		}

		// Write the forwarded response to the response writer
		// TODO: Return an actual response

		// copyHeader(w.Header(), header)
		// w.WriteHeader(status)
		// w.Write()

		return
	})
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func handleCacheClear(proxyCache *cache.Cache) http.Handler {
	type request struct {
		Type string `json:"type"`
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req := new(request)

		err := jsonutil.DecodeJSONFromReader(r.Body, req)
		if err != nil && err != io.EOF {
			w.WriteHeader(400)
			return
		}

		// TODO: Cache the secret

		// TODO: Renew the secret

		// Return the response to the client
		return
	})
}

// rmListener is an implementation of net.Listener that forwards most
// calls to the listener but also removes a file as part of the close. We
// use this to cleanup the unix domain socket on close.
type rmListener struct {
	net.Listener
	Path string
}

func (l *rmListener) Close() error {
	// Close the listener itself
	if err := l.Listener.Close(); err != nil {
		return err
	}

	// Remove the file
	return os.Remove(l.Path)
}

func serverListeners(lnConfigs []*config.Listener, logger io.Writer, ui cli.Ui) ([]net.Listener, error) {
	var listeners []net.Listener
	var listener net.Listener
	var err error
	for _, lnConfig := range lnConfigs {
		switch lnConfig.Type {
		case "unix":
			listener, _, _, err = unixSocketListener(lnConfig.Config, logger, ui)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, listener)
		case "tcp":
			listener, _, _, err := tcpListener(lnConfig.Config, logger, ui)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, listener)
		default:
			return nil, fmt.Errorf("unsupported listener type: %q", lnConfig.Type)
		}
	}

	return listeners, nil
}

func unixSocketListener(config map[string]interface{}, _ io.Writer, ui cli.Ui) (net.Listener, map[string]string, reload.ReloadFunc, error) {
	addr, ok := config["address"].(string)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid address: %v", config["address"])
	}

	if addr == "" {
		return nil, nil, nil, fmt.Errorf("address field should point to socket file path")
	}

	// Remove the socket file as it shouldn't exist for the domain socket to
	// work
	err := os.Remove(addr)
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, nil, fmt.Errorf("failed to remove the socket file: %v", err)
	}

	listener, err := net.Listen("unix", addr)
	if err != nil {
		return nil, nil, nil, err
	}

	// Wrap the listener in rmListener so that the Unix domain socket file is
	// removed on close.
	listener = &rmListener{
		Listener: listener,
		Path:     addr,
	}

	props := map[string]string{"addr": addr}

	return listenerWrapTLS(listener, props, config, ui)
}

func tcpListener(config map[string]interface{}, _ io.Writer, ui cli.Ui) (net.Listener, map[string]string, reload.ReloadFunc, error) {
	bindProto := "tcp"
	var addr string
	addrRaw, ok := config["address"]
	if !ok {
		addr = "127.0.0.1:8300"
	} else {
		addr = addrRaw.(string)
	}

	// If they've passed 0.0.0.0, we only want to bind on IPv4
	// rather than golang's dual stack default
	if strings.HasPrefix(addr, "0.0.0.0:") {
		bindProto = "tcp4"
	}

	ln, err := net.Listen(bindProto, addr)
	if err != nil {
		return nil, nil, nil, err
	}

	ln = tcpKeepAliveListener{ln.(*net.TCPListener)}

	props := map[string]string{"addr": addr}

	return listenerWrapTLS(ln, props, config, ui)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
//
// This is copied directly from the Go source code.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}

func listenerWrapTLS(
	ln net.Listener,
	props map[string]string,
	config map[string]interface{},
	ui cli.Ui) (net.Listener, map[string]string, reload.ReloadFunc, error) {
	props["tls"] = "disabled"

	if v, ok := config["tls_disable"]; ok {
		disabled, err := parseutil.ParseBool(v)
		if err != nil {
			return nil, nil, nil, errwrap.Wrapf("invalid value for 'tls_disable': {{err}}", err)
		}
		if disabled {
			return ln, props, nil, nil
		}
	}

	certFileRaw, ok := config["tls_cert_file"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("'tls_cert_file' must be set")
	}
	certFile := certFileRaw.(string)
	keyFileRaw, ok := config["tls_key_file"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("'tls_key_file' must be set")
	}
	keyFile := keyFileRaw.(string)

	cg := reload.NewCertificateGetter(certFile, keyFile, "")
	if err := cg.Reload(config); err != nil {
		// We try the key without a passphrase first and if we get an incorrect
		// passphrase response, try again after prompting for a passphrase
		if errwrap.Contains(err, x509.IncorrectPasswordError.Error()) {
			var passphrase string
			passphrase, err = ui.AskSecret(fmt.Sprintf("Enter passphrase for %s:", keyFile))
			if err == nil {
				cg = reload.NewCertificateGetter(certFile, keyFile, passphrase)
				if err = cg.Reload(config); err == nil {
					goto PASSPHRASECORRECT
				}
			}
		}
		return nil, nil, nil, errwrap.Wrapf("error loading TLS cert: {{err}}", err)
	}

PASSPHRASECORRECT:
	var tlsvers string
	tlsversRaw, ok := config["tls_min_version"]
	if !ok {
		tlsvers = "tls12"
	} else {
		tlsvers = tlsversRaw.(string)
	}

	tlsConf := &tls.Config{}
	tlsConf.GetCertificate = cg.GetCertificate
	tlsConf.NextProtos = []string{"h2", "http/1.1"}
	tlsConf.MinVersion, ok = tlsutil.TLSLookup[tlsvers]
	if !ok {
		return nil, nil, nil, fmt.Errorf("'tls_min_version' value %q not supported, please specify one of [tls10,tls11,tls12]", tlsvers)
	}
	tlsConf.ClientAuth = tls.RequestClientCert

	if v, ok := config["tls_cipher_suites"]; ok {
		ciphers, err := tlsutil.ParseCiphers(v.(string))
		if err != nil {
			return nil, nil, nil, errwrap.Wrapf("invalid value for 'tls_cipher_suites': {{err}}", err)
		}
		tlsConf.CipherSuites = ciphers
	}
	if v, ok := config["tls_prefer_server_cipher_suites"]; ok {
		preferServer, err := parseutil.ParseBool(v)
		if err != nil {
			return nil, nil, nil, errwrap.Wrapf("invalid value for 'tls_prefer_server_cipher_suites': {{err}}", err)
		}
		tlsConf.PreferServerCipherSuites = preferServer
	}
	var requireVerifyCerts bool
	var err error
	if v, ok := config["tls_require_and_verify_client_cert"]; ok {
		requireVerifyCerts, err = parseutil.ParseBool(v)
		if err != nil {
			return nil, nil, nil, errwrap.Wrapf("invalid value for 'tls_require_and_verify_client_cert': {{err}}", err)
		}
		if requireVerifyCerts {
			tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		}
		if tlsClientCaFile, ok := config["tls_client_ca_file"]; ok {
			caPool := x509.NewCertPool()
			data, err := ioutil.ReadFile(tlsClientCaFile.(string))
			if err != nil {
				return nil, nil, nil, errwrap.Wrapf("failed to read tls_client_ca_file: {{err}}", err)
			}

			if !caPool.AppendCertsFromPEM(data) {
				return nil, nil, nil, fmt.Errorf("failed to parse CA certificate in tls_client_ca_file")
			}
			tlsConf.ClientCAs = caPool
		}
	}
	if v, ok := config["tls_disable_client_certs"]; ok {
		disableClientCerts, err := parseutil.ParseBool(v)
		if err != nil {
			return nil, nil, nil, errwrap.Wrapf("invalid value for 'tls_disable_client_certs': {{err}}", err)
		}
		if disableClientCerts && requireVerifyCerts {
			return nil, nil, nil, fmt.Errorf("'tls_disable_client_certs' and 'tls_require_and_verify_client_cert' are mutually exclusive")
		}
		if disableClientCerts {
			tlsConf.ClientAuth = tls.NoClientCert
		}
	}

	ln = tls.NewListener(ln, tlsConf)
	props["tls"] = "enabled"
	return ln, props, cg.Reload, nil
}

func respondError(w http.ResponseWriter, status int, err error) {
	logical.AdjustErrorStatusCode(&status, err)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	resp := &vaulthttp.ErrorResponse{Errors: make([]string, 0, 1)}
	if err != nil {
		resp.Errors = append(resp.Errors, err.Error())
	}

	enc := json.NewEncoder(w)
	enc.Encode(resp)
}

func respondOk(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if body == nil {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusOK)
		enc := json.NewEncoder(w)
		enc.Encode(body)
	}
}
