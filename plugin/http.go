package plugin

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// TODO: Make these config options.
const EX_MAX_RETRY = 5
const EX_RETRY_INTERVAL = 2

const HUB_CERT_PATH = "/openhorizon/certs/hub.crt"

// Create an https connection, using a supplied SSL CA certificate.
func NewHTTPClient() (*http.Client, error) {

	// Consume the openhorizon hub certificate
	var err error
	var caBytes []byte
	var tlsConf tls.Config

	if _, err = os.Stat(HUB_CERT_PATH); err == nil {

		caBytes, err = ioutil.ReadFile(HUB_CERT_PATH)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("unable to read %v, error %v", HUB_CERT_PATH, err))
		}

		// Setup the TLS confif if there is a cert.
		tlsConf.InsecureSkipVerify = false

		// Do not allow negotiation to previous versions of TLS.
		tlsConf.MinVersion = tls.VersionTLS12

		certPool := x509.NewCertPool()

		certPool.AppendCertsFromPEM(caBytes)
		tlsConf.RootCAs = certPool

		tlsConf.BuildNameToCertificate()
	}

	return &http.Client{
		// remember that this timouet is for the whole request, including
		// body reading. This means that you must set the timeout according
		// to the total payload size you expect
		Timeout: time.Second * time.Duration(20),
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   60 * time.Second,
				KeepAlive: 120 * time.Second,
			}).Dial,
			// TLSHandshakeTimeout:   20 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			ExpectContinueTimeout: 8 * time.Second,
			MaxIdleConns:          20,
			IdleConnTimeout:       120 * time.Second,
			TLSClientConfig:       &tlsConf,
		},
	}, nil

}

// Common function to invoke the Exchange API with builtin retry logic.
func (o *ohAuthPlugin) InvokeExchangeWithRetry(url string, user string, pw string) (*http.Response, error) {
	var currRetry int
	var resp *http.Response
	var err error
	for currRetry = EX_MAX_RETRY; currRetry > 0; {
		resp, err = o.invokeExchange(url, user, pw)

		// Log the HTTP response code.
		if resp == nil && o.Logger().IsWarn() {
			o.Logger().Warn(ohlog(fmt.Sprintf("received nil response from exchange")))
		}

		if resp != nil && o.Logger().IsInfo() {
			o.Logger().Info(ohlog(fmt.Sprintf("received HTTP code: %d", resp.StatusCode)))
		}

		if err == nil {
			break
		}

		// If the invocation resulted in a retyable network error, log it and retry the exchange invocation.
		if isTransportError(resp, err) {
			// Log the transport error and retry
			if o.Logger().IsWarn() {
				o.Logger().Warn(ohlog(fmt.Sprintf("received transport error, retry...")))
			}

			currRetry--
			time.Sleep(time.Duration(EX_RETRY_INTERVAL) * time.Second)
		} else {
			return resp, err
		}
	}

	if currRetry == 0 {
		return resp, errors.New(fmt.Sprintf("unable to verify %v in the exchange, exceeded %v retries", user, EX_MAX_RETRY))
	}

	return resp, err
}

// Common function to invoke the Exchange API when checking for valid users.
func (o *ohAuthPlugin) invokeExchange(url string, user string, pw string) (*http.Response, error) {

	apiMsg := fmt.Sprintf("%v %v", http.MethodGet, url)

	// Create an outgoing HTTP request for the exchange.
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to create HTTP request for %v, error %v", apiMsg, err))
	}

	// Add the basic auth header so that the exchange will authenticate.
	if user != "" && pw != "" {
		req.SetBasicAuth(user, pw)
		req.Header.Add("Accept", "application/json")
	}
	req.Close = true

	// Send the request to verify the user.
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to send HTTP request for %v, error %v", apiMsg, err))
	} else {
		return resp, nil
	}
}

// Common function to invoke the Vault API.
func (o *ohAuthPlugin) InvokeVault(url string, method string, vaultToken string) (*http.Response, error) {

	apiMsg := fmt.Sprintf("%v %v", method, url)

	// Create an outgoing HTTP request for the vault.
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to create HTTP request for %v, error %v", apiMsg, err))
	}

	req.Header.Add("X-Vault-Token", vaultToken)
	req.Close = true

	// Send the request to the vault.
	resp, err := o.httpClient.Do(req)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("unable to send HTTP request for %v, error %v", apiMsg, err))
	} else {
		return resp, nil
	}
}

// Return true if an exchange invocation resulted in an error that is retryable. In general, errors which
// result from network level problems can be retried due the transient nature of these errors, especially
// if the exchange is under heavy load.
func isTransportError(pResp *http.Response, err error) bool {
	if err != nil {
		if strings.Contains(err.Error(), ": EOF") {
			return true
		}

		l_error_string := strings.ToLower(err.Error())
		if strings.Contains(l_error_string, "time") && strings.Contains(l_error_string, "out") {
			return true
		} else if strings.Contains(l_error_string, "connection") && (strings.Contains(l_error_string, "refused") || strings.Contains(l_error_string, "reset")) {
			return true
		}
	}

	if pResp != nil {
		if pResp.StatusCode == http.StatusBadGateway {
			// 502: bad gateway error
			return true
		} else if pResp.StatusCode == http.StatusGatewayTimeout {
			// 504: gateway timeout
			return true
		} else if pResp.StatusCode == http.StatusServiceUnavailable {
			//503: service unavailable
			return true
		}
	}
	return false
}
