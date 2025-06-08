package web

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jonhadfield/ip-fetcher/internal/pflog"

	"github.com/hashicorp/go-retryablehttp"

	"github.com/sirupsen/logrus"
)

func Resolve(name string) (netip.Addr, error) {
	i, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return netip.Addr{}, err
	}

	return netip.ParseAddr(i.String())
}

const (
	defaultRetryMax     = 2
	defaultRetryWaitMin = 2 * time.Second
	defaultRetryWaitMax = 5 * time.Second
	// DefaultRequestTimeout is used for HTTP requests unless otherwise specified
	DefaultRequestTimeout = 10 * time.Second
	// ShortRequestTimeout is used for short HTTP requests
	ShortRequestTimeout = 5 * time.Second
	// LongRequestTimeout is used for lengthy HTTP requests
	LongRequestTimeout = 30 * time.Second
)

func NewHTTPClient() *retryablehttp.Client {
	rc := &http.Client{Transport: &http.Transport{}}
	c := retryablehttp.NewClient()
	c.HTTPClient = rc
	c.RetryMax = defaultRetryMax
	c.RetryWaitMin = defaultRetryWaitMin
	c.RetryWaitMax = defaultRetryWaitMax

	return c
}

func MaskSecrets(content string, secret []string) string {
	for _, s := range secret {
		content = strings.ReplaceAll(content, s, strings.Repeat("*", len(s)))
	}

	return content
}

func Request(c *retryablehttp.Client, url, method string, inHeaders http.Header, secrets []string, timeout time.Duration) ([]byte, http.Header, int, error) {
	if method == "" {
		return nil, nil, 0, errors.New("HTTP method not specified")
	}

	request, err := retryablehttp.NewRequest(method, url, nil)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to request %s: %w", MaskSecrets(url, secrets), err)
	}

	request.Header = inHeaders

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout != 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}

	request = request.WithContext(ctx)

	resp, err := c.Do(request)
	if err != nil {
		return nil, nil, 0, err
	}
	defer resp.Body.Close()

	headers := resp.Header

	body, err := GetResponseBody(resp)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("%w", err)
	}

	return body, headers, resp.StatusCode, nil
}

// GetResourceHeaderValue will make an HTTP request and return the value of the specified header
func GetResourceHeaderValue(client *retryablehttp.Client, url, method, header string, secrets []string) (string, error) {
	if header == "" {
		return "", errors.New("header must not be empty")
	}

	_, response, _, err := Request(client, url, method, nil, secrets, LongRequestTimeout)
	if err != nil {
		return "", err
	}

	return response.Get(header), nil
}

type PathInfo struct {
	Exists, ParentExists, IsDir bool
	Parent                      string
	Mode                        os.FileMode
}

func GetPathInfo(p string) (PathInfo, error) {
	info, err := os.Stat(p)
	if err == nil {
		parent := p
		if !info.IsDir() {
			parent = filepath.Dir(p)
		}
		return PathInfo{
			Exists:       true,
			ParentExists: true,
			IsDir:        info.IsDir(),
			Parent:       parent,
			Mode:         info.Mode(),
		}, nil
	}
	if !os.IsNotExist(err) {
		return PathInfo{}, err
	}

	parent := filepath.Dir(p)
	info, perr := os.Stat(parent)
	if perr != nil {
		if os.IsNotExist(perr) {
			return PathInfo{Exists: false, ParentExists: false}, nil
		}
		return PathInfo{}, perr
	}

	return PathInfo{
		Exists:       false,
		ParentExists: true,
		Parent:       parent,
		Mode:         info.Mode(),
	}, nil
}

func DownloadFile(client *retryablehttp.Client, u, path string) (string, error) {
	if u == "" {
		return "", errors.New("url must not be empty")
	}

	logrus.Debugf("%s | downloading: %s to %s", pflog.GetFunctionName(), u, path)

	info, err := GetPathInfo(path)
	if err != nil {
		return "", err
	}

	switch {
	case info.Exists && info.IsDir:
		pU, err := url.Parse(u)
		if err != nil {
			return "", err
		}
		path = filepath.Join(path, filepath.Base(pU.Path))
	case info.Exists || info.ParentExists:
		// path is valid as provided
	default:
		return "", errors.New("Parent directory does not exist")
	}

	logrus.Infof("downloading %s to %s", u, path)

	resp, err := client.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode > http.StatusMultipleChoices {
		return "", fmt.Errorf("server responded with status %d", resp.StatusCode)
	}

	logrus.Infof("writing to path: %s", path)

	out, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return "", err
	}

	return path, nil
}

func RequestContentDispositionFileName(httpClient *retryablehttp.Client, url string, secrets []string) (string, error) {
	logrus.Debugf("requesting filename %s", MaskSecrets(url, secrets))

	contentDispHeader, err := GetResourceHeaderValue(
		httpClient, url, http.MethodHead, "Content-Disposition", secrets,
	)
	if err != nil {
		return "", err
	}

	_, params, err := mime.ParseMediaType(contentDispHeader)
	if err != nil {
		return "", fmt.Errorf("failed to get Content-Disposition header - %w", err)
	}

	if len(params) == 0 {
		return "", errors.New("failed to get Content-Disposition header")
	}

	return params["filename"], nil
}

func GetResponseBody(resp *http.Response) ([]byte, error) {
	var output io.ReadCloser

	var err error
	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		output, err = gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
	default:
		output = resp.Body
	}

	buf := new(bytes.Buffer)

	if _, err = buf.ReadFrom(output); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
