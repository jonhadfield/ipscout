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

func Resolve(name string) (ip netip.Addr, err error) {
	i, err := net.ResolveIPAddr("ip", name)
	if err != nil {
		return
	}

	return netip.ParseAddr(i.String())
}

func NewHTTPClient() *retryablehttp.Client {
	rc := &http.Client{Transport: &http.Transport{}}
	c := retryablehttp.NewClient()
	c.HTTPClient = rc
	c.RetryMax = 2
	c.RetryWaitMin = 2 * time.Second
	c.RetryWaitMax = 5 * time.Second

	return c
}

func MaskSecrets(content string, secret []string) string {
	for _, s := range secret {
		content = strings.ReplaceAll(content, s, strings.Repeat("*", len(s)))
	}

	return content
}

func Request(c *retryablehttp.Client, url string, method string, inHeaders http.Header, secrets []string, timeout time.Duration) (body []byte, headers http.Header, status int, err error) {
	if method == "" {
		err = fmt.Errorf("HTTP method not specified")

		return
	}

	request, err := retryablehttp.NewRequest(method, url, nil)
	if err != nil {
		err = fmt.Errorf("failed to request %s: %w", MaskSecrets(url, secrets), err)

		return
	}

	request.Header = inHeaders

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeout != 0 {
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}

	request = request.WithContext(ctx)

	var resp *http.Response

	resp, err = c.Do(request)
	if err != nil {
		return
	}

	headers = resp.Header

	body, err = GetResponseBody(resp)
	if err != nil {
		err = fmt.Errorf("%w", err)

		return
	}
	defer resp.Body.Close()

	return body, resp.Header, resp.StatusCode, err
}

// GetResourceHeaderValue will make an HTTP request and return the value of the specified header
func GetResourceHeaderValue(client *retryablehttp.Client, url, method, header string, secrets []string) (result string, err error) {
	if header == "" {
		return "", fmt.Errorf("header must not be empty")
	}

	_, response, _, err := Request(client, url, method, nil, secrets, 30*time.Second)

	return response.Get(header), err
}

type pathInfo struct {
	exists, parentExists, isDir bool
	parent                      string
	mode                        os.FileMode
}

func getPathInfo(p string) (pathInfo, error) {
	info, err := os.Stat(p)
	if err == nil {
		parent := p
		if !info.IsDir() {
			parent = filepath.Dir(p)
		}
		return pathInfo{
			exists:       true,
			parentExists: true,
			isDir:        info.IsDir(),
			parent:       parent,
			mode:         info.Mode(),
		}, nil
	}
	if !os.IsNotExist(err) {
		return pathInfo{}, err
	}

	parent := filepath.Dir(p)
	info, perr := os.Stat(parent)
	if perr != nil {
		if os.IsNotExist(perr) {
			return pathInfo{exists: false, parentExists: false}, nil
		}
		return pathInfo{}, perr
	}

	return pathInfo{
		exists:       false,
		parentExists: true,
		parent:       parent,
		mode:         info.Mode(),
	}, nil
}

func DownloadFile(client *retryablehttp.Client, u, path string) (string, error) {
	if u == "" {
		return "", fmt.Errorf("url must not be empty")
	}

	logrus.Debugf("%s | downloading: %s to %s", pflog.GetFunctionName(), u, path)

	info, err := getPathInfo(path)
	if err != nil {
		return "", err
	}

	switch {
	case info.exists && info.isDir:
		pU, err := url.Parse(u)
		if err != nil {
			return "", err
		}
		path = filepath.Join(path, filepath.Base(pU.Path))
	case info.exists || info.parentExists:
		// path is valid as provided
	default:
		return "", fmt.Errorf("parent directory does not exist")
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

func RequestContentDispositionFileName(httpClient *retryablehttp.Client, url string, secrets []string) (filename string, err error) {
	logrus.Debugf("requesting filename %s", MaskSecrets(url, secrets))

	contentDispHeader, err := GetResourceHeaderValue(
		httpClient, url, http.MethodHead, "Content-Disposition", secrets,
	)
	if err != nil {
		return
	}

	_, params, err := mime.ParseMediaType(contentDispHeader)
	if err != nil {
		return "", fmt.Errorf("failed to get Content-Disposition header - %w", err)
	}

	if len(params) == 0 {
		return "", errors.New("failed to get Content-Disposition header")
	}

	return params["filename"], err
}

func GetResponseBody(resp *http.Response) (body []byte, err error) {
	var output io.ReadCloser

	switch resp.Header.Get("Content-Encoding") {
	case "gzip":
		output, err = gzip.NewReader(resp.Body)

		if err != nil {
			return
		}
	default:
		output = resp.Body

		if err != nil {
			return
		}
	}

	buf := new(bytes.Buffer)

	_, err = buf.ReadFrom(output)
	if err != nil {
		return
	}

	body = buf.Bytes()

	return
}
