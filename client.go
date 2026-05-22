package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type client struct {
	baseURL string
	token   string
	http    *http.Client
	verbose bool
}

type page struct {
	Total  int               `json:"total"`
	Offset int               `json:"offset"`
	Limit  int               `json:"limit"`
	Data   []json.RawMessage `json:"data"`
}

func (c *client) urlFor(entity string, q url.Values, offset, limit int) string {
	qq := cloneValues(q)
	qq.Set("offset", strconv.Itoa(offset))
	qq.Set("limit", strconv.Itoa(limit))
	path := entity
	if !strings.HasPrefix(path, "v1/") && !strings.HasPrefix(path, "/v1/") {
		path = "v1/" + path
	}
	path = strings.TrimLeft(path, "/")
	return fmt.Sprintf("%s/%s?%s", c.baseURL, path, qq.Encode())
}

func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

// doGET issues a GET with retries on 429/5xx and returns the response body.
// On 4xx (non-429) it returns an error containing a snippet of the body.
func (c *client) doGET(ctx context.Context, urlStr string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoffDelay(attempt)):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", userAgent())

		if c.verbose {
			fmt.Fprintln(os.Stderr, "GET", urlStr)
		}

		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			lastErr = fmt.Errorf("http %d: %s", resp.StatusCode, snippet(body))
			if c.verbose {
				fmt.Fprintln(os.Stderr, "retryable:", lastErr)
			}
			continue
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("http %d: %s", resp.StatusCode, snippet(body))
		}
		return body, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("exhausted retries")
	}
	return nil, lastErr
}

func backoffDelay(attempt int) time.Duration {
	return time.Duration(1<<attempt) * 250 * time.Millisecond
}

func snippet(b []byte) string {
	if len(b) > 512 {
		b = b[:512]
	}
	return strings.TrimSpace(string(b))
}

func (c *client) fetchPage(ctx context.Context, urlStr string) (*page, error) {
	body, err := c.doGET(ctx, urlStr)
	if err != nil {
		return nil, err
	}
	var p page
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &p, nil
}

// paginate walks pages sequentially starting at offset, calling emit for each
// record, until max records have been emitted or the server reports no more
// data. max == 0 means "all".
func (c *client) paginate(
	ctx context.Context,
	entity string,
	base url.Values,
	startOffset, limit, max int,
	emit func(json.RawMessage) error,
) error {
	emitted := 0
	offset := startOffset
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		thisLimit := limit
		if max > 0 && emitted+thisLimit > max {
			thisLimit = max - emitted
		}
		if thisLimit <= 0 {
			return nil
		}

		u := c.urlFor(entity, base, offset, thisLimit)
		p, err := c.fetchPage(ctx, u)
		if err != nil {
			return err
		}

		for _, item := range p.Data {
			if err := emit(item); err != nil {
				return err
			}
			emitted++
			if max > 0 && emitted >= max {
				return nil
			}
		}

		if len(p.Data) == 0 {
			return nil
		}
		if p.Total > 0 && offset+len(p.Data) >= p.Total {
			return nil
		}
		if len(p.Data) < thisLimit {
			return nil
		}

		offset += len(p.Data)
	}
}
