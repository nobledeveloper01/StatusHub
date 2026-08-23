package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nobledeveloper01/StatusHub/internal/dispatch"
	"github.com/nobledeveloper01/StatusHub/internal/domain"
	"github.com/nobledeveloper01/StatusHub/internal/tunnel"
)

// cmdListen streams live events to a local handler.
//
// The Stripe CLI pattern, and it exists for the same reason: an engineer
// cannot develop against webhooks without a publicly reachable URL, so they
// reach for a tunnel service, or hand-craft payloads from documentation, or
// test in staging with real money. All three are worse than this.
func cmdListen(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("listen", flag.ExitOnError)
	api := fs.String("api", "https://api.statushub.dev", "the StatusHub API")
	key := fs.String("key", os.Getenv("STATUSHUB_API_KEY"), "API key; defaults to STATUSHUB_API_KEY")
	forward := fs.String("forward", "", "the local URL to POST each event at, e.g. http://localhost:3000/hooks")
	provider := fs.String("provider", "", "only stream events from this provider")
	statusFlag := fs.String("status", "", "only stream events with this canonical status")
	printOnly := fs.Bool("print", false, "print events instead of forwarding them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return fmt.Errorf("--key is required, or set STATUSHUB_API_KEY")
	}
	if *forward == "" && !*printOnly {
		return fmt.Errorf("--forward is required, or pass --print to see events without forwarding them")
	}

	filter := domain.Filter{}
	if *provider != "" {
		filter.Providers = []string{*provider}
	}
	if *statusFlag != "" {
		st, err := domain.ParseStatus(*statusFlag)
		if err != nil {
			return err
		}
		filter.Statuses = []domain.Status{st}
	}

	c := &listenClient{api: strings.TrimRight(*api, "/"), key: *key, http: &http.Client{
		// Longer than the server's poll, or every long poll would be
		// cancelled by our own client just before the server answered.
		Timeout: tunnel.MaxWait + 20*time.Second,
	}}

	session, err := c.start(ctx, *forward, filter)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "listening as %s\n", session)
	if *forward != "" {
		fmt.Fprintf(os.Stderr, "forwarding to %s\n", *forward)
	}
	fmt.Fprintf(os.Stderr, "your real destinations keep receiving everything; this is a copy.\n")
	fmt.Fprintf(os.Stderr, "press Ctrl-C to stop.\n\n")

	// Ctrl-C stops the session server-side rather than leaving it to time
	// out, so an operator looking at the listen list sees the truth.
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = c.stop(cleanup, session)
	}()

	local := &http.Client{Timeout: 30 * time.Second}
	var delivered, failed int

	for ctx.Err() == nil {
		deliveries, queued, err := c.poll(ctx, session)
		switch {
		case ctx.Err() != nil:
			fmt.Fprintf(os.Stderr, "\nstopped. %d forwarded, %d failed.\n", delivered, failed)
			return nil
		case err != nil:
			// A transient API error must not end the session: a developer's
			// wifi dropping for ten seconds should not require them to
			// restart and lose their place.
			fmt.Fprintf(os.Stderr, "  poll failed (%v); retrying\n", err)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(2 * time.Second):
			}
			continue
		}

		if queued > 20 {
			// Said before events start being dropped from the back of the
			// queue, rather than after.
			fmt.Fprintf(os.Stderr, "  %d events queued — your handler is falling behind\n", queued)
		}

		var outcomes []tunnel.Outcome
		for _, d := range deliveries {
			if *printOnly {
				fmt.Printf("%s  %-12s %-22s %s\n", time.Now().Format("15:04:05"),
					d.Provider, d.EventType, string(d.Payload))
				delivered++
				outcomes = append(outcomes, tunnel.Outcome{EventID: d.EventID, StatusCode: 200})
				continue
			}

			start := time.Now()
			status, err := postLocal(ctx, local, *forward, d)
			took := time.Since(start)

			o := tunnel.Outcome{EventID: d.EventID, StatusCode: status, Duration: took}
			switch {
			case err != nil:
				failed++
				o.Error = err.Error()
				fmt.Printf("%s  %-12s %-22s  %v\n", time.Now().Format("15:04:05"), d.Provider, d.EventType, err)
			case status >= 200 && status < 300:
				delivered++
				fmt.Printf("%s  %-12s %-22s  %d in %s\n", time.Now().Format("15:04:05"),
					d.Provider, d.EventType, status, took.Round(time.Millisecond))
			default:
				failed++
				fmt.Printf("%s  %-12s %-22s  %d in %s\n", time.Now().Format("15:04:05"),
					d.Provider, d.EventType, status, took.Round(time.Millisecond))
			}
			outcomes = append(outcomes, o)
		}

		if len(outcomes) > 0 {
			// Reported so the CLI's tally and the dashboard's agree.
			if err := c.report(ctx, session, outcomes); err != nil {
				fmt.Fprintf(os.Stderr, "  could not report outcomes: %v\n", err)
			}
		}
	}
	fmt.Fprintf(os.Stderr, "\nstopped. %d forwarded, %d failed.\n", delivered, failed)
	return nil
}

// postLocal forwards one event, with the same headers a real destination
// receives — including the signature, so the developer's verification code is
// exercised rather than skipped.
func postLocal(ctx context.Context, client *http.Client, url string, d tunnel.Delivery) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(d.Payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(dispatch.SignatureHeader, d.Signature)
	req.Header.Set("X-StatusHub-Event-Id", d.EventID)
	req.Header.Set("Idempotency-Key", d.EventID)
	// Marked, so a handler can tell a local development delivery from the
	// real one it will also receive.
	req.Header.Set("X-StatusHub-Forwarded-By", "statushubctl-listen")

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, nil
}

type listenClient struct {
	api  string
	key  string
	http *http.Client
}

func (c *listenClient) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.key)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusGone {
		return fmt.Errorf("the listen session expired; restart `statushubctl listen`")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf("%s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *listenClient) start(ctx context.Context, forward string, filter domain.Filter) (string, error) {
	var out struct {
		SessionID string `json:"session_id"`
	}
	err := c.do(ctx, http.MethodPost, "/v1/listen",
		map[string]any{"forward": forward, "filter": filter}, &out)
	return out.SessionID, err
}

func (c *listenClient) poll(ctx context.Context, session string) ([]tunnel.Delivery, int, error) {
	var out struct {
		Deliveries []tunnel.Delivery `json:"deliveries"`
		Queued     int               `json:"queued"`
	}
	err := c.do(ctx, http.MethodGet, "/v1/listen/"+session+"/poll", nil, &out)
	return out.Deliveries, out.Queued, err
}

func (c *listenClient) report(ctx context.Context, session string, outcomes []tunnel.Outcome) error {
	return c.do(ctx, http.MethodPost, "/v1/listen/"+session+"/report",
		map[string]any{"outcomes": outcomes}, nil)
}

func (c *listenClient) stop(ctx context.Context, session string) error {
	return c.do(ctx, http.MethodDelete, "/v1/listen/"+session, nil, nil)
}
