//go:build windows

package desktop

import (
	"context"
	"errors"

	webview "github.com/webview/webview_go"
)

// Run owns the native desktop window. Closing it ends the WebView message loop,
// which lets the launcher shut down monitoring and the local HTTP server.
func Run(ctx context.Context, title, targetURL string) error {
	w := webview.New(false)
	if w == nil || w.Window() == nil {
		return errors.New("Microsoft Edge WebView2 Runtime is unavailable")
	}
	defer w.Destroy()
	w.SetTitle(title)
	w.SetSize(1040, 700, webview.HintMin)
	w.SetSize(1320, 840, webview.HintNone)
	w.Navigate(targetURL)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			w.Terminate()
		case <-done:
		}
	}()
	w.Run()
	close(done)
	return nil
}
