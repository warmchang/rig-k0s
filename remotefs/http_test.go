package remotefs_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/k0sproject/rig/v2/remotefs"
	"github.com/k0sproject/rig/v2/rigtest"
	"github.com/stretchr/testify/require"
)

func TestHTTPStatusInsecureURLValidation(t *testing.T) {
	mr := rigtest.NewMockRunner()
	f := remotefs.NewPosixFS(mr)

	for _, rawURL := range []string{
		"file:///etc/passwd",
		"ftp://example.com",
		"http:///path",
		"/relative/path",
		"http://user:pass@example.com",
		"http://example.com\x00",
	} {
		_, err := remotefs.HTTPStatusInsecure(context.Background(), f, rawURL)
		require.Error(t, err, "expected error for %q", rawURL)
	}
}

func TestPosixHTTPStatusInsecure(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandOutput(rigtest.HasPrefix("curl"), "200")
		f := remotefs.NewPosixFS(mr)
		code, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.NoError(t, err)
		require.Equal(t, 200, code)
		require.Contains(t, mr.LastCommand(), "-k")
	})
	t.Run("503", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandOutput(rigtest.HasPrefix("curl"), "503")
		f := remotefs.NewPosixFS(mr)
		code, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.NoError(t, err)
		require.Equal(t, 503, code)
	})
	t.Run("curl error", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandFailure(rigtest.HasPrefix("curl"), errors.New("exit status 60"))
		f := remotefs.NewPosixFS(mr)
		_, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.Error(t, err)
	})
}

func TestPosixHTTPStatusInsecureWget(t *testing.T) {
	noCurl := errors.New("not found")

	t.Run("200 via wget", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandFailure(rigtest.Equal("command -v curl"), noCurl)
		mr.AddCommandOutput(rigtest.Equal("command -v wget"), "/usr/bin/wget")
		mr.AddCommand(rigtest.HasPrefix("wget"), func(a *rigtest.A) error {
			_, err := fmt.Fprint(a.Stderr, "  HTTP/1.1 200 OK\n")
			return err
		})
		f := remotefs.NewPosixFS(mr)
		code, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.NoError(t, err)
		require.Equal(t, 200, code)
	})

	t.Run("301 via wget", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandFailure(rigtest.Equal("command -v curl"), noCurl)
		mr.AddCommandOutput(rigtest.Equal("command -v wget"), "/usr/bin/wget")
		mr.AddCommand(rigtest.HasPrefix("wget"), func(a *rigtest.A) error {
			_, err := fmt.Fprint(a.Stderr, "  HTTP/1.1 301 Moved Permanently\n")
			return err
		})
		f := remotefs.NewPosixFS(mr)
		code, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.NoError(t, err)
		require.Equal(t, 301, code)
	})

	t.Run("no tools", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.AddCommandFailure(rigtest.Equal("command -v curl"), noCurl)
		mr.AddCommandFailure(rigtest.Equal("command -v wget"), noCurl)
		f := remotefs.NewPosixFS(mr)
		_, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.ErrorIs(t, err, remotefs.ErrHTTPStatusNotSupported)
	})
}

func TestWindowsHTTPStatusInsecure(t *testing.T) {
	t.Run("200", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.Windows = true
		mr.AddCommandOutput(rigtest.HasPrefix("powershell.exe"), "200")
		f := remotefs.NewWindowsFS(mr)
		code, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.NoError(t, err)
		require.Equal(t, 200, code)
	})
	t.Run("failure", func(t *testing.T) {
		mr := rigtest.NewMockRunner()
		mr.Windows = true
		mr.AddCommandFailure(rigtest.HasPrefix("powershell.exe"), errors.New("exit 1"))
		f := remotefs.NewWindowsFS(mr)
		_, err := remotefs.HTTPStatusInsecure(context.Background(), f, "https://example.com/health")
		require.Error(t, err)
	})
}
