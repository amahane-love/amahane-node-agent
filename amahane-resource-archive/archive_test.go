package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

func testLimits(input, source, output int64) Limits {
	return Limits{
		MaxInputBytes:  input,
		MaxSourceBytes: source,
		MaxOutputBytes: output,
		MaxEntries:     100_000,
	}
}

func makeSnapshot(t *testing.T, entries []tar.Header, contents map[string]string, trailing string) []byte {
	t.Helper()
	var output bytes.Buffer
	gz := gzip.NewWriter(&output)
	archive := tar.NewWriter(gz)
	for _, header := range entries {
		copyHeader := header
		if body, ok := contents[header.Name]; ok {
			copyHeader.Size = int64(len(body))
		}
		if err := archive.WriteHeader(&copyHeader); err != nil {
			t.Fatal(err)
		}
		if body, ok := contents[header.Name]; ok {
			if _, err := io.WriteString(archive, body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(gz, trailing); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestRepackageRoundTrip(t *testing.T) {
	source := makeSnapshot(t, []tar.Header{
		{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "world/", Typeflag: tar.TypeDir, Mode: 0o755},
		{Name: "world/level.dat", Typeflag: tar.TypeReg, Mode: 0o640},
		{Name: "server.properties", Typeflag: tar.TypeReg, Mode: 0o600},
	}, map[string]string{
		"world/level.dat":   "level-data",
		"server.properties": "motd=test\n",
	}, "")
	var output bytes.Buffer
	result, err := Repackage(context.Background(), bytes.NewReader(source), &output, testLimits(int64(len(source))+1, 1024, 1<<20))
	if err != nil {
		t.Fatalf("Repackage: %v", err)
	}
	if result.SizeBytes != int64(output.Len()) || result.SourceBytes != int64(len("level-data")+len("motd=test\n")) {
		t.Fatalf("result = %+v", result)
	}
	digest := sha256.Sum256(output.Bytes())
	if result.ChecksumSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("checksum = %q", result.ChecksumSHA256)
	}

	decoder, err := zstd.NewReader(bytes.NewReader(output.Bytes()))
	if err != nil {
		t.Fatalf("open zstd archive: %v", err)
	}
	defer decoder.Close()
	tarReader := tar.NewReader(decoder)
	files := make(map[string]string)
	for {
		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read tar entry: %v", err)
		}
		if header.Typeflag == tar.TypeReg {
			data, err := io.ReadAll(tarReader)
			if err != nil {
				t.Fatalf("read %q: %v", header.Name, err)
			}
			files[header.Name] = string(data)
		}
	}
	if files["world/level.dat"] != "level-data" || files["server.properties"] != "motd=test\n" {
		t.Fatalf("repacked files = %#v", files)
	}
}

func TestRepackageRejectsUnsafePathsAndEntryTypes(t *testing.T) {
	cases := []struct {
		name   string
		header tar.Header
	}{
		{name: "traversal", header: tar.Header{Name: "../outside", Typeflag: tar.TypeReg, Size: 1}},
		{name: "absolute", header: tar.Header{Name: "/etc/passwd", Typeflag: tar.TypeReg, Size: 1}},
		{name: "backslash", header: tar.Header{Name: `folder\\file`, Typeflag: tar.TypeReg, Size: 1}},
		{name: "symlink", header: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "target"}},
		{name: "special", header: tar.Header{Name: "device", Typeflag: tar.TypeChar}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			contents := map[string]string{}
			if test.header.Size > 0 {
				contents[test.header.Name] = "x"
			}
			source := makeSnapshot(t, []tar.Header{test.header}, contents, "")
			var output bytes.Buffer
			_, err := Repackage(context.Background(), bytes.NewReader(source), &output, testLimits(int64(len(source))+1, 1024, 1<<20))
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestRepackageEnforcesInputSourceOutputAndEntryLimits(t *testing.T) {
	source := makeSnapshot(t, []tar.Header{{Name: "file", Typeflag: tar.TypeReg, Size: 4}}, map[string]string{"file": "data"}, "")
	t.Run("input", func(t *testing.T) {
		var output bytes.Buffer
		limits := testLimits(int64(len(source))-1, 1024, 1<<20)
		_, err := Repackage(context.Background(), bytes.NewReader(source), &output, limits)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})
	t.Run("source", func(t *testing.T) {
		var output bytes.Buffer
		limits := testLimits(int64(len(source))+1, 3, 1<<20)
		_, err := Repackage(context.Background(), bytes.NewReader(source), &output, limits)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})
	t.Run("output", func(t *testing.T) {
		var output bytes.Buffer
		limits := testLimits(int64(len(source))+1, 1024, 1)
		_, err := Repackage(context.Background(), bytes.NewReader(source), &output, limits)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})
	t.Run("entries", func(t *testing.T) {
		multi := makeSnapshot(t, []tar.Header{
			{Name: "one", Typeflag: tar.TypeReg, Size: 1},
			{Name: "two", Typeflag: tar.TypeReg, Size: 1},
		}, map[string]string{"one": "1", "two": "2"}, "")
		var output bytes.Buffer
		limits := testLimits(int64(len(multi))+1, 1024, 1<<20)
		limits.MaxEntries = 1
		_, err := Repackage(context.Background(), bytes.NewReader(multi), &output, limits)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})
}

func TestRepackageVerifiesGzipTrailerAndTarRemainder(t *testing.T) {
	valid := makeSnapshot(t, []tar.Header{{Name: "file", Typeflag: tar.TypeReg, Size: 1}}, map[string]string{"file": "x"}, "")
	corruptTrailer := append([]byte(nil), valid...)
	corruptTrailer[len(corruptTrailer)-1] ^= 0xff
	withNonzeroTrailingData := makeSnapshot(t, nil, nil, "unexpected data")
	withZeroPadding := makeSnapshot(t, nil, nil, "\x00\x00\x00")

	for name, source := range map[string][]byte{
		"gzip trailer checksum": corruptTrailer,
		"nonzero tar remainder": withNonzeroTrailingData,
	} {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			limits := testLimits(int64(len(source))+1, 1024, 1<<20)
			_, err := Repackage(context.Background(), bytes.NewReader(source), &output, limits)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("error = %v, want ErrInvalid", err)
			}
		})
	}
	t.Run("bounded zero padding accepted", func(t *testing.T) {
		var output bytes.Buffer
		limits := testLimits(int64(len(withZeroPadding))+1, 1024, 1<<20)
		limits.MaxTrailingPaddingBytes = 3
		if _, err := Repackage(context.Background(), bytes.NewReader(withZeroPadding), &output, limits); err != nil {
			t.Fatalf("Repackage: %v", err)
		}
	})
	t.Run("padding limit", func(t *testing.T) {
		var output bytes.Buffer
		limits := testLimits(int64(len(withZeroPadding))+1, 1024, 1<<20)
		limits.MaxTrailingPaddingBytes = 2
		_, err := Repackage(context.Background(), bytes.NewReader(withZeroPadding), &output, limits)
		if !errors.Is(err, ErrTooLarge) {
			t.Fatalf("error = %v, want ErrTooLarge", err)
		}
	})
}

func TestRepackageHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var output bytes.Buffer
	_, err := Repackage(ctx, bytes.NewReader(nil), &output, testLimits(1024, 1024, 1<<20))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
