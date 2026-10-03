package archive

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/klauspost/compress/zstd"
)

const (
	defaultMaxEntries         = 100_000
	defaultMaxTrailingPadding = 1 << 20
)

var (
	ErrInvalid  = errors.New("resource_backup_archive_invalid")
	ErrTooLarge = errors.New("resource_backup_archive_too_large")
)

type Limits struct {
	MaxInputBytes           int64
	MaxSourceBytes          int64
	MaxOutputBytes          int64
	MaxEntries              int
	MaxTrailingPaddingBytes int64
}

type Result struct {
	SizeBytes      int64
	SourceBytes    int64
	ChecksumSHA256 string
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r contextReader) Read(data []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(data)
}

type countWriter struct {
	w io.Writer
	n int64
}

func (w *countWriter) Write(data []byte) (int, error) {
	n, err := w.w.Write(data)
	w.n += int64(n)
	return n, err
}

type limitWriter struct {
	w         io.Writer
	remaining int64
}

func (w *limitWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > w.remaining {
		return 0, ErrTooLarge
	}
	n, err := w.w.Write(data)
	w.remaining -= int64(n)
	return n, err
}

func Repackage(ctx context.Context, src io.Reader, dst io.Writer, limits Limits) (Result, error) {
	if ctx == nil || src == nil || dst == nil {
		return Result{}, ErrInvalid
	}
	if limits.MaxInputBytes <= 0 || limits.MaxInputBytes == int64(^uint64(0)>>1) || limits.MaxSourceBytes <= 0 || limits.MaxOutputBytes <= 0 || limits.MaxEntries < 0 || limits.MaxTrailingPaddingBytes < 0 {
		return Result{}, ErrTooLarge
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	maxPadding := limits.MaxTrailingPaddingBytes
	if maxPadding == 0 {
		maxPadding = defaultMaxTrailingPadding
	}
	maxEntries := limits.MaxEntries
	if maxEntries == 0 {
		maxEntries = defaultMaxEntries
	}

	limitedInput := &io.LimitedReader{R: contextReader{ctx: ctx, r: src}, N: limits.MaxInputBytes + 1}
	gzipReader, err := gzip.NewReader(limitedInput)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if errors.Is(err, ErrTooLarge) {
			return Result{}, ErrTooLarge
		}
		return Result{}, fmt.Errorf("open panel snapshot: %w", ErrInvalid)
	}
	defer gzipReader.Close()

	hasher := sha256.New()
	counted := &countWriter{w: io.MultiWriter(dst, hasher)}
	limitedOutput := &limitWriter{w: counted, remaining: limits.MaxOutputBytes}
	encoder, err := zstd.NewWriter(limitedOutput,
		zstd.WithEncoderConcurrency(1),
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(5)))
	if err != nil {
		return Result{}, fmt.Errorf("create zstd encoder: %w", err)
	}
	tarWriter := tar.NewWriter(encoder)
	tarReader := tar.NewReader(gzipReader)
	seenFiles := make(map[string]struct{})
	seenPaths := make(map[string]struct{})
	hasChildren := make(map[string]struct{})
	var sourceBytes int64
	entries := 0
	buffer := make([]byte, 128<<10)

	closeWriters := func() {
		_ = tarWriter.Close()
		_ = encoder.Close()
	}
	for {
		if err := ctx.Err(); err != nil {
			closeWriters()
			return Result{}, err
		}
		header, nextErr := tarReader.Next()
		if errors.Is(nextErr, io.EOF) {
			if err := verifyGzipRemainder(ctx, gzipReader, maxPadding); err != nil {
				closeWriters()
				return Result{}, err
			}
			break
		}
		if nextErr != nil {
			closeWriters()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Result{}, ctxErr
			}
			return Result{}, fmt.Errorf("read panel snapshot entry: %w", ErrInvalid)
		}
		entries++
		if entries > maxEntries || header.Size < 0 || header.Size > limits.MaxSourceBytes-sourceBytes {
			closeWriters()
			return Result{}, ErrTooLarge
		}
		trailingSlash := strings.HasSuffix(header.Name, "/")
		name, valid := normalizedEntryName(header.Name)
		if !valid || trailingSlash && header.Typeflag != tar.TypeDir {
			closeWriters()
			return Result{}, ErrInvalid
		}
		if name == "." && header.Typeflag == tar.TypeDir {
			continue
		}
		if _, duplicate := seenPaths[name]; duplicate {
			closeWriters()
			return Result{}, ErrInvalid
		}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if _, isFile := seenFiles[parent]; isFile {
				closeWriters()
				return Result{}, ErrInvalid
			}
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				closeWriters()
				return Result{}, ErrInvalid
			}
		case tar.TypeReg, tar.TypeRegA:
			if _, hasChild := hasChildren[name]; hasChild {
				closeWriters()
				return Result{}, ErrInvalid
			}
			seenFiles[name] = struct{}{}
		default:
			closeWriters()
			return Result{}, ErrInvalid
		}
		seenPaths[name] = struct{}{}
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			hasChildren[parent] = struct{}{}
		}
		copyHeader := *header
		copyHeader.Name = name
		copyHeader.PAXRecords = nil
		copyHeader.Xattrs = nil
		copyHeader.Mode &= 0o777
		copyHeader.Format = tar.FormatUnknown
		if header.Typeflag == tar.TypeDir {
			copyHeader.Typeflag = tar.TypeDir
		} else {
			copyHeader.Typeflag = tar.TypeReg
		}
		if err := tarWriter.WriteHeader(&copyHeader); err != nil {
			closeWriters()
			return Result{}, fmt.Errorf("write archive header: %w", err)
		}
		remaining := header.Size
		for remaining > 0 {
			if err := ctx.Err(); err != nil {
				closeWriters()
				return Result{}, err
			}
			chunk := int64(len(buffer))
			if remaining < chunk {
				chunk = remaining
			}
			read, readErr := io.ReadFull(tarReader, buffer[:int(chunk)])
			if read > 0 {
				written, writeErr := tarWriter.Write(buffer[:read])
				sourceBytes += int64(read)
				remaining -= int64(read)
				if writeErr != nil || written != read {
					closeWriters()
					if writeErr != nil {
						return Result{}, fmt.Errorf("write archive data: %w", writeErr)
					}
					return Result{}, io.ErrShortWrite
				}
			}
			if readErr != nil {
				closeWriters()
				if ctxErr := ctx.Err(); ctxErr != nil {
					return Result{}, ctxErr
				}
				return Result{}, fmt.Errorf("read archive data: %w", ErrInvalid)
			}
		}
	}
	if limitedInput.N == 0 {
		closeWriters()
		return Result{}, ErrTooLarge
	}
	if err := tarWriter.Close(); err != nil {
		_ = encoder.Close()
		return Result{}, fmt.Errorf("finish tar archive: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return Result{}, fmt.Errorf("finish zstd archive: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{
		SizeBytes: counted.n, SourceBytes: sourceBytes, ChecksumSHA256: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func verifyGzipRemainder(ctx context.Context, reader io.Reader, maxPadding int64) error {
	buffer := make([]byte, 32<<10)
	var paddingBytes int64
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		read, err := reader.Read(buffer)
		if read > 0 {
			paddingBytes += int64(read)
			if paddingBytes > maxPadding {
				return ErrTooLarge
			}
			for _, value := range buffer[:read] {
				if value != 0 {
					return ErrInvalid
				}
			}
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return ctxErr
			}
			return fmt.Errorf("verify panel snapshot checksum: %w", ErrInvalid)
		}
		if read == 0 {
			return io.ErrNoProgress
		}
	}
}

func normalizedEntryName(value string) (string, bool) {
	if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") {
		return "", false
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	value = strings.TrimSuffix(value, "/")
	clean := path.Clean(value)
	if clean == "." {
		return clean, value == "" || value == "."
	}
	if clean == ".." || strings.HasPrefix(clean, "../") || clean != value {
		return "", false
	}
	return clean, true
}
