package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"
	"golang.org/x/term"

	lib "github.com/ravoni4devs/libcryptus/cryptus"
)

const (
	magic        = "CRYPTUS\n"
	AlgoAES      = "aes"
	AlgoChaCha20 = "chacha20"
	KdfArgon2id  = "argon2id"
	KdfPBKDF2    = "pbkdf2"
)

func main() {
	flags := []cli.Flag{
		&cli.StringFlag{Name: "input", Aliases: []string{"i", "string", "text", "file"}, Required: true},
		&cli.StringFlag{Name: "nonce", Aliases: []string{"salt"}},
		&cli.StringFlag{Name: "out", Aliases: []string{"output", "o"}},
		&cli.IntFlag{Name: "chunk", Value: 1 << 20},
		&cli.StringFlag{Name: "algo", Aliases: []string{"a"}, Value: AlgoAES, Usage: "cipher algorithm: aes|chacha20"},
		&cli.StringFlag{Name: "kdf", Aliases: []string{"k"}, Value: KdfArgon2id, Usage: "key derivation function: argon2id|pbkdf2"},
	}
	cmds := []*cli.Command{
		{
			Name:   "encrypt",
			Flags:  flags,
			Action: func(ctx context.Context, cmd *cli.Command) error { return runApp(cmd) },
		},
		{
			Name:   "decrypt",
			Flags:  flags,
			Action: func(ctx context.Context, cmd *cli.Command) error { return runApp(cmd) },
		},
	}
	root := &cli.Command{Commands: cmds}
	if err := root.Run(context.Background(), os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func runApp(cmd *cli.Command) error {
	name := cmd.Name
	input := cmd.String("input")
	nonceArg := cmd.String("nonce")
	out := cmd.String("out")
	chunk := cmd.Int("chunk")
	algo := strings.ToLower(cmd.String("algo"))
	kdf := strings.ToLower(cmd.String("kdf"))

	if chunk <= 0 {
		return fmt.Errorf("invalid chunk size")
	}
	if err := validateAlgo(algo); err != nil {
		return err
	}
	if err := validateKDF(kdf); err != nil {
		return err
	}

	isFile := fileExists(input)
	isDecrypt := name == "decrypt"

	if isFile {
		return runFile(input, out, nonceArg, chunk, isDecrypt, algo, kdf)
	}
	return runString(input, nonceArg, isDecrypt, algo, kdf)
}

// ---------------- Validation ----------------

func validateAlgo(algo string) error {
	switch algo {
	case AlgoAES, AlgoChaCha20:
		return nil
	default:
		return fmt.Errorf("invalid -algo: %s (use %s|%s)", algo, AlgoAES, AlgoChaCha20)
	}
}

func validateKDF(kdf string) error {
	switch kdf {
	case KdfArgon2id, KdfPBKDF2:
		return nil
	default:
		return fmt.Errorf("invalid -kdf: %s (use %s|%s)", kdf, KdfArgon2id, KdfPBKDF2)
	}
}

// ---------------- String Mode ----------------

func runString(text, nonceArg string, isDecrypt bool, algo, kdf string) error {
	nonceStr, autoNonce := resolveNonceForString(nonceArg, isDecrypt)
	baseNonce, kdfSalt := deriveBaseNonceAndSalt(nonceStr)
	password := promptPassword()
	c := lib.New()
	nonceHex := hex.EncodeToString(baseNonce)

	keyHex, err := deriveKeyHex(c, kdf, password, kdfSalt)
	if err != nil {
		return err
	}

	if isDecrypt {
		if autoNonce {
			return fmt.Errorf("nonce is required for string decryption")
		}
		switch algo {
		case AlgoAES:
			plain, err := c.DecryptAESGCMHex(text, keyHex, nonceHex)
			if err != nil {
				return err
			}
			fmt.Println(plain)
		case AlgoChaCha20:
			plain, err := c.DecryptChaCha20Hex(text, keyHex, nonceHex)
			if err != nil {
				return err
			}
			fmt.Println(plain)
		}
		return nil
	}

	switch algo {
	case AlgoAES:
		ct, err := c.EncryptAESGCMHex(text, keyHex, nonceHex)
		if err != nil {
			return err
		}
		fmt.Println("Encrypted:", ct)
	case AlgoChaCha20:
		ct, err := c.EncryptChaCha20Hex(text, keyHex, nonceHex)
		if err != nil {
			return err
		}
		fmt.Println("Encrypted:", ct)
	}

	if autoNonce {
		fmt.Println("Nonce:", nonceHex)
	}
	return nil
}

// ---------------- File Mode ----------------

func runFile(inPath, outPath, nonceArg string, chunk int, isDecrypt bool, algo, kdf string) error {
	nonceStr, autoNonce := resolveNonceForFile(inPath, nonceArg, isDecrypt)
	baseNonce, kdfSalt := deriveBaseNonceAndSalt(nonceStr)
	password := promptPassword()

	c := lib.New()
	keyHex, err := deriveKeyHex(c, kdf, password, kdfSalt)
	if err != nil {
		return err
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("derived key is not valid hex")
	}

	aead, err := buildAEAD(algo, key)
	if err != nil {
		return err
	}
	if aead.NonceSize() != 12 {
		return fmt.Errorf("unexpected AEAD nonce size (got %d)", aead.NonceSize())
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	if isDecrypt {
		dest := desiredOutputPath(inPath, outPath, true)
		if fileExists(dest) {
			return fmt.Errorf("output file already exists: %s", dest)
		}
		if err := decryptStream(in, dest, aead, baseNonce); err != nil {
			return err
		}
		fmt.Println("Decryption successful:", dest)
		return nil
	}

	dest := desiredOutputPath(inPath, outPath, false)
	if fileExists(dest) {
		return fmt.Errorf("output file already exists: %s", dest)
	}
	if err := encryptStream(in, dest, aead, baseNonce, chunk); err != nil {
		return err
	}
	if autoNonce {
		nf := noncePathOriginal(inPath)
		if fileExists(nf) {
			return fmt.Errorf("nonce file already exists: %s", nf)
		}
		if err := writeFileAtomic(nf, []byte(hex.EncodeToString(baseNonce)+"\n")); err != nil {
			return err
		}
		fmt.Println("Nonce saved:", nf)
	}
	fmt.Println("Encryption successful:", dest)
	return nil
}

// ---------------- KDF & AEAD ----------------

func deriveKeyHex(c lib.Cryptus, kdf, password, saltStr string) (string, error) {
	switch kdf {
	case KdfPBKDF2:
		length := 32 // AES-256 or ChaCha20
		cfg := lib.NewKdfConfig(lib.WithIterations(100_000), lib.WithLength(length))
		return c.Pbkdf2(password, saltStr, cfg), nil
	case KdfArgon2id:
		salt := []byte(saltStr)
		cfg := lib.NewKdfConfig(
			lib.WithIterations(3),
			lib.WithMemory(1024*64),
			lib.WithThreads(1),
			lib.WithLength(32),
		)
		return c.Argon2Hex([]byte(password), salt, cfg)
	default:
		return "", errors.New("unknown kdf")
	}
}

func buildAEAD(algo string, key []byte) (cipher.AEAD, error) {
	switch algo {
	case AlgoAES:
		if l := len(key); l != 16 && l != 24 && l != 32 {
			return nil, fmt.Errorf("AES key must be 16, 24, or 32 bytes; got %d", len(key))
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case AlgoChaCha20:
		return lib.NewChacha20Poly1305Key(key)
	default:
		return nil, fmt.Errorf("unsupported algo: %s", algo)
	}
}

// ---------------- Utils ----------------

func resolveNonceForString(nonceArg string, isDecrypt bool) (string, bool) {
	if nonceArg != "" {
		return nonceArg, false
	}
	if isDecrypt {
		return "", true
	}
	return generateRandomNonceHex(), true
}

func resolveNonceForFile(inPath, nonceArg string, isDecrypt bool) (string, bool) {
	if nonceArg != "" {
		return nonceArg, false
	}
	if isDecrypt {
		nf := noncePathForOperation(inPath, true)
		if fileExists(nf) {
			data, err := os.ReadFile(nf)
			if err == nil {
				s := string(trimNewline(data))
				fmt.Println("Using nonce from file:", nf)
				return s, false
			}
		}
		return "", true
	}
	return generateRandomNonceHex(), true
}

func desiredOutputPath(inPath, outPath string, decrypt bool) string {
	if outPath != "" {
		return outPath
	}
	if decrypt {
		if hasSuffix(inPath, ".enc") {
			return trimSuffix(inPath, ".enc")
		}
		return inPath + ".dec"
	}
	return inPath + ".enc"
}

func noncePathForOperation(inPath string, decrypt bool) string {
	if decrypt && hasSuffix(inPath, ".enc") {
		orig := trimSuffix(inPath, ".enc")
		p := noncePathOriginal(orig)
		if fileExists(p) {
			return p
		}
		return inPath + ".nonce"
	}
	return noncePathOriginal(inPath)
}

func noncePathOriginal(inPath string) string { return inPath + ".nonce" }

func deriveBaseNonceAndSalt(nonceInput string) ([]byte, string) {
	b, err := hex.DecodeString(nonceInput)
	if err == nil && len(nonceInput)%2 == 0 {
		if len(b) == 12 {
			return b, nonceInput
		}
		h := sha256.Sum256(b)
		return h[:12], nonceInput
	}
	h := sha256.Sum256([]byte(nonceInput))
	return h[:12], nonceInput
}

func generateRandomNonceHex() string {
	nb, err := genNonce(12)
	if err != nil {
		fail(err.Error())
	}
	return hex.EncodeToString(nb)
}

func promptPassword() string {
	fmt.Print("Enter password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fail("could not read password")
	}
	return string(pw)
}

// ---------- Streaming ----------
func encryptStream(in *os.File, outPath string, aead cipher.AEAD, baseNonce []byte, chunkSize int) error {
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	bw := bufio.NewWriter(tmp)
	if _, err := bw.WriteString(magic); err != nil {
		return err
	}
	if err := binary.Write(bw, binary.BigEndian, uint32(chunkSize)); err != nil {
		return err
	}
	br := bufio.NewReader(in)
	buf := make([]byte, chunkSize)
	var idx uint64
	for {
		n, er := io.ReadFull(br, buf)
		if n == 0 && (er == io.EOF || er == io.ErrUnexpectedEOF) {
			break
		}
		if er != nil && er != io.EOF && er != io.ErrUnexpectedEOF {
			return er
		}
		nonce := deriveChunkNonce(baseNonce, idx, aead.NonceSize())
		ct := aead.Seal(nil, nonce, buf[:n], nil)
		if err := binary.Write(bw, binary.BigEndian, uint32(len(ct))); err != nil {
			return err
		}
		if _, err := bw.Write(ct); err != nil {
			return err
		}
		idx++
		if er == io.EOF || er == io.ErrUnexpectedEOF {
			break
		}
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), outPath)
}

func decryptStream(in *os.File, outPath string, aead cipher.AEAD, baseNonce []byte) error {
	br := bufio.NewReader(in)
	hdr := make([]byte, len(magic))
	if _, err := io.ReadFull(br, hdr); err != nil {
		return err
	}
	if string(hdr) != magic {
		return fmt.Errorf("invalid file format")
	}
	var chunkSize uint32
	if err := binary.Read(br, binary.BigEndian, &chunkSize); err != nil {
		return err
	}
	dir := filepath.Dir(outPath)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	bw := bufio.NewWriter(tmp)
	var idx uint64
	for {
		var clen uint32
		if err := binary.Read(br, binary.BigEndian, &clen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		ct := make([]byte, clen)
		if _, err := io.ReadFull(br, ct); err != nil {
			return err
		}
		nonce := deriveChunkNonce(baseNonce, idx, aead.NonceSize())
		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return err
		}
		if _, err := bw.Write(pt); err != nil {
			return err
		}
		idx++
	}
	if err := bw.Flush(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), outPath)
}

// ---------- Low-level utils ----------
func deriveChunkNonce(base []byte, index uint64, size int) []byte {
	var idx [8]byte
	binary.BigEndian.PutUint64(idx[:], index)
	h := sha256.New()
	h.Write(base)
	h.Write(idx[:])
	sum := h.Sum(nil)
	return sum[:size]
}

func genNonce(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func trimNewline(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return b
}

func hasSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

func trimSuffix(s, suf string) string {
	if hasSuffix(s, suf) {
		return s[:len(s)-len(suf)]
	}
	return s
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "Error:", msg)
	os.Exit(1)
}
