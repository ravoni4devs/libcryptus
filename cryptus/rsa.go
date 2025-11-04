package cryptus

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

func (c *cryptus) GenerateRsaKeyPair(size int) (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		return "", "", err
	}
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pub := &priv.PublicKey
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: asn1Bytes})
	return string(privPEM), string(pubPEM), nil
}

func (c *cryptus) EncryptRsaOAEPB64(plainText, publicKeyPEM string) (string, error) {
	pub, err := c.ParseRSAPublicKeyFromPEM(publicKeyPEM)
	if err != nil {
		return "", err
	}
	label := []byte("") // opcional
	ct, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, []byte(plainText), label)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(ct), nil
}

func (c *cryptus) DecryptRsaOAEPB64(cipherB64, privateKeyPEM string) (string, error) {
	priv, err := c.ParseRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return "", err
	}
	raw, err := base64.RawStdEncoding.DecodeString(cipherB64)
	if err != nil {
		return "", fmt.Errorf("invalid base64: %w", err)
	}
	label := []byte("")
	pt, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, raw, label)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

func (c *cryptus) ParseRSAPublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block (public)")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKIX public key: %w", err)
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}
	return pub, nil
}

func (c *cryptus) ParseRSAPrivateKeyFromPEM(privateKeyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block (private)")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 private key: %w", err)
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}
	return priv, nil
}
