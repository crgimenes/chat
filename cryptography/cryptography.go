package cryptography

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

type Crypto struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

// Gera um novo par de chaves RSA
func GenerateKeyPair() (*Crypto, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &Crypto{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}, nil
}

// Criptografa uma string utilizando a chave pública
func (c *Crypto) Encrypt(plaintext string) (string, error) {
	label := []byte("")
	encryptedBytes, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, c.publicKey, []byte(plaintext), label)
	if err != nil {
		return "", err
	}

	encryptedText := base64.StdEncoding.EncodeToString(encryptedBytes)
	return encryptedText, nil
}

// Assina uma string utilizando a chave privada
func (c *Crypto) Sign(message string) (string, error) {
	hashed := sha256.Sum256([]byte(message))
	signature, err := rsa.SignPSS(rand.Reader, c.privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return "", err
	}

	signatureText := base64.StdEncoding.EncodeToString(signature)
	return signatureText, nil
}

// Verifica a assinatura de uma string utilizando a chave pública
func VerifySignature(message, signature string, publicKey *rsa.PublicKey) error {
	hashed := sha256.Sum256([]byte(message))
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA256, hashed[:], signatureBytes, nil)
	if err != nil {
		return fmt.Errorf("assinatura inválida: %v", err)
	}

	return nil
}

// Descriptografa uma string utilizando a chave privada
func (c *Crypto) Decrypt(ciphertext string) (string, error) {
	label := []byte("")
	encryptedBytes, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	decryptedBytes, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, c.privateKey, encryptedBytes, label)
	if err != nil {
		return "", err
	}

	decryptedText := string(decryptedBytes)
	return decryptedText, nil
}

// Salva o par de chaves em arquivos separados
func (c *Crypto) SaveKeyPair(privateKeyPath, publicKeyPath string) error {
	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(c.privateKey),
	})

	err := ioutil.WriteFile(privateKeyPath, privateKeyBytes, 0600)
	if err != nil {
		return err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(c.publicKey)
	if err != nil {
		return err
	}

	publicKeyBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	err = ioutil.WriteFile(publicKeyPath, publicKeyBytes, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Carrega o par de chaves a partir de arquivos
func LoadKeyPair(privateKeyPath, publicKeyPath string) (*Crypto, error) {
	privateKeyBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil, err
	}

	publicKeyBlock, _ := pem.Decode(publicKeyBytes)
	publicKeyInterface, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("falha ao converter chave pública")
	}

	return &Crypto{
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

// Retorna o fingerprint (impressão digital) da chave pública
func (c *Crypto) GetPublicKeyFingerprint() (string, error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(c.publicKey)
	if err != nil {
		return "", err
	}

	hash := md5.Sum(publicKeyBytes)
	fingerprint := hex.EncodeToString(hash[:])

	return fingerprint, nil
}
