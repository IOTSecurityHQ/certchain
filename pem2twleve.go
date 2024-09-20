package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	// Paths to the root, intermediate, and final certificate files
	rootCertPath := "root.crt"
	intermediateCertPath := "intermediate.crt"
	finalCertPath := "final.crt"

	// Read and parse the root certificate from file
	rootCert, err := readAndParseCert(rootCertPath)
	if err != nil {
		fmt.Println("Error reading root certificate:", err)
		return
	}

	// Read and parse the intermediate certificate from file
	intermediateCert, err := readAndParseCert(intermediateCertPath)
	if err != nil {
		fmt.Println("Error reading intermediate certificate:", err)
		return
	}

	// Read and parse the final signing certificate from file
	finalCert, err := readAndParseCert(finalCertPath)
	if err != nil {
		fmt.Println("Error reading final certificate:", err)
		return
	}

	// Create a chain containing the final, intermediate, and root certificates
	chain := []*x509.Certificate{finalCert, intermediateCert, rootCert}

	// Create a PKCS#12 structure (without private key) with the full chain
	pfxData, err := pkcs12.Encode(rand.Reader, nil, finalCert, chain[1:], "")
	if err != nil {
		fmt.Println("Error encoding PKCS#12 structure:", err)
		return
	}

	// Write the PKCS#12 structure to a file
	err = ioutil.WriteFile("cert_chain_no_key.p12", pfxData, 0644)
	if err != nil {
		fmt.Println("Error writing PKCS#12 file:", err)
		return
	}

	fmt.Println("PKCS#12 file created successfully!")
}

// readAndParseCert reads a certificate from a file and parses it
func readAndParseCert(certPath string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("error reading certificate file %s: %v", certPath, err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode certificate PEM from file %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate from file %s: %v", certPath, err)
	}
	return cert, nil
}
