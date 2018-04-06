// Copyright 2018 certgen Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//////////////////////////////////////////////////////////////////////////////

// The certificate generator server creates various certificates or keys on
// demand. First support is for SSH host keys, like ssh-keygen.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/mux"
	"github.com/kr/pretty"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
)

var (
	// Environment variables are preferred to flags for deployments in
	// AppEngine. And, using environment variables is encouraged for
	// twelve-factor apps -- https://12factor.net/config

	// projectID must be set using the GCLOUD_PROJECT environment variable.
	projectID = os.Getenv("GCLOUD_PROJECT")

	// bindAddress may be set using the LISTEN environment variable. By default, ePoxy
	// listens on all available interfaces.
	bindAddress = os.Getenv("LISTEN")

	// bindPort may be set using the PORT environment variable.
	bindPort = "8080"
)

// init checks the environment for configuration values.
func init() {
	// Only use the automatic public address if PUBLIC_ADDRESS is not already set.
	if port := os.Getenv("PORT"); port != "" {
		bindPort = port
	}
}

// checkHealth reports whether the server is healthy. checkHealth will
// typically be registered as the http.Handler for the path "/_ah/health" when
// running in Docker or AppEngine.
func checkHealth(rw http.ResponseWriter, req *http.Request) {
	fmt.Fprint(rw, "ok")
}

// Env holds data necessary for executing handler functions.
type Env struct {
}

// GenerateSSHECDSA creates a private key suitable for an SSH server.
// The key is returned in PEM format.
func (env *Env) GenerateSSH_ECDSA(rw http.ResponseWriter, req *http.Request) {
	// TODO: enforce a request whitelist.
	// TODO: support other options, like bitsize, etc.
	privateRaw, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rawBytes, err := x509.MarshalECPrivateKey(privateRaw)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	privatePEM := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: rawBytes,
	}
	rw.Header().Set("Content-Type", "text/plain; charset=us-ascii")
	rw.WriteHeader(http.StatusOK)
	if err := pem.Encode(rw, privatePEM); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate and log the public key.
	publicRaw, err := ssh.NewPublicKey(&privateRaw.PublicKey)
	if err != nil {
		// TODO: log error.
		return
	}

	// Log the public key.
	hostname := mux.Vars(req)["hostname"]
	// Note: ssh does not seem to support setting the public comment field, and
	// MarshalAuthorizedKey ends string with new line.
	pubkey := strings.Trim(string(ssh.MarshalAuthorizedKey(publicRaw)), "")
	log.Println(pubkey[:len(pubkey)-1], hostname)
	return
}

// GenerateSSH_ED25519 thing.
func (env *Env) GenerateSSH_ED25519(rw http.ResponseWriter, req *http.Request) {
	publicRaw, privateRaw, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	privatePEM := &pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateRaw),
	}
	rw.Header().Set("Content-Type", "text/plain; charset=us-ascii")
	rw.WriteHeader(http.StatusOK)
	if err := pem.Encode(rw, privatePEM); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate and log the public key.
	public, err := ssh.NewPublicKey(publicRaw)
	if err != nil {
		// TODO: log error.
		log.Println(err)
		return
	}

	// Log the public key.
	hostname := mux.Vars(req)["hostname"]
	// Note: ssh does not seem to support setting the public comment field, and
	// MarshalAuthorizedKey ends string with new line.
	pubkey := strings.Trim(string(ssh.MarshalAuthorizedKey(public)), "")
	log.Println(pubkey[:len(pubkey)-1], hostname)
	return
}

// GenerateSSH_RSA creates a private key suitable for an SSH server.
// The key is returned in PEM format.
func (env *Env) GenerateSSH_RSA(rw http.ResponseWriter, req *http.Request) {
	log.Println("GenerateSSH_RSA")
	// TODO: enforce a request whitelist.
	// TODO: support other options, like bitsize, etc.
	privateRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Write PEM encoded private key to the ResponseWriter.
	privatePEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateRaw),
	}
	rw.Header().Set("Content-Type", "text/plain; charset=us-ascii")
	rw.WriteHeader(http.StatusOK)
	if err := pem.Encode(rw, privatePEM); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// Generate and log the public key.
	publicRaw, err := ssh.NewPublicKey(&privateRaw.PublicKey)
	if err != nil {
		// TODO: log error.
		return
	}

	// Log the public key.
	hostname := mux.Vars(req)["hostname"]
	// Note: ssh does not seem to support setting the public comment field, and
	// MarshalAuthorizedKey ends string with new line.
	pubkey := strings.Trim(string(ssh.MarshalAuthorizedKey(publicRaw)), "")
	log.Println(pubkey[:len(pubkey)-1], hostname)
	return
}

// addRoute adds a new handler for a pattern-based URL target to a Gorilla mux.Router.
func addRoute(router *mux.Router, method, pattern string, handler http.Handler) {
	router.Methods(method).Path(pattern).Handler(handler)
}

func main() {
	// ssh-keygen -s measurement-lab-ssh-ca \
	// HOST CERTIFICATE (-h)
	//   -n 192.168.0.109
	//   -V +52w
	//   -I ubuntu-192-168-0-109
	// ssh_host_rsa_key.pub

	b, err := ioutil.ReadFile("measurement-lab-ssh-ca.pub")
	if err != nil {
		log.Println("read ca pub")
		log.Fatal(err)
	}
	fmt.Println(string(b))
	f := strings.SplitN(string(b), " ", 3)

	b, err = base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		fmt.Println("Decode fail: ", f[1])
		log.Fatal(err)
	}

	pubkey, err := ssh.ParsePublicKey(b)
	if err != nil {
		log.Println("parse ca key 1")
		log.Fatal(err)
	}
	//c := pubkey.(*ssh.Certificate)
	pretty.Println(string(b))
	pretty.Println(pubkey)

	b, err = ioutil.ReadFile("measurement-lab-ssh-ca")
	if err != nil {
		log.Println("read ca key")
		log.Fatal(err)
	}
	signer, err := ssh.ParsePrivateKey(b)
	if err != nil {
		log.Println("parse ca private key")
		log.Fatal(err)
	}
	pretty.Println("signer")
	pretty.Println(signer)

	// b, err = ioutil.ReadFile("ssh_host_rsa_key.pub")
	b, err = ioutil.ReadFile("id_rsa.pub")
	if err != nil {
		log.Println("read rsa key pub")
		log.Fatal(err)
	}
	fmt.Println(string(b))
	f = strings.SplitN(string(b), " ", 3)

	b, err = base64.StdEncoding.DecodeString(f[1])
	if err != nil {
		fmt.Println("Decode fail: ", f[1])
		log.Fatal(err)
	}

	pubkey, err = ssh.ParsePublicKey(b)
	if err != nil {
		log.Println("parse rsa key pub")
		log.Fatal(err)
	}
	pretty.Println(pubkey)
	/*
		marker, hosts, pubkey, comment, rest, err := ssh.ParseKnownHosts(b)
		pretty.Print(pubkey)
		pretty.Print(marker)
		pretty.Print(hosts)
		pretty.Print(comment)
		pretty.Print(rest)
	*/

	/*
		c := ssh.Certificate{
			Nonce           []byte
			Key             PublicKey
			Serial          uint64
			CertType        uint32
			KeyId           string
			ValidPrincipals []string
			ValidAfter      uint64
			ValidBefore     uint64
			ssh.Permissions{
			}
		}
	*/

}
