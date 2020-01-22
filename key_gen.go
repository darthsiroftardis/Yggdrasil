package main

import (
    "fmt"
    "io/ioutil"
    "crypto/rand"
    "crypto/elliptic"
    "crypto/ecdsa"
    "crypto/x509"
    "encoding/pem"
)

func check(e error) {
	if e != nil {
		panic(e)
	}
}


func encode(privateKey *ecdsa.PrivateKey, publicKey *ecdsa.PublicKey) (string, string) {
	x509Encoded, _ := x509.MarshalECPrivateKey(privateKey)
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	x509EncodedPub,_ := x509.MarshalPKIXPublicKey(publicKey)
	pemEncodedPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: x509EncodedPub})

	return string(pemEncoded), string(pemEncodedPub)
}


func main() {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	encPriv, encPub := encode(privateKey, publicKey)
	fmt.Println(encPriv)
	fmt.Println(encPub)
 	err = ioutil.WriteFile("privateKey",[]byte(encPriv), 0600)
 	check(err)

	err = ioutil.WriteFile("publicKey",[]byte(encPub), 0644)
 	check(err)


}


