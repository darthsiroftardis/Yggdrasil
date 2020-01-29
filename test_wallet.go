package main

import (
	"io/ioutil"
	"log"
	"fmt"
	"net/http"
	"encoding/json"
)

type Transaction struct {
	Number		string
	Input		inputList
	Output		outputList
	Signature 	string
}

type Transactions []Transaction


type TransactionOutput struct {
	PublicKey 	string
	Hostname	string
	IpAddr	string
}

type outputList []TransactionOutput

func (outputs outputList) OutputString() string {
	var outputString string
	for _,output := range outputs {
		outputString += output.PublicKey
		outputString += output.Hostname
		outputString += output.IpAddr
	}
	return outputString
}

type TransactionInput struct {
	Number	string
	Outputs outputList
}

type inputList []TransactionInput

func (inputs inputList) InputString() string {
	var inputString string
	for _,input := range inputs {
		inputString += input.Number
		inputString += input.Outputs.OutputString()
	}

	return inputString	
}

type DNSEntry struct {
	Hostname 	string
	IpAddr		string
}

type DNSEntryList []DNSEntry

type Block struct {
	Index      int
	Timestamp  string
	Tx         Transaction
	Hash       string
	PrevHash   string
	Difficulty int
	Nonce      float64
}

type Blockchain []Block

func main() {
	resp, err := http.Get("http://localhost:8080/")
	if err != nil {
		log.Fatalln(err)
	}

	database := make(map[string]DNSEntryList)


	var blockchain Blockchain
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	
	if err = json.Unmarshal(body, &blockchain); err != nil {
		panic(err)
	}

	for _, block := range blockchain {
		for _, output := range block.Tx.Output {
			if _, ok := database[output.PublicKey]; ok {
				newEntry := DNSEntry {
					output.Hostname,
					output.IpAddr,
				}
				database[output.PublicKey] = append(database[output.PublicKey],newEntry)
			} else {
				var newEntryList DNSEntryList
				newEntryList = append(newEntryList,DNSEntry {
					output.Hostname,
					output.IpAddr,
				})
				database[output.PublicKey] = newEntryList
			}
		}
	}

	fmt.Println(database)

}