package main

import (
	"log"
	"os"

	"github.com/keithballdotnet/go-kms/kms"
)

// main will start up the application
func main() {

	// Set up logging

	os.Setenv("GOKMS_KSMC_PASSPHRASE", "A long passphrase that will be used to generate the master key")
	log.SetOutput(os.Stdout)
	log.SetPrefix("GO-KMS:")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	log.Println("Starting GO-KMS...")

	kms.Start()
}
