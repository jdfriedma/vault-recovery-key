package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	proto "github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"
	context "golang.org/x/net/context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	awskms "github.com/hashicorp/go-kms-wrapping/wrappers/awskms/v2"
	azurekeyvault "github.com/hashicorp/go-kms-wrapping/wrappers/azurekeyvault/v2"
	gcpckms "github.com/hashicorp/go-kms-wrapping/wrappers/gcpckms/v2"
	transit "github.com/hashicorp/go-kms-wrapping/wrappers/transit/v2"
	"github.com/hashicorp/vault/shamir"
)

const (
	version = "0.3"
)

func main() {

	log.SetOutput(os.Stdout)
	log.SetFormatter(&log.TextFormatter{})
	log.SetLevel(log.DebugLevel)
	log.Infof("Starting version %s", version)

	cloud := flag.String("env", "gcpckms", "Environment that hosts the KMS: gcpckms,azurekeyvault,transit,awskms")
	encKey := flag.String("enc-key", "key.enc", "Path to the encrypted recovery keys from the storage, found at core/_recovery-key")
	shares := flag.Int("shamir-shares", 1, "Number of shamir shares to divide the key into")
	threshold := flag.Int("shamir-threshold", 1, "Threshold number of keys needed for shamir creation")

	flag.Parse()

	if *cloud == "" || *encKey == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	log.Infof("Starting with environment %s", *cloud)

	env, err := readBin(*encKey)

	if err != nil {
		log.Fatalf("Couldnt read file: %s", err)
		os.Exit(1)
	}
	var wrapper wrapping.Wrapper

	log.Infof("Setting up for %s", *cloud)
	switch *cloud {
	case "gcpckms":
		wrapper = gcpckms.NewWrapper()
	case "azurekeyvault":
		wrapper = azurekeyvault.NewWrapper()
	case "awskms":
		wrapper = awskms.NewWrapper()
	case "transit":
		wrapper = transit.NewWrapper()
	default:
		log.Fatalf("Environment not implemented: %s", *cloud)
	}
	_, err = wrapper.SetConfig(nil)
	if err != nil {
		log.Fatalf("SetConfig failed: %s", err)
	}
	blobInfo := &wrapping.BlobInfo{}
	if err := proto.Unmarshal(env, blobInfo); err != nil {
		log.Errorf("failed to proto decode stored keys: %s", err)
		return
	}
	blobStr, err := json.MarshalIndent(blobInfo, "", "\t")
	if err != nil {
		log.Fatalf("failed to marshall blobInfo: %s", err)
	}
	log.Debugf("blobInfo=%s", blobStr)
	pt, err := wrapper.Decrypt(context.Background(), blobInfo, nil)
	if err != nil {
		log.Errorf("failed to decrypt encrypted stored keys: %s", err)
		return
	}
	log.Debugf("HEX=%#X", pt)

	if *shares == 1 {
		encoded := base64.StdEncoding.EncodeToString([]byte(pt))
		fmt.Printf("Recovery key\n%s", encoded)
	} else {
		shares, err := shamir.Split(pt, *shares, *threshold)
		if err != nil {
			log.Fatalf("failed to generate barrier shares: %s", err)
		}
		log.Infof("Recovery keys")
		for _, share := range shares {
			fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(share))
		}
	}
}
func readBin(filename string) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stats, statsErr := file.Stat()
	if statsErr != nil {
		return nil, statsErr
	}

	var size int64 = stats.Size()
	bytes := make([]byte, size)

	bufr := bufio.NewReader(file)
	_, err = bufr.Read(bytes)

	return bytes, err
}

