package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"github.com/dvvislobokov/notary-tool/notary"
	log "github.com/sirupsen/logrus"
	"github.com/t-tomalak/logrus-easy-formatter"
	"os"
	"time"
)

func main() {
	log.SetFormatter(&easy.Formatter{
		TimestampFormat: "2006-01-02 15:04:05",
		LogFormat:       " %time% [%lvl%] %msg%",
	})
	log.SetLevel(log.InfoLevel)
	file := flag.String("f", "", "file to notarize")
	key := flag.String("k", "", "private key")
	kid := flag.String("kid", "", "kid for jwt (required)")
	iss := flag.String("iss", "", "iss for jwt (required)")
	s3Timeout := flag.Duration("s3t", time.Minute, "aws s3 timeout to upload file")
	checkPeriod := flag.Duration("cp", time.Second*10, "period to check notarization")
	jwtOnly := flag.Bool("jwtout", false, "only output jwt")
	flag.Parse()
	if *file == "" || *key == "" || *kid == "" || *iss == "" || *s3Timeout == 0 {
		flag.PrintDefaults()
		os.Exit(-1)
	}

	if *jwtOnly {
		jwtKey, err := notary.CreateJwtToken(*iss, *kid, *key)
		if err != nil {
			log.Fatal(err)
		}
		println(jwtKey)
	}

	fileStat, err := os.Stat(*file)
	if err != nil {
		log.Fatal(err)
	}
	fileName := fileStat.Name()
	hash := sha256.New()

	fileData, err := os.ReadFile(*file)
	if err != nil {
		log.Fatal(err)
	}
	hash.Write(fileData)
	fileHash := fmt.Sprintf("%x", hash.Sum(nil))

	log.Infof("File to upload %s. File hash is %s\n", fileName, fileHash)
	if err := notary.Notarize(*iss, *kid, *key, fileName, fileHash, fileData, *s3Timeout, *checkPeriod, false); err != nil {
		log.Fatal(err)
	}
	log.Infof("File successfullty notarized\n")

}
