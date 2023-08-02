package notary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/golang-jwt/jwt/v5"
	"github.com/schollz/progressbar/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

type CustomReader struct {
	fp   *os.File
	size int64
	read int64
	pb   *progressbar.ProgressBar
}

func (r *CustomReader) Read(p []byte) (int, error) {
	return r.fp.Read(p)
}

func (r *CustomReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.fp.ReadAt(p, off)
	if err != nil {
		return n, err
	}

	// Got the length have read( or means has uploaded), and you can construct your message
	atomic.AddInt64(&r.read, int64(n))

	// I have no idea why the read length need to be div 2,
	// maybe the request read once when Sign and actually send call ReadAt again
	// It works for me
	_ = r.pb.Set64(r.read)
	//log.Printf("total read:%d    progress:%d%%\n", r.read/2, int(float32(r.read*100/2)/float32(r.size)))

	return n, err
}

func (r *CustomReader) Seek(offset int64, whence int) (int64, error) {
	return r.fp.Seek(offset, whence)
}

type SubmissionRequest struct {
	SubmissionName string `json:"submissionName"`
	Sha256         string `json:"sha256"`
	Notifications  []struct {
		Channel string `json:"channel"`
		Target  string `json:"target"`
	} `json:"notifications"`
}

type SubmissionResponse struct {
	Data struct {
		Attributes struct {
			AwsAccessKeyId     string `json:"awsAccessKeyId"`
			AwsSecretAccessKey string `json:"awsSecretAccessKey"`
			AwsSessionToken    string `json:"awsSessionToken"`
			Bucket             string `json:"bucket"`
			Object             string `json:"object"`
		} `json:"attributes"`
		Id   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
}

type SubmissionStatusResponse struct {
	Data struct {
		Attributes struct {
			CreatedDate time.Time `json:"createdDate"`
			Name        string    `json:"name"`
			Status      string    `json:"status"`
		} `json:"attributes"`
		Id   string `json:"id"`
		Type string `json:"type"`
	} `json:"data"`
	Meta struct {
	} `json:"meta"`
}

func CreateJwtToken(iss string, kid string, keyfile string) (string, error) {
	keyData, err := os.ReadFile(keyfile)
	if err != nil {
		return "", errors.New(fmt.Sprintf("cannot find key at \"%s\"", keyfile))
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(keyData)
	if err != nil {
		return "", errors.New(fmt.Sprintf("cannot parse key from \"%s\"", keyfile))
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": iss,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 15).Unix(),
		"aud": "appstoreconnect-v1",
	})
	token.Header["kid"] = kid

	result, err := token.SignedString(key)
	if err != nil {
		return "", err
	}
	return result, nil
}

func UploadFile(response *SubmissionResponse, fileData []byte, timeout time.Duration) error {
	sess := session.Must(session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(response.Data.Attributes.AwsAccessKeyId, response.Data.Attributes.AwsSecretAccessKey, response.Data.Attributes.AwsSessionToken),
	}))

	// Create a new instance of the service's client with a Session.
	// Optional aws.Config values can also be provided as variadic arguments
	// to the New function. This option allows you to provide service
	// specific configuration.
	svc := s3.New(sess)

	// Create a context with a timeout that will abort the upload if it takes
	// more than the passed in timeout.
	ctx := context.Background()
	var cancelFn func()
	if timeout < time.Minute {
		timeout = time.Minute
	}
	ctx, cancelFn = context.WithTimeout(ctx, timeout)
	// Ensure the context is canceled to prevent leaking.
	// See context package for more information, https://golang.org/pkg/context/
	if cancelFn != nil {
		defer cancelFn()
	}

	// Uploads the object to S3. The Context will interrupt the request if the
	// timeout expires.
	bytesReader := bytes.NewReader(fileData)
	_, err := svc.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(response.Data.Attributes.Bucket),
		Key:    aws.String(response.Data.Attributes.Object),
		Body:   bytesReader,
	})

	if err != nil {
		if awserr, ok := err.(awserr.Error); ok && awserr.Code() == request.CanceledErrorCode {
			// If the SDK can determine the request or retry delay was canceled
			// by a context the CanceledErrorCode error code will be returned.
			return errors.New(fmt.Sprintf("upload canceled due to timeout, %v\n", awserr))
		} else {
			return errors.New(fmt.Sprintf("failed to upload object, %v\n", err))
		}
	}

	return nil
}

func UploadFileWithProgress(response *SubmissionResponse, file *os.File, timeout time.Duration) error {
	sess := session.Must(session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(response.Data.Attributes.AwsAccessKeyId, response.Data.Attributes.AwsSecretAccessKey, response.Data.Attributes.AwsSessionToken),
	}))

	ctx := context.Background()
	var cancelFn func()
	if timeout < time.Minute {
		timeout = time.Minute
	}
	ctx, cancelFn = context.WithTimeout(ctx, timeout)
	if cancelFn != nil {
		defer cancelFn()
	}
	fileStat, _ := file.Stat()
	uploader := s3manager.NewUploader(sess)
	bytesReader := &CustomReader{
		fp:   file,
		size: fileStat.Size(),
		pb:   progressbar.DefaultBytes(fileStat.Size()),
	}
	_, err := uploader.Upload(&s3manager.UploadInput{
		Bucket: &response.Data.Attributes.Bucket,
		Key:    &response.Data.Attributes.Object,
		Body:   bytesReader,
	}, func(u *s3manager.Uploader) {
		u.PartSize = 1024 * 1024
	})

	if err != nil {
		return errors.New(fmt.Sprintf("failed to upload object, %v\n", err))
	}

	return nil
}

func StartSubmission(subReq *SubmissionRequest, jwt *string) (*SubmissionResponse, error) {
	if data, err := json.Marshal(subReq); err != nil {
		return nil, err
	} else {
		reader := bytes.NewReader(data)
		request, err := http.NewRequest(http.MethodPost, "https://appstoreconnect.apple.com/notary/v2/submissions", reader)
		request.Header.Add("Authorization", "Bearer "+*jwt)
		if err != nil {
			return nil, err
		}
		resp, err := http.DefaultClient.Do(request)
		if err != nil {
			return nil, err
		}
		response := SubmissionResponse{}
		err = json.NewDecoder(resp.Body).Decode(response)
		if err != nil {
			return nil, err
		}
		return &response, nil
	}
}

func CheckSubmission(id string, jwt string) (*SubmissionStatusResponse, error) {
	newRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("https://appstoreconnect.apple.com/notary/v2/submissions/%s", id), nil)
	newRequest.Header.Add("Authorization", "Bearer "+jwt)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(newRequest)
	if err != nil {
		return nil, err
	}
	response := SubmissionStatusResponse{}
	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

func Notarize(iss string, kid string, keyfile string, fileName string, fileHash string, fileData []byte, s3Timeout time.Duration, checkPeriod time.Duration, showProgress bool) error {
	jwtKey, err := CreateJwtToken(iss, kid, keyfile)
	if err != nil {
		return err
	}

	resp, err := StartSubmission(&SubmissionRequest{
		SubmissionName: fileName,
		Sha256:         fileHash,
	}, &jwtKey)

	if err != nil {
		return err
	}
	err = UploadFile(resp, fileData, s3Timeout)
	if err != nil {
		return err
	}

	checkRespErrCounter := 0
	for {
		checkResp, err := CheckSubmission(resp.Data.Id, jwtKey)
		if err != nil {
			log.Error(err)
			if checkRespErrCounter == 5 {
				return err
			}
			checkRespErrCounter++
			time.Sleep(checkPeriod)
		}

		if checkResp.Data.Attributes.Status == "Accepted" {
			log.Info("file was accepted. Notarization successfully\n")
			return nil
		}

		if checkResp.Data.Attributes.Status == "In Progress" {
			log.Infof("Notarization %s in progress\n", checkResp.Data.Id)
			time.Sleep(checkPeriod)
			continue
		} else {
			log.Info(checkResp)
			return nil
		}

	}
}
