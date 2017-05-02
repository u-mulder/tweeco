package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"time"
)

const (
	tweetMaxLen    = 140
	addTweetAPIURL = "https://api.twitter.com/1.1/statuses/update.json"

	// Set your personal twitter keys here
	consumerKey       = ""
	consumerSecret    = ""
	accessToken       = ""
	accessTokenSecret = ""

	// oauth Constants
	oauthHeaderTpl     = `OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="%s", oauth_timestamp="%s", oauth_token="%s", oauth_version="%s"`
	oauthVersion       = "1.0"
	oauthMethod        = "HMAC-SHA1"
	oauthSigningKeyTpl = "%s&%s"
	oauthBaseStringTpl = "%s&%s&%s"
	oauthParametersTpl = "oauth_consumer_key=%s&oauth_nonce=%s&oauth_signature_method=%s&oauth_timestamp=%s&oauth_token=%s&oauth_version=%s&status=%s"

	// For creating a nonce
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type tweet struct {
	text string
}

func (tw tweet) checkTweetLen() error {
	tweetLen := len([]rune(tw.text))
	if tweetMaxLen <= tweetLen {
		return fmt.Errorf(fmt.Sprintf(errTweetLenMsg, tweetLen, tweetMaxLen))
	}

	return nil
}

func (tw tweet) sendTweet() error {
	client := &http.Client{}

	reqStr := "status=" + percentEncode(tw.text)
	req, err := http.NewRequest(http.MethodPost, addTweetAPIURL, bytes.NewBufferString(reqStr))
	if err != nil {
		panic(err)
	}

	req.Header.Set("User-Agent", "Console Tweet app")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Host", "api.twitter.com")
	req.Header.Set("Authorization", getOauthHeader(tw.text))

	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	fmt.Println("Respose Status:", resp.Status)

	return nil
}

var errTweetLenMsg = "Tweet length %d exceeds max length %d"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	tw := tweet{
		text: os.Args[1],
	}

	if err := tw.checkTweetLen(); err != nil {
		panic(err)
	}

	if err := tw.sendTweet(); err != nil {
		panic(err)
	}
}

func getOauthHeader(tweetText string) string {
	nonce := getNonce(32)
	t := fmt.Sprint(time.Now().Unix())

	return fmt.Sprintf(
		oauthHeaderTpl,
		percentEncode(consumerKey),
		percentEncode(nonce),
		percentEncode(getSignature(nonce, tweetText, t)),
		percentEncode(oauthMethod),
		percentEncode(t),
		percentEncode(accessToken),
		percentEncode(oauthVersion),
	)
}

// From http://stackoverflow.com/q/22892120/1553888
func getNonce(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Int63()%int64(len(letterBytes))]
	}

	return string(b)
}

// As described in https://dev.twitter.com/oauth/overview/creating-signatures
func getSignature(nonce, text, t string) string {
	baseString := fmt.Sprintf(
		oauthBaseStringTpl,
		http.MethodPost,
		percentEncode(addTweetAPIURL),
		percentEncode(fmt.Sprintf(
			oauthParametersTpl,
			percentEncode(consumerKey),
			percentEncode(nonce),
			percentEncode(oauthMethod),
			percentEncode(t),
			percentEncode(accessToken),
			percentEncode(oauthVersion),
			percentEncode(text),
		)),
	)

	signingKey := fmt.Sprintf(
		oauthSigningKeyTpl,
		percentEncode(consumerSecret),
		percentEncode(accessTokenSecret),
	)

	// now pass baseString and signingKey to hmac algo
	mac := hmac.New(sha1.New, []byte(signingKey))
	mac.Write([]byte(baseString))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// Do percent encoding according to RFC 3986
func percentEncode(input string) string {
	var buf bytes.Buffer
	for _, b := range []byte(input) {
		if 'A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~' {
			buf.WriteByte(b)
		} else {
			buf.Write([]byte(fmt.Sprintf("%%%02X", b)))
		}
	}

	return buf.String()
}
