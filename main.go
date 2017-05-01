package main

import (
    "net/http"
    "net/url"
    "os"
    "fmt"
    "time"
    "math/rand"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/base64"
    "bytes"
)

const (
    tweetMaxLen = 140
    addTweetAPIURL = "https://api.twitter.com/1.1/statuses/update.json"

    // Set your personal twitter keys here
    consumerKey = ""
    consumerSecret = ""
    accessToken = ""
    accessTokenSecret = ""

    // oauth Constants
    oauthHeaderTpl = `OAuth oauth_consumer_key="%s", oauth_nonce="%s", oauth_signature="%s", oauth_signature_method="%s", oauth_timestamp="%s", oauth_token="%s", oauth_version="%s"`
    oauthVersion = "1.0"
    oauthMethod = "HMAC-SHA1"
    oauthSigningKeyTpl = "%s&%s"
    oauthBaseStringTpl = "%s&%s&%s"
    oauthParametersTpl = "oauth_consumer_key=%s&oauth_nonce=%s&oauth_signature_method=%s&oauth_timestamp=%s&oauth_token=%s&oauth_version=%s&status=%s"

    // For creating a nonce
    letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
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

    formValues := url.Values{}
    formValues.Add("status", tw.text)
    req, err := http.NewRequest(http.MethodPost, addTweetAPIURL, bytes.NewBufferString(formValues.Encode()))
    if err != nil {
        panic(err)
    }

    req.Header.Set("User-Agent", "Console Tweet app")
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Set("Host", "api.twitter.com")
    req.Header.Set("Authorization", getOauthHeader(tw.text))
    //Content-Length: 76    // TODO need this?

    resp, err := client.Do(req)
    if err != nil {
        return err
    }

    fmt.Println("Status:", resp.Status)

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

    if err := tw.sendTweet();  err != nil {
        panic(err)
    }
}

func getOauthHeader(tweetText string) string {
    nonce := getNonce(32)
    t := fmt.Sprint(time.Now().Unix())

    return fmt.Sprintf(
        oauthHeaderTpl,
        url.QueryEscape(consumerKey),
        url.QueryEscape(nonce),
        url.QueryEscape(getSignature(nonce, tweetText, t)),
        url.QueryEscape(oauthMethod),
        url.QueryEscape(t),
        url.QueryEscape(accessToken),
        url.QueryEscape(oauthVersion),
    )
}

// From http://stackoverflow.com/q/22892120/1553888
func getNonce(n int) string {
    b := make([]byte, n)
    for i := range b {
        b[i] = letterBytes[rand.Int63() % int64(len(letterBytes))]
    }

    return string(b)
}

// As described in https://dev.twitter.com/oauth/overview/creating-signatures
func getSignature(nonce, text, t string) string {
    baseString := fmt.Sprintf(
        oauthBaseStringTpl,
        http.MethodPost,
        url.QueryEscape(addTweetAPIURL),
        fmt.Sprintf(
            oauthParametersTpl,
            url.QueryEscape(consumerKey),
            url.QueryEscape(nonce),
            url.QueryEscape(oauthMethod),
            url.QueryEscape(t),
            url.QueryEscape(accessToken),
            url.QueryEscape(oauthVersion),
            url.QueryEscape(text),
        ),
    )
    fmt.Println(baseString)

    signingKey := fmt.Sprintf(
        oauthSigningKeyTpl,
        url.QueryEscape(consumerSecret),
        url.QueryEscape(accessTokenSecret),
    )

    // now pass baseString and signingKey to hmac algo
    mac := hmac.New(sha256.New, []byte(signingKey))
    mac.Write([]byte(baseString))
    return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}
