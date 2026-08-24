package mobile

import (
	"crypto/tls"
	"encoding/base64"
	"sync"

	"github.com/mythologyli/zju-connect/client/easyconnect"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack/tun"
)

var vpnClient *easyconnect.Client
var vpnClientMu sync.Mutex
var loginMu sync.Mutex

// CaptchaProvider is implemented on the Java/Kotlin side to display the image
// captcha and return the user-entered code. GetCaptcha may block until the
// user submits.
type CaptchaProvider interface {
	GetCaptcha(imageBase64 string) string
}

var captchaProvider CaptchaProvider

// lastError records why the most recent Login attempt failed ("" if none).
var lastErrorMutex sync.RWMutex
var lastErrorStr string

func SetCaptchaProvider(p CaptchaProvider) {
	captchaProvider = p
}

// LastError returns the error message of the most recent Login failure.
func LastError() string {
	lastErrorMutex.RLock()
	defer lastErrorMutex.RUnlock()
	return lastErrorStr
}

func setLastError(err error) {
	lastErrorMutex.Lock()
	defer lastErrorMutex.Unlock()
	if err == nil {
		lastErrorStr = ""
	} else {
		lastErrorStr = err.Error()
	}
}

func Login(server string, username string, password string) string {
	log.Init()

	return login(server, username, password)
}

func DebugLogin(server string, username string, password string) string {
	log.Init()
	log.EnableDebug()

	return login(server, username, password)
}

func Logout() {
	vpnClientMu.Lock()
	defer vpnClientMu.Unlock()

	if vpnClient != nil {
		vpnClient.Close()
		vpnClient = nil
	}
}

func login(server string, username string, password string) string {
	loginMu.Lock()
	defer loginMu.Unlock()
	setLastError(nil)

	newClient := easyconnect.NewClient(
		server,
		username,
		password,
		"",
		tls.Certificate{},
		"",
		false,
		false,
		false,
	)

	if captchaProvider != nil {
		newClient.SetRandCodeProvider(func(img []byte) string {
			return captchaProvider.GetCaptcha(base64.StdEncoding.EncodeToString(img))
		})
	}

	// Close the old client and clear vpnClient to nil during setup so that
	// concurrent StartStack calls see nil and return early rather than
	// operating on an uninitialized client.
	vpnClientMu.Lock()
	old := vpnClient
	vpnClient = nil
	vpnClientMu.Unlock()
	if old != nil {
		old.Close()
	}

	err := newClient.Setup("", "", false)
	if err != nil {
		setLastError(err)
		newClient.Close()
		return ""
	}

	log.Printf("EasyConnect client started")

	clientIP, err := newClient.IP()
	if err != nil {
		setLastError(err)
		newClient.Close()
		return ""
	}

	vpnClientMu.Lock()
	vpnClient = newClient
	vpnClientMu.Unlock()

	return clientIP.String()
}

func StartStack(fd int) {
	vpnClientMu.Lock()
	client := vpnClient
	vpnClientMu.Unlock()
	if client == nil {
		return
	}

	vpnTUNStack, err := tun.NewStack(client)
	if err != nil {
		return
	}

	vpnTUNStack.SetupTun(fd)
	vpnTUNStack.Run()
}
