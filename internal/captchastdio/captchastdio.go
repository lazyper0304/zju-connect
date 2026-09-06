// yibinu-patch: interactive image captcha over stdin/stdout for GUI wrappers.
//
// The smartcampus Windows client runs zju-connect as a headless child process.
// When the Sangfor server enforces an image captcha (RndImg=1), the wrapper
// needs to relay the captcha image to the user and feed the answer back.
// This package implements a minimal line protocol over the standard streams:
//
//	zju-connect -> wrapper:  @CAPTCHA:<base64 image>\n
//	wrapper -> zju-connect:  @CAPTCHA_ANSWER:<text>\n
//
// Log output goes to stdout too, so the prefix "@CAPTCHA:" is reserved and
// must never appear in log lines.
package captchastdio

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"sync"
)

var (
	mu     sync.Mutex
	writer *bufio.Writer
	reader *bufio.Scanner
)

// Serve blocks until the user's answer is received, mirroring the signature
// of easyconnect's randCodeProvider callback. The image is written to stdout
// as a single @CAPTCHA: line and the answer is read from a single
// @CAPTCHA_ANSWER: line.
func Serve(img []byte) string {
	mu.Lock()
	defer mu.Unlock()

	if writer == nil {
		writer = bufio.NewWriter(os.Stdout)
		reader = bufio.NewScanner(os.Stdin)
		reader.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	}

	encoded := base64.StdEncoding.EncodeToString(img)
	if _, err := fmt.Fprintf(writer, "@CAPTCHA:%s\n", encoded); err != nil {
		return ""
	}
	if err := writer.Flush(); err != nil {
		return ""
	}

	if reader.Scan() {
		line := strings.TrimSpace(reader.Text())
		if strings.HasPrefix(line, "@CAPTCHA_ANSWER:") {
			return strings.TrimSpace(line[len("@CAPTCHA_ANSWER:"):])
		}
		// Tolerate a bare answer line (wrapper without strict protocol)
		return line
	}
	return ""
}
