// +build develop

package tls

import (
	"fmt"
	"log"
	"os"
)

var (
	infoLog    = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	warningLog = log.New(os.Stdout, "WARNING: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLog   = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
)

//Infof Infof
func Infof(s string, v ...interface{}) {
	_ = infoLog.Output(2, fmt.Sprintf(s, v...))
}

//Warningf Warningf
func Warningf(s string, v ...interface{}) {
	_ = warningLog.Output(2, fmt.Sprintf(s, v...))
}

//Errorf Errorf
func Errorf(s string, v ...interface{}) {
	_ = errorLog.Output(2, fmt.Sprintf(s, v...))
}
