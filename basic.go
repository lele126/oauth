package oauth

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gogf/gf/net/ghttp"
)

// GetBasicAuthentication get username and password from Authorization header
func GetBasicAuthentication(r *ghttp.Request) (username, password string, err error) {
	if header := r.Request.Header.Get("Authorization"); header != "" {
		if strings.ToLower(header[:6]) == "basic " {
			// decode header value
			value, err := base64.StdEncoding.DecodeString(header[6:])
			if err != nil {
				return "", "", err
			}
			strValue := string(value)
			if ind := strings.Index(strValue, ":"); ind > 0 {
				return strValue[:ind], strValue[ind+1:], nil
			}
		}
	}
	return "", "", nil
}

// Check Basic Autrhorization header credentials
func CheckBasicAuthentication(username, password string, r *ghttp.Request) error {
	u, p, err := GetBasicAuthentication(r)
	if err != nil {
		return err
	} else {
		if u != "" && p != "" {
			if u != username && p != password {
				return errors.New("Invalid credentials")
			}
		}
		return nil
	}
}
