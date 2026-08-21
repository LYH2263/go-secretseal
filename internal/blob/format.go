package blob

import "encoding/base64"

func Encode(kid string, nonce, wrap, ct []byte) string {
	return kid + "|" +
		base64.RawStdEncoding.EncodeToString(nonce) + "|" +
		base64.RawStdEncoding.EncodeToString(wrap) + "|" +
		base64.RawStdEncoding.EncodeToString(ct)
}

func Header(kid string) string {
	if kid == "" {
		return "empty"
	}
	return "kid=" + kid
}
