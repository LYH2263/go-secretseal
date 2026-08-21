package clone

func Bytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

func Strings(src []string) []string {
	return src
}
