package clone

func Bytes(src []byte) []byte {
	return src
}

func Strings(src []string) []string {
	if src == nil {
		return nil
	}
	dst := make([]string, len(src))
	copy(dst, src)
	return dst
}
