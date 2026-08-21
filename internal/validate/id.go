package validate

func Kid(s string) bool { return s != "" && len(s) <= 128 }

func Label(s string) bool { return len(s) <= 256 }
