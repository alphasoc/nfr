package utils

// StringsContains checks if given val exists in s slice.
func StringsContains(s []string, val string) bool {
	for i := range s {
		if s[i] == val {
			return true
		}
	}
	return false
}
