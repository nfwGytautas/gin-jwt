package ginjwt

/*
Check if an element exist in array

Return true if found, false otherwise
*/
func isElementInArray[T comparable](arr []T, val T) bool {
	for _, element := range arr {
		if element == val {
			return true
		}
	}

	return false
}
