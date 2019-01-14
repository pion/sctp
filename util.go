package sctp

const (
	paddingMultiple = 4
)

func getPadding(len int) int {
	return (paddingMultiple - (len % paddingMultiple)) % paddingMultiple
}

func padByte(in []byte, cnt int) []byte {
	if cnt < 0 {
		cnt = 0
	}
	padding := make([]byte, cnt)
	return append(in, padding...)
}
