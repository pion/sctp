package sctp

func padByte(in []byte, cnt int) []byte {
	if cnt < 0 {
		cnt = 0
	}
	padding := make([]byte, cnt)
	return append(in, padding...)
}
