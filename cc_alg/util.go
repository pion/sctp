package cc_alg

// the unit of pacingRate is bytes/ms
func CalcSendQuantum(pacingRate uint32, mss uint32, maxQuantum uint32) uint32 {
	quantum := min(pacingRate, maxQuantum)
	quantum = max(quantum, 2*mss)
	return quantum
}
