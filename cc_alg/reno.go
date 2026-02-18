package cc_alg

import (
	"time"
)

const (
	MinCWND = 10 * 1500
)

type Reno struct {
	InFastRecovery    bool
	SSThreshold       uint32
	CWND              uint32
	PartialBytesAcked uint32
	Step              uint32
}

func CreateReno(step uint32) Reno {
	return Reno{
		false,
		1000000,
		MinCWND,
		0,
		step,
	}
}

// implement CongestionController
func (reno *Reno) OnACK(ackedBytes uint32, rtt time.Duration) {
	if reno.CWND < reno.SSThreshold {
		if !reno.InFastRecovery {
			reno.CWND += ackedBytes
		}
	} else {
		reno.PartialBytesAcked += ackedBytes
		if reno.PartialBytesAcked >= reno.CWND {
			reno.PartialBytesAcked -= reno.CWND
			reno.CWND += reno.Step
		}
	}
}
func (reno *Reno) OnSend(packets uint32) {}
func (reno *Reno) OnLoss() {
	if !reno.InFastRecovery {
		reno.InFastRecovery = true
		reno.PartialBytesAcked = 0
		reno.CWND = max(reno.CWND/2, MinCWND)
		reno.SSThreshold = reno.CWND
	}
}
func (reno *Reno) OnTimeout() {
	reno.OnLoss()
}
func (reno *Reno) GetWindow() uint32 {
	return reno.CWND
}
func (reno *Reno) GetTimeout() time.Duration {
	return time.Second * 120
}
func (reno *Reno) CanSend() (canSend bool, next time.Time) {
	return true, time.Time{}
}
func (reno *Reno) SetFastRecovery(v bool) {
	reno.InFastRecovery = v
}
