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
	PacingSlotStart   time.Time
	PacingSlotEnd     time.Time
	PacingRate        uint32 // bytes/ms
	SentInSlot        uint32
}

func CreateReno(step uint32) Reno {
	return Reno{
		false,
		1000000,
		MinCWND,
		0,
		step,
		time.Time{},
		time.Time{},
		0,
		0,
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
func (reno *Reno) OnSend(bytes uint32) {
	reno.SentInSlot += bytes
}
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
func (reno *Reno) CanSend(bytes uint32, smoothedRTT time.Duration) (canSend bool, next time.Time) {
	now := time.Now()
	sinceStart := max(now.Sub(reno.PacingSlotStart).Microseconds(), 1)
	t1 := time.Time{}
	if reno.PacingSlotStart == t1 || reno.PacingSlotEnd.Sub(now) <= time.Duration(0) {
		reno.PacingSlotStart = now
		reno.PacingSlotEnd = now.Add(smoothedRTT)
		srttUs := max(smoothedRTT.Microseconds(), 1)
		reno.PacingRate = uint32(2 * int64(reno.CWND) * 1000 / srttUs)
		reno.SentInSlot = 0
		sinceStart = 1000
	}

	willSend := reno.SentInSlot + bytes
	rate1 := uint32(int64(willSend) * 1000 / sinceStart)
	if rate1 <= reno.PacingRate {
		return true, time.Time{}
	} else {
		duration := time.Duration(willSend*1000/reno.PacingRate) * time.Microsecond
		next := reno.PacingSlotStart.Add(duration)
		return false, next
	}
}
func (reno *Reno) SetFastRecovery(v bool) {
	reno.InFastRecovery = v
}
