package sctp

import (
	"time"
)

type CongestionController interface {
	OnACK(ackedBytes uint32, rtt time.Duration)
	OnSend(bytes uint32)
	OnLoss()
	OnTimeout()
	GetWindow() uint32
	GetTimeout() time.Duration
	CanSend(bytes uint32, smoothedRTT time.Duration) (canSend bool, next time.Time) //for pacing
	SetFastRecovery(bool)
}
