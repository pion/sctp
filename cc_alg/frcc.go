package cc_alg

import (
	"log"
	"math"
	"math/rand"
	"time"
)

// this file is nearly a copy of
// https://github.com/108anup/frcc_kernel/blob/ade790959c4fdfa7549d4f26f459dfc5eb507130/tcp_frcc.c

type FRCCParam struct {
	// Assumptions about network scenarios
	UBRTProp    time.Duration
	UBRTTErr    time.Duration
	UBFlowCount uint32

	// Design parameters
	LBCwnd                 uint32
	ContractMinQDel        time.Duration
	ProbeDuration          time.Duration
	ProbeMultiplier        float32
	CwndAveragingFactor    float32
	InvCwndAveragingFactor float32
	CwndClampHi            float32
	CwndClampLo            float32
	SlotLoadFactor         float32
	UBSlotsPerRound        uint32
	RProbeInterval         time.Duration
	ProbeWaitRTTs          uint32
	PacingQuantum          uint32

	// Design features
	UseRPropProbe         bool
	WaitRTTAfterProbe     bool
	UseStableCwndUpdate   bool
	ProbeWaitInMaxRTTs    bool
	ProbeDurationMaxRTT   bool
	DrainOverRTT          bool
	ProbeOverRTT          bool
	SlotGreaterThanRTProp bool
	SlotExactlyRTProp     bool
}

func FRCCDefaultParam() FRCCParam {
	p := FRCCParam{
		UBRTProp:    100 * time.Millisecond,
		UBRTTErr:    10 * time.Millisecond,
		UBFlowCount: 3,

		LBCwnd:              MinCWND,
		ContractMinQDel:     10 * time.Millisecond,
		ProbeDuration:       10 * time.Millisecond,
		ProbeMultiplier:     4.0, //gamma in the paper
		CwndAveragingFactor: 1.0, // alpha = 1/2 for non-stable design, otherwise 1.
		CwndClampHi:         1.3,
		CwndClampLo:         10.0 / 13.0,
		SlotLoadFactor:      2.0,
		UBSlotsPerRound:     20,
		RProbeInterval:      30 * time.Second,
		ProbeWaitRTTs:       2,
		PacingQuantum:       65536,

		UseRPropProbe:         true,
		WaitRTTAfterProbe:     true,
		UseStableCwndUpdate:   true,
		ProbeWaitInMaxRTTs:    true,
		ProbeDurationMaxRTT:   true,
		DrainOverRTT:          true,
		ProbeOverRTT:          true,
		SlotGreaterThanRTProp: true,
		SlotExactlyRTProp:     true,
	}
	p.InvCwndAveragingFactor = 1.0 - p.CwndAveragingFactor
	return p
}

type FRCCProbeData struct {
	Ongoing        bool
	MinRTTBefore   time.Duration
	MinRTT         time.Duration // for logging only
	MinExcessDelay time.Duration
	PrevCwnd       uint32
	Excess         uint32
	EndInitiated   bool
	Drain          float32
	DrainRem       float32

	StartTime          time.Time
	BytesAcked         uint64
	InflightMatchBytes uint64
	BytesSent          uint64
	FirstTime          time.Time
	AllSent            bool
}
type FRCCRProbeData struct {
	Ongoing       bool
	PrevStartTime time.Time
	StartTime     time.Time
	InitEndTime   time.Time
	PrevCwnd      uint32
	EndInitiated  bool
}
type FRCCRoundData struct {
	SlotsTillNow uint32
	MinRTT       time.Duration
	MaxRate      uint32 // bytes/ms
	ProbeSlotIdx uint32
	Probed       bool
	SlotsTotal   uint32
}
type FRCC struct {
	Param FRCCParam

	LastLogTime time.Time

	// State variables
	MinRTProp      time.Duration
	CWND           uint32
	PrevCwnd       uint32
	InFastRecovery bool

	SSDone         bool
	SSEndInitiated bool
	SSSentBytes    uint64
	SSAckedBytes   uint64

	SlotMaxQDel   time.Duration
	SlotStartTime time.Time
	SlotMaxRate   uint32        // for logging only
	SlotMinRTT    time.Duration // for logging only
	SlotMaxRTT    time.Duration // for logging only

	PacingSlotStart time.Time
	PacingSlotEnd   time.Time
	PacingRate      uint32 // bytes/ms
	SentInSlot      uint32

	ProbeData  FRCCProbeData
	RProbeData FRCCRProbeData
	RoundData  FRCCRoundData
}

func (frcc *FRCC) getTargetFlowCount() float32 {
	roundQDel := frcc.RoundData.MinRTT - frcc.MinRTProp
	targetFlowCount := float32(roundQDel.Microseconds()) / float32(frcc.Param.ContractMinQDel.Microseconds())
	return targetFlowCount
}
func (frcc *FRCC) getSlotsPerRound() uint32 {
	p := &frcc.Param
	LBSlotsPerRound := uint32(float32(p.UBFlowCount) * p.SlotLoadFactor)
	targetFlowCount := frcc.getTargetFlowCount()
	slotsPerRound := uint32(targetFlowCount * p.SlotLoadFactor)

	slotsPerRound = max(slotsPerRound, LBSlotsPerRound)
	slotsPerRound = min(slotsPerRound, p.UBSlotsPerRound)
	if frcc.RoundData.MinRTT == math.MaxUint32*time.Microsecond || frcc.MinRTProp == math.MaxUint32*time.Microsecond {
		return LBSlotsPerRound
	}
	return slotsPerRound
}
func (frcc *FRCC) resetRoundState() {
	r := &frcc.RoundData
	r.SlotsTotal = frcc.getSlotsPerRound()
	// ^^ Note: we need to compute this before resetting round min rtt.
	r.SlotsTillNow = 0
	r.MinRTT = math.MaxUint32 * time.Microsecond
	r.MaxRate = 0
	r.ProbeSlotIdx = uint32(1 + rand.Int31n(int32(frcc.RoundData.SlotsTotal-1)))
	r.Probed = false
	// Rationale for -1 in the input to rand.Int31n: If there are 6
	// slots: 0 to 5, we want the slot idx to be in range [1,5]. Note, slot
	// 0 is not in the range because we do not probe in slot 0 to be able
	// to obtain some information in the round.
}
func (frcc *FRCC) resetProbeState() {
	pr := &frcc.ProbeData
	pr.Ongoing = false
	pr.MinRTTBefore = math.MaxUint32 * time.Microsecond
	pr.MinRTT = math.MaxUint32 * time.Microsecond
	pr.MinExcessDelay = math.MaxUint32 * time.Microsecond
	pr.PrevCwnd = 0 // should not be read anyway.
	pr.Excess = 0   // should not be read anyway.
	pr.EndInitiated = false
	pr.Drain = 0
	pr.DrainRem = 0

	pr.StartTime = time.Time{}
	pr.BytesAcked = 0
	pr.InflightMatchBytes = 0
	pr.BytesSent = 0
	pr.FirstTime = time.Time{}
	pr.AllSent = false
}
func (frcc *FRCC) resetRProbeState(currentRProbeStartTime time.Time) {
	rpr := &frcc.RProbeData
	rpr.Ongoing = false
	rpr.PrevStartTime = frcc.getRProbeTime(currentRProbeStartTime)
	rpr.StartTime = time.Time{}
	rpr.InitEndTime = time.Time{}
	rpr.EndInitiated = false
	rpr.PrevCwnd = 0
}
func (frcc *FRCC) startNewSlot(now time.Time) {
	frcc.SlotMaxQDel = 0
	frcc.SlotStartTime = now
	frcc.SlotMaxRate = 0
	frcc.SlotMinRTT = math.MaxUint32 * time.Microsecond
	frcc.SlotMaxRTT = 0
}
func (frcc *FRCC) getRProbeTime(t1 time.Time) time.Time {
	// Round down to the nearest multiple of RProbeInterval
	p := &frcc.Param
	interval := p.RProbeInterval.Microseconds()
	t2 := t1.UnixMicro() / interval * interval
	return time.UnixMicro(t2)
}
func CreateFRCC(config FRCCParam) FRCC {
	frcc := FRCC{
		Param: config,

		// TODO: we should reset this at some time to accommodate path changes.
		MinRTProp:      math.MaxUint32 * time.Microsecond,
		CWND:           config.LBCwnd,
		PrevCwnd:       config.LBCwnd,
		InFastRecovery: false,

		SSDone:         false,
		SSEndInitiated: false,

		PacingSlotStart: time.Time{},
		PacingSlotEnd:   time.Time{},
		PacingRate:      0,
		SentInSlot:      0,
	}

	now := time.Now()
	frcc.resetRoundState()
	frcc.startNewSlot(now)
	frcc.resetProbeState()
	frcc.resetRProbeState(now)

	return frcc
}
func (frcc *FRCC) partOfProbe() bool {
	p := &frcc.ProbeData
	return p.BytesAcked <= p.BytesSent
}
func (frcc *FRCC) getInitialRTT() time.Duration {
	// Get initial RTT - as measured by INIT -> INIT ACK.  If information
	// does not exist - use U32_MAX
	return math.MaxUint32 * time.Microsecond
}
func (frcc *FRCC) updatePacingRate(rtt time.Duration, probeGain bool) {
	nextRate := int64(frcc.CWND) * 1000
	if probeGain {
		// Just after cwnd increase for probe, set pacing rate to new
		// (probing) cwnd / old RTT, so that the new inflight builds up
		// slowly over an RTT in an attempt to avoid self induced
		// oscillations.
		frcc.PacingRate = uint32(nextRate / rtt.Microseconds())
	} else {
		frcc.PacingRate = uint32(2 * nextRate / frcc.MinRTProp.Microseconds())
	}

	if frcc.PacingRate == 0 {
		log.Printf("%#v", frcc)
	}
}
func (frcc *FRCC) updateEstimates(rttSample time.Duration) {
	initRTT := frcc.getInitialRTT()
	// TODO: Should we use the delivered bytes instead of CWND?
	thisRate := uint32(int64(frcc.CWND) * 1000 / rttSample.Microseconds())

	frcc.MinRTProp = min(frcc.MinRTProp, initRTT)
	frcc.MinRTProp = min(frcc.MinRTProp, rttSample)

	round := &frcc.RoundData
	round.MinRTT = min(round.MinRTT, rttSample)
	thisQDel := rttSample - frcc.MinRTProp

	probe := &frcc.ProbeData
	if probe.Ongoing && frcc.partOfProbe() {
		thisExcessDelay := rttSample - probe.MinRTTBefore
		probe.MinExcessDelay = min(probe.MinExcessDelay, thisExcessDelay)
		probe.MinRTT = min(probe.MinRTT, rttSample)
	} else if !probe.Ongoing {
		round.MaxRate = max(round.MaxRate, thisRate)
	}
	frcc.SlotMaxQDel = max(frcc.SlotMaxQDel, thisQDel)
	frcc.SlotMaxRate = max(frcc.SlotMaxRate, thisRate)
	frcc.SlotMaxRTT = max(frcc.SlotMaxRTT, rttSample)
	frcc.SlotMinRTT = min(frcc.SlotMinRTT, rttSample)
}
func (frcc *FRCC) probeEnded() bool {
	p := &frcc.ProbeData
	return p.BytesAcked >= p.BytesSent
}
func (frcc *FRCC) cruiseEnded(now time.Time) bool {
	param := &frcc.Param
	maxRTProp := param.UBRTProp
	if param.SlotGreaterThanRTProp {
		maxRTProp = max(frcc.MinRTProp, param.UBRTProp)
	}
	if param.SlotExactlyRTProp {
		maxRTProp = frcc.MinRTProp
	}

	maxRTT := maxRTProp + frcc.SlotMaxQDel

	probeDuration := param.ProbeDuration
	if param.ProbeDurationMaxRTT {
		probeDuration = maxRTT
	}

	drainDuration := frcc.SlotMaxQDel
	if param.DrainOverRTT {
		drainDuration = maxRTT
	}

	slotDuration := maxRTT + probeDuration + drainDuration
	if param.WaitRTTAfterProbe {
		slotDuration += maxRTT
	}
	if param.ProbeWaitInMaxRTTs {
		slotDuration = max(slotDuration, maxRTT*time.Duration(param.ProbeWaitRTTs)+probeDuration+drainDuration)
	}

	slotEndTime := frcc.SlotStartTime.Add(slotDuration)
	return now.Sub(slotEndTime) >= 0
}
func (frcc *FRCC) shouldInitProbeEnd() bool {
	pr := &frcc.ProbeData
	return pr.AllSent && !pr.EndInitiated
}
func (frcc *FRCC) roundEnded() bool {
	return frcc.RoundData.SlotsTillNow >= frcc.getSlotsPerRound()
}
func (frcc *FRCC) shouldProbe() bool {
	r := &frcc.RoundData
	return r.SlotsTillNow >= r.ProbeSlotIdx
}
func (frcc *FRCC) getProbeExcess() uint32 {
	param := &frcc.Param

	targetFlowCount := frcc.getTargetFlowCount()
	excess := param.ProbeMultiplier * targetFlowCount
	excess *= float32(int64(frcc.RoundData.MaxRate) * param.UBRTTErr.Microseconds())
	t1 := uint64(excess)
	r1 := t1 % 1000
	t1 /= 1000
	if r1 > 0 {
		t1 += 1
	}

	return max(uint32(t1), 1500)
}
func (frcc *FRCC) startProbe(rtt time.Duration, now time.Time, slotMinRTT time.Duration) {
	pr := &frcc.ProbeData
	pr.Ongoing = true
	pr.MinRTTBefore = slotMinRTT
	pr.MinRTT = math.MaxUint32 * time.Microsecond
	pr.MinExcessDelay = math.MaxUint32 * time.Microsecond
	pr.PrevCwnd = frcc.CWND
	pr.Excess = frcc.getProbeExcess()
	pr.EndInitiated = false
	pr.Drain = 0
	pr.DrainRem = 0

	pr.StartTime = now
	pr.BytesAcked = 0
	pr.InflightMatchBytes = 0
	pr.BytesSent = 0
	pr.FirstTime = time.Time{}
	pr.AllSent = false

	frcc.CWND += pr.Excess
	frcc.updatePacingRate(rtt, true)
}
func (frcc *FRCC) updateCwndDrain(rtt time.Duration, ackedBytes uint32) {
	param := frcc.Param
	if !param.DrainOverRTT {
		return
	}

	pr := &frcc.ProbeData
	pr.DrainRem += pr.Drain * float32(ackedBytes)
	thisDrain := uint32(pr.DrainRem)
	pr.DrainRem = min(pr.DrainRem, 1.0)

	frcc.CWND = max(frcc.CWND-thisDrain, param.LBCwnd)
	frcc.updatePacingRate(rtt, false)
}
func (frcc *FRCC) initiateProbeEnd(rtt time.Duration, ackedBytes uint32) {
	pr := &frcc.ProbeData
	pr.EndInitiated = true
	if !(frcc.Param.DrainOverRTT) {
		frcc.CWND = pr.PrevCwnd
		frcc.updatePacingRate(rtt, false)
	} else {
		// We are amortizing the decrease over a window, so every ack,
		// we will reduce by probeData.Drain bytes.
		pr.Drain = float32(pr.Excess) / float32(frcc.CWND)
		pr.DrainRem = 0
		frcc.updateCwndDrain(rtt, ackedBytes)
	}
}
func (frcc *FRCC) updateProbeState(rtt time.Duration, now time.Time) {
	param := &frcc.Param

	maxRTProp := max(param.UBRTProp, frcc.MinRTProp)
	// Note, in cruise ended, we check if we are using
	// SlotGreaterThanRTProp, but here for our own flow we definitely
	// want the probe to be bigger.
	if param.SlotExactlyRTProp {
		maxRTProp = frcc.MinRTProp
	}
	maxRTT := maxRTProp + frcc.SlotMaxQDel

	probe := &frcc.ProbeData
	waitTime := maxRTT * time.Duration(param.ProbeWaitRTTs)
	waitUntil := probe.StartTime.Add(waitTime)

	probeDuration := param.ProbeDuration
	if param.ProbeDurationMaxRTT {
		probeDuration = maxRTT
	}

	if probe.InflightMatchBytes == 0 {
		// The inflight match will happen after half pre-probe-RTT (old
		// RTT) under our pacing rate = 2 * new cwnd / old_rtt, i.e.,
		// last packet of new cwnd sent at time old_rtt/2.
		// Conservatively, we wait a full (packet timed) new RTT.
		// Alternatively, we can just check inflight = cwnd.
		if probe.BytesSent > 0 {
			frcc.updatePacingRate(rtt, false)
			probe.InflightMatchBytes = probe.BytesSent
			if !param.WaitRTTAfterProbe {
				probe.FirstTime = now
			}
		}
	} else if probe.BytesSent == 0 {
		if probe.BytesAcked > probe.InflightMatchBytes {
			if !param.ProbeWaitInMaxRTTs || now.Sub(waitUntil) >= 0 {
				probe.BytesSent = probe.BytesAcked
				probe.FirstTime = now
			}
		}
	} else if !probe.AllSent {
		sendEndTime := probe.FirstTime.Add(probeDuration)
		if sendEndTime.Sub(now) <= 0 {
			probe.AllSent = true
		}
	}
}
func (frcc *FRCC) updateCwnd(rtt time.Duration) {
	param := &frcc.Param
	probe := &frcc.ProbeData
	prevCwnd := float32(probe.PrevCwnd)
	tcwndHiClamp := prevCwnd * param.CwndClampHi
	tcwndLoClamp := prevCwnd * param.CwndClampLo

	bwEstimate := int64(math.MaxInt64)
	if probe.MinExcessDelay > 0 {
		bwEstimate = int64(probe.Excess) * 1000 / probe.MinExcessDelay.Microseconds()
	}

	round := &frcc.RoundData
	flowCountBelief := float32(param.UBFlowCount)
	// ^^ this can be anything as this will never be read.
	if round.MaxRate > 0 {
		flowCountBelief = float32(bwEstimate) / float32(round.MaxRate)
	}
	flowCountBelief = max(flowCountBelief, 1.0)

	targetCwnd := float32(0.0)
	targetFlowCount := frcc.getTargetFlowCount()
	if targetFlowCount < 1 || round.MaxRate == 0 {
		targetCwnd = prevCwnd * param.CwndClampHi
	} else {
		if param.UseStableCwndUpdate {
			minRTProp := float32(frcc.MinRTProp.Microseconds())
			contractMinQDel := float32(param.ContractMinQDel.Microseconds())
			tcwndNum := minRTProp + contractMinQDel*flowCountBelief
			tcwndDen := minRTProp + contractMinQDel*targetFlowCount
			targetCwnd = prevCwnd * tcwndNum / tcwndDen
		} else {
			targetCwnd = prevCwnd * flowCountBelief / targetFlowCount
		}
	}
	targetCwnd = max(targetCwnd, tcwndLoClamp)
	targetCwnd = min(targetCwnd, tcwndHiClamp)

	nextCwnd := param.InvCwndAveragingFactor*prevCwnd + param.CwndAveragingFactor*targetCwnd
	frcc.CWND = max(uint32(math.Ceil(float64(nextCwnd))), param.LBCwnd)
	frcc.updatePacingRate(rtt, false)
}
func (frcc *FRCC) slowStart(now time.Time, rtt time.Duration, ackedBytes uint32) {
	// Directly saying do slow start until target_flow_count is 1 is not
	// good because we use both min rtt to estimate rtprop and qdelay, so
	// the qdelay estimate is 0, as we only timeout after a round.

	// So instead we just say we want rtt to be more than min rtt +
	// contract_const + max_jitter, this ensures that we built a queue of
	// at least contract_const.

	// slot min rtt will be very small after slow start, it will be same as
	// the rtprop because both are min rtt since flow start, resetting the
	// slot min rtt will help get fresher estimate of queueing delay.

	// cwnd is continuously increasing, so if rtt goes above the target, it
	// will continue to increase, we want to reset slot and round estimates
	// when we expect the rtt to stop increasing.

	param := &frcc.Param
	delta1 := param.ContractMinQDel + param.UBRTTErr
	shouldInitSSEnd := rtt > frcc.MinRTProp+delta1
	// TODO: contract_const subsumes rtt_err, so should we really add that
	// here?
	if frcc.MinRTProp < delta1 {
		shouldInitSSEnd = rtt > frcc.MinRTProp<<1
	}

	ssEnded := frcc.SSAckedBytes >= frcc.SSSentBytes

	if !frcc.SSEndInitiated {
		if !shouldInitSSEnd {
			frcc.CWND = max(frcc.CWND+ackedBytes, param.LBCwnd)
			frcc.updatePacingRate(rtt, false)
		} else {
			frcc.CWND = max(frcc.CWND/2, param.LBCwnd)
			frcc.updatePacingRate(rtt, false)
			frcc.SSEndInitiated = true
		}
	} else {
		if ssEnded {
			frcc.SSDone = true
			frcc.resetRoundState()
			frcc.startNewSlot(now)
		} // ss end initiated but not yet ended. do nothing.
	}
}
func (frcc *FRCC) shouldRProbe(now time.Time) bool {
	return now.Sub(frcc.RProbeData.PrevStartTime) > frcc.Param.RProbeInterval
}
func (frcc *FRCC) rProbe(rtt time.Duration, now time.Time) {
	// Note, these values only make sense when the boolean conditions they
	// are used in are met.
	param := &frcc.Param
	rp := &frcc.RProbeData
	rProbeDuration := frcc.SlotMaxQDel + param.UBRTProp
	shouldInitRProbeEnd := false
	rProbeEnded := false
	t1 := time.Time{}
	if rp.StartTime != t1 {
		initRProbeEnd := rp.StartTime.Add(rProbeDuration)
		shouldInitRProbeEnd = now.Sub(initRProbeEnd) >= 0
	}
	if rp.InitEndTime != t1 {
		rProbeEndTime := rp.InitEndTime.Add(2 * rProbeDuration)
		rProbeEnded = now.Sub(rProbeEndTime) >= 0
	}

	if !rp.Ongoing {
		rp.Ongoing = true
		rp.PrevStartTime = frcc.getRProbeTime(now)
		rp.StartTime = now
		rp.InitEndTime = time.Time{}
		rp.PrevCwnd = frcc.CWND

		probe := &frcc.ProbeData
		if probe.Ongoing {
			// if a capacity probe was ongoing, we need to reset to
			// the cwnd before the probe.
			rp.PrevCwnd = probe.PrevCwnd
		}
		rp.EndInitiated = false

		frcc.CWND = param.LBCwnd
		return
	}

	// rprobe ongoing
	if !rp.EndInitiated {
		if shouldInitRProbeEnd {
			rp.EndInitiated = true
			rp.InitEndTime = now
			frcc.CWND = rp.PrevCwnd
			frcc.updatePacingRate(rtt, false)
		}
	} else {
		if rProbeEnded {
			frcc.resetRProbeState(rp.StartTime)

			// slow start may also be ongoing, in that
			// case, we do not touch slow start state. If
			// if ss end had been initiated then rprobe end
			// does the same thing, if end was not
			// initiated, we go back to slow start, now
			// with a better rtprop estimate.
			frcc.resetProbeState()
			frcc.resetRoundState()
			frcc.startNewSlot(now)
		}
	}
}

// implement CongestionController
func (frcc *FRCC) OnACK(ackedBytes uint32, rttSample time.Duration, smoothedRTT time.Duration) {
	probe := &frcc.ProbeData
	if rttSample.Microseconds() <= 0 {
		//log.Printf("rttSample=%v <= 0us, ackedBytes %v, smoothedRTT %v", rttSample, ackedBytes, smoothedRTT)
		return
	}

	now := time.Now()
	slotMinRTT := frcc.SlotMinRTT

	frcc.updateEstimates(rttSample)

	if probe.Ongoing {
		probe.BytesAcked += uint64(ackedBytes)
		frcc.updateProbeState(rttSample, now)
	}

	if frcc.Param.UseRPropProbe && (frcc.shouldRProbe(now) || frcc.RProbeData.Ongoing) {
		frcc.rProbe(rttSample, now)
		return
	}

	if !frcc.SSDone {
		frcc.SSAckedBytes += uint64(ackedBytes)
		frcc.slowStart(now, rttSample, ackedBytes)
		return
	}

	if probe.Ongoing {
		if frcc.shouldInitProbeEnd() {
			frcc.initiateProbeEnd(rttSample, ackedBytes)
		} else if probe.EndInitiated {
			frcc.updateCwndDrain(rttSample, ackedBytes)
		}
	}

	if (!probe.Ongoing && frcc.cruiseEnded(now)) || (probe.Ongoing && frcc.probeEnded()) {
		// probe ended
		if probe.Ongoing {
			frcc.updateCwnd(rttSample)
			frcc.resetProbeState()
		}

		if frcc.roundEnded() {
			frcc.resetRoundState()
		}

		round := &frcc.RoundData
		if round.SlotsTillNow >= 1 && !round.Probed && frcc.shouldProbe() {
			round.Probed = true
			frcc.startProbe(rttSample, now, slotMinRTT)
		}
		frcc.startNewSlot(now)
		round.SlotsTillNow += 1
	}
}
func (frcc *FRCC) OnSend(bytes uint32) {
	frcc.SentInSlot += bytes
	pr := &frcc.ProbeData
	if pr.Ongoing {
		pr.BytesSent += uint64(bytes)
	}
	if !frcc.SSEndInitiated {
		frcc.SSSentBytes += uint64(bytes)
	}
}
func (frcc *FRCC) OnLoss() {
	if !frcc.InFastRecovery {
		frcc.InFastRecovery = true
		frcc.PrevCwnd = frcc.CWND
		frcc.CWND = max(frcc.CWND/2, frcc.Param.LBCwnd)
	}
}
func (frcc *FRCC) OnTimeout() {
	frcc.OnLoss()
}
func (frcc *FRCC) GetWindow() uint32 {
	return frcc.CWND
}
func (frcc *FRCC) GetTimeout() time.Duration {
	if frcc.SlotMaxRTT > 0 {
		return frcc.SlotMaxRTT * 2
	} else {
		return time.Second * 120
	}
}
func (frcc *FRCC) CanSend(bytes uint32, smoothedRTT time.Duration) (canSend bool, next time.Time) {
	now := time.Now()
	sinceStart := max(now.Sub(frcc.PacingSlotStart).Microseconds(), 1)
	t1 := time.Time{}
	if frcc.PacingSlotStart == t1 || frcc.PacingSlotEnd.Sub(now) <= time.Duration(0) {
		frcc.PacingSlotStart = now
		frcc.PacingSlotEnd = now.Add(smoothedRTT)
		if frcc.PacingRate == 0 {
			srttUs := max(smoothedRTT.Microseconds(), 1)
			r1 := 2 * int64(frcc.CWND) * 1000 / srttUs
			if r1 > math.MaxUint32 {
				log.Printf("PacingRate > MaxUint32: %v", r1)
			}
			frcc.PacingRate = uint32(r1)
		} // updatePacingRate() will update frcc.PacingRate
		frcc.SentInSlot = 0
		sinceStart = 1000
	}

	willSend := frcc.SentInSlot + bytes
	rate1 := uint32(int64(willSend) * 1000 / sinceStart)
	if rate1 <= frcc.PacingRate {
		return true, time.Time{}
	} else {
		willSend = frcc.SentInSlot + max(bytes, CalcSendQuantum(frcc.PacingRate, 1500, frcc.Param.PacingQuantum))
		if frcc.PacingRate == 0 {
			log.Printf("%#v", frcc)
		}
		duration := time.Duration(willSend*1000/frcc.PacingRate) * time.Microsecond
		next := frcc.PacingSlotStart.Add(duration)
		return false, next
	}
}
func (frcc *FRCC) SetFastRecovery(v bool) {
	if !v {
		frcc.InFastRecovery = false
		frcc.CWND = max(frcc.CWND, frcc.PrevCwnd)
	}
}
