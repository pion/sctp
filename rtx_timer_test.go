package sctp

import (
	//"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRTOManager(t *testing.T) {
	t.Run("initial values", func(t *testing.T) {
		m := newRTOManager()
		assert.Equal(t, rtoInitial, m.rto, "should be rtoInitial")
		assert.Equal(t, rtoInitial, m.getRTO(), "should be rtoInitial")
		assert.Equal(t, float64(0), m.srtt, "should be 0")
		assert.Equal(t, float64(0), m.rttvar, "should be 0")
	})

	t.Run("RTO calculation (small RTT)", func(t *testing.T) {
		var rto float64
		m := newRTOManager()
		exp := []int32{
			1800,
			1500,
			1275,
			1106,
			1000, // capped at RTO.Min
		}

		for i := 0; i < 5; i++ {
			m.setNewRTT(600)
			rto = m.getRTO()
			//fmt.Printf("rto: %.03f, srtt:%.03f rttvar:%.03f\n", rto, m.srtt, m.rttvar)
			assert.Equal(t, exp[i], int32(math.Floor(rto)), "should be equal")
		}
	})

	t.Run("RTO calculation (large RTT)", func(t *testing.T) {
		var rto float64
		m := newRTOManager()
		exp := []int32{
			60000, // capped at RTO.Max
			60000, // capped at RTO.Max
			60000, // capped at RTO.Max
			55312,
			48984,
		}

		for i := 0; i < 5; i++ {
			m.setNewRTT(30000)
			rto = m.getRTO()
			//fmt.Printf("rto: %.03f, srtt:%.03f rttvar:%.03f\n", rto, m.srtt, m.rttvar)
			assert.Equal(t, exp[i], int32(math.Floor(rto)), "should be equal")
		}
	})

	t.Run("reset", func(t *testing.T) {
		m := newRTOManager()
		for i := 0; i < 10; i++ {
			m.setNewRTT(200)
		}

		m.reset()
		assert.Equal(t, rtoInitial, m.getRTO(), "should be rtoInitial")
		assert.Equal(t, float64(0), m.srtt, "should be 0")
		assert.Equal(t, float64(0), m.rttvar, "should be 0")
	})
}

type onRTO func(id int, n uint)
type onRtxFailure func(id int)

type testTimerObserver struct {
	onRTO        onRTO
	onRtxFailure onRtxFailure
}

func (o *testTimerObserver) onRetransmissionTimeout(id int, n uint) {
	o.onRTO(id, n)
}

func (o *testTimerObserver) onRetransmissionFailure(id int) {
	o.onRtxFailure(id)
}

func TestRtxTimer(t *testing.T) {
	t.Run("callback interval", func(t *testing.T) {
		timerID := 0
		var nCbs int
		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				// 30 : 1 (30)
				// 60 : 2 (90)
				// 120: 3 (210)
				// 240: 4 (550) <== expected in 650 msec
				//fmt.Printf("nCbs=%d at %v\n", nCbs, time.Now().Sub(since).Seconds()*1000)

				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		assert.False(t, rt.isRunning(), "should not be running")

		//since := time.Now()
		ok := rt.start(30)
		assert.True(t, ok, "should be true")
		assert.True(t, rt.isRunning(), "should be running")

		time.Sleep(650 * time.Millisecond)
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		assert.Equal(t, 4, nCbs, "should be called 4 times (actual: %d)", nCbs)
	})

	t.Run("last start wins", func(t *testing.T) {
		timerID := 3
		var nCbs int

		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		interval := float64(30.0)
		ok := rt.start(interval)
		assert.True(t, ok, "should be accepted")
		ok = rt.start(interval * 99) // should ignored
		assert.False(t, ok, "should be ignored")
		ok = rt.start(interval * 99) // should ignored
		assert.False(t, ok, "should be ignored")

		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		rt.stop()

		assert.False(t, rt.isRunning(), "should not be running")
		assert.Equal(t, 1, nCbs, "must be called once")
	})

	t.Run("stop right afeter start", func(t *testing.T) {
		timerID := 3
		var nCbs int

		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		interval := float64(30.0)
		ok := rt.start(interval)
		assert.True(t, ok, "should be accepted")
		rt.stop()

		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		rt.stop()

		assert.False(t, rt.isRunning(), "should not be running")
		assert.Equal(t, 0, nCbs, "must be called once")
	})

	t.Run("start, stop then start", func(t *testing.T) {
		timerID := 1
		var nCbs int
		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		interval := float64(30.0)
		ok := rt.start(interval)
		assert.True(t, ok, "should be accepted")
		rt.stop()
		assert.False(t, rt.isRunning(), "should NOT be running")
		ok = rt.start(interval)
		assert.True(t, ok, "should be accepted")
		assert.True(t, rt.isRunning(), "should be running")

		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		rt.stop()
		assert.False(t, rt.isRunning(), "should NOT be running")
		assert.Equal(t, 1, nCbs, "must be called once")
	})

	t.Run("start and stop in a tight loop", func(t *testing.T) {
		timerID := 2
		var nCbs int
		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				t.Log("onRTO() called")
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		for i := 0; i < 1000; i++ {
			ok := rt.start(30)
			assert.True(t, ok, "should be accepted")
			assert.True(t, rt.isRunning(), "should be running")
			rt.stop()
			assert.False(t, rt.isRunning(), "should NOT be running")
		}

		assert.Equal(t, 0, nCbs, "no callback should be made")
	})

	t.Run("time should stop after rtx failure", func(t *testing.T) {
		timerID := 4
		var nCbs int
		doneCh := make(chan bool)

		since := time.Now()
		var elapsed float64 // in seconds
		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
				t.Logf("onRTO: n=%d elapsed=%.03f\n", nRtos, time.Since(since).Seconds())
				nCbs++
			},
			onRtxFailure: func(id int) {
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
				elapsed = time.Since(since).Seconds()
				t.Logf("onRtxFailure: elapsed=%.03f\n", elapsed)
				doneCh <- true
			},
		}, pathMaxRetrans)

		// RTO(msec) Total(msec)
		//  10          10    1st RTO
		//  20          30    2nd RTO
		//  40          70    3rd RTO
		//  80         150    4th RTO
		// 160         310    5th RTO (== Path.Max.Retrans)
		// 320         630    Failure

		interval := float64(10.0)
		ok := rt.start(interval)
		assert.True(t, ok, "should be accepted")
		assert.True(t, rt.isRunning(), "should be running")

		<-doneCh

		assert.False(t, rt.isRunning(), "should not be running")
		assert.Equal(t, 5, nCbs, "must have been called once")
		assert.True(t, elapsed > 0.600, "must have taken more than 600 msec")
		assert.True(t, elapsed < 0.700, "must fail in less than 700 msec")
	})

	t.Run("stop timer that is not running is noop", func(t *testing.T) {
		timerID := 5
		doneCh := make(chan bool)

		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
				doneCh <- true
			},
			onRtxFailure: func(id int) {},
		}, pathMaxRetrans)

		for i := 0; i < 10; i++ {
			rt.stop()
		}

		ok := rt.start(20)
		assert.True(t, ok, "should be accepted")
		assert.True(t, rt.isRunning(), "must be running")

		<-doneCh
		rt.stop()
		assert.False(t, rt.isRunning(), "must be false")
	})
}
