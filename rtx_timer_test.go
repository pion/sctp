package sctp

import (
	"fmt"
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

func (o *testTimerObserver) OnRetransmissionTimeout(id int, n uint) {
	o.onRTO(id, n)
}

func (o *testTimerObserver) OnRetransmissionFailure(id int) {
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
		})

		assert.False(t, rt.isRunning(), "should not be running")

		//since := time.Now()
		rt.start(30)

		assert.True(t, rt.isRunning(), "should be running")

		time.Sleep(650 * time.Millisecond)
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		assert.Equal(t, 4, nCbs, "should be called 4 times (actual: %d)", nCbs)
	})

	t.Run("start, stop then start", func(t *testing.T) {
		timerID := 1
		var nGoodCbs int
		var nBadCbs int
		var afterStop bool
		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				if !afterStop {
					nBadCbs++
				} else {
					nGoodCbs++
				}
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		})

		interval := float64(30.0)

		rt.start(interval)
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		afterStop = true

		rt.start(interval)
		assert.True(t, rt.isRunning(), "should be running")
		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		rt.stop()

		assert.Equal(t, 1, nGoodCbs, "must be called once")
		assert.Equal(t, 0, nBadCbs, "must not be called at all")
		assert.False(t, rt.isRunning(), "should not be running")
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
		})

		for i := 0; i < 1000; i++ {
			ok := rt.start(30)
			assert.True(t, ok, "should be true")
			assert.True(t, rt.isRunning(), "should be running")
			//since := time.Now()
			rt.stop()
			//t.Logf("stop() took %.03f\n", time.Since(since).Seconds())
			assert.False(t, rt.isRunning(), "should not be running")
		}

		assert.Equal(t, 0, nCbs, "no callback should be made")
	})

	t.Run("many start calls", func(t *testing.T) {
		timerID := 3
		var nCbs int

		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				nCbs++
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
			},
			onRtxFailure: func(id int) {},
		})

		var ok bool
		interval := float64(30.0)
		ok = rt.start(interval)
		assert.True(t, ok, "must be true")

		for i := 0; i < 3; i++ {
			// The timer has already stareted. This should be noop
			// and return false.
			ok = rt.start(interval)
			assert.False(t, ok, "must be false")
		}

		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		rt.stop()
		assert.False(t, rt.isRunning(), "should not be running")

		assert.Equal(t, 1, nCbs, "must be called once")

		// wait extra 25 msec to make sure the timer has stopped
		time.Sleep(time.Duration(interval*1.5) * time.Millisecond)
		assert.Equal(t, 1, nCbs, "must be called once")
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
		})

		// RTO(msec) Total(msec)
		//  10          10    1st RTO
		//  20          30    2nd RTO
		//  40          70    3rd RTO
		//  80         150    4th RTO
		// 160         310    5th RTO (== Path.Max.Retrans)
		// 320         630    Failure

		interval := float64(10.0)
		ok := rt.start(interval)
		assert.True(t, ok, "must be true")

		<-doneCh

		assert.False(t, rt.isRunning(), "should not be running")
		assert.Equal(t, 5, nCbs, "must have been called once")
		assert.True(t, elapsed > 0.600, "must have taken more than 600 msec")
		assert.True(t, elapsed < 0.700, "must fail in less than 700 msec")
	})

	t.Run("stop on timer not running is noop", func(t *testing.T) {
		timerID := 5
		doneCh := make(chan bool)

		rt := newRTXTimer(timerID, &testTimerObserver{
			onRTO: func(id int, nRtos uint) {
				assert.Equal(t, timerID, id, "unexpted timer ID: %d", id)
				doneCh <- true
			},
			onRtxFailure: func(id int) {},
		})

		fmt.Println("calling stop() 10 times")
		for i := 0; i < 10; i++ {
			rt.stop()
		}

		fmt.Println("start()")
		ok := rt.start(20.0)
		assert.True(t, ok, "must be true")
		assert.True(t, rt.isRunning(), "must be running")

		fmt.Println("waiting done")
		<-doneCh
		rt.stop()
		fmt.Println("done")

		assert.False(t, rt.isRunning(), "must be false")
	})
}
