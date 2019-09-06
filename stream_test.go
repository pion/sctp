package sctp

import (
	"testing"

	"github.com/pion/logging"
	"github.com/stretchr/testify/assert"
)

func TestSessionBufferedAmount(t *testing.T) {
	t.Run("bufferedAmount", func(t *testing.T) {
		s := &Stream{
			log: logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		assert.Equal(t, uint64(0), s.BufferedAmount())
		assert.Equal(t, uint64(0), s.BufferedAmountLowThreshold())

		s.bufferedAmount = 8192
		s.SetBufferedAmountLowThreshold(2048)
		assert.Equal(t, uint64(8192), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, uint64(2048), s.BufferedAmountLowThreshold(), "unexpected threshold")
	})

	t.Run("OnBufferedAmountLow", func(t *testing.T) {
		s := &Stream{
			log: logging.NewDefaultLoggerFactory().NewLogger("sctp-test"),
		}

		s.bufferedAmount = 4096
		s.SetBufferedAmountLowThreshold(2048)

		nCbs := 0

		s.OnBufferedAmountLow(func() {
			nCbs++
		})

		// Negative value should be ignored (by design)
		s.onBufferReleased(-32) // bufferedAmount = 3072
		assert.Equal(t, uint64(4096), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to above, no callback
		s.onBufferReleased(1024) // bufferedAmount = 3072
		assert.Equal(t, uint64(3072), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 0, nCbs, "callback count mismatch")

		// Above to equal, callback should be made
		s.onBufferReleased(1024) // bufferedAmount = 2048
		assert.Equal(t, uint64(2048), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Eaual to below, no callback
		s.onBufferReleased(1024) // bufferedAmount = 1024
		assert.Equal(t, uint64(1024), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Blow to below, no callback
		s.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")

		// Capped at 0, no callback
		s.onBufferReleased(1024) // bufferedAmount = 0
		assert.Equal(t, uint64(0), s.BufferedAmount(), "unexpected bufferedAmount")
		assert.Equal(t, 1, nCbs, "callback count mismatch")
	})
}
