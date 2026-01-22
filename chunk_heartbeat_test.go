// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// helper to build a raw HEARTBEAT chunk with a single HeartbeatInfo param.
func buildHeartbeatChunk(t *testing.T, info []byte) []byte {
	t.Helper()

	p := &paramHeartbeatInfo{heartbeatInformation: info}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return nil
	}

	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   pp,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return nil
	}

	return raw
}

func TestChunkHeartbeat_Unmarshal_Success_EmptyBody(t *testing.T) {
	// HEARTBEAT with no body (header only) should be accepted, params left empty.
	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   nil,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.NoError(t, err)
	assert.Equal(t, ctHeartbeat, hb.typ)
	assert.Len(t, hb.params, 0)
}

func TestChunkHeartbeat_Unmarshal_Success_WithInfo(t *testing.T) {
	info := []byte{0xde, 0xad, 0xbe, 0xef}
	raw := buildHeartbeatChunk(t, info)
	if raw == nil {
		return
	}

	hb := &chunkHeartbeat{}
	err := hb.unmarshal(raw)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, ctHeartbeat, hb.typ)
	if assert.Len(t, hb.params, 1) {
		p, ok := hb.params[0].(*paramHeartbeatInfo)
		if assert.True(t, ok, "param should be *paramHeartbeatInfo") {
			assert.Equal(t, info, p.heartbeatInformation)
		}
	}
}

func TestChunkHeartbeat_Unmarshal_Success_WithZeroPaddingAfterTLV(t *testing.T) {
	info := []byte{0xaa, 0xbb, 0xcc, 0xdd}
	p := &paramHeartbeatInfo{heartbeatInformation: info}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}

	// add extra zero padding outside the TLV
	body := append([]byte{}, pp...)
	body = append(body, 0x00, 0x00, 0x00, 0x00)

	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   body,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	if !assert.NoError(t, err) {
		return
	}

	if assert.Len(t, hb.params, 1) {
		p2, ok := hb.params[0].(*paramHeartbeatInfo)
		if assert.True(t, ok) {
			assert.Equal(t, info, p2.heartbeatInformation)
		}
	}
}

func TestChunkHeartbeat_Unmarshal_Failure_TrailingNonZeroBytes(t *testing.T) {
	info := []byte{0x01, 0x02, 0x03, 0x04}
	p := &paramHeartbeatInfo{heartbeatInformation: info}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}

	body := append([]byte{}, pp...)
	body = append(body, 0x00, 0x00, 0x00, 0x01) // non-zero trailing byte

	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   body,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatExtraNonZero)
}

func TestChunkHeartbeat_Unmarshal_Failure_WrongChunkType(t *testing.T) {
	ch := chunkHeader{
		typ:   ctInit, // not ctHeartbeat
		flags: 0,
		raw:   nil,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkTypeNotHeartbeat)
}

func TestChunkHeartbeat_Unmarshal_Failure_TooShortBody(t *testing.T) {
	// raw shorter than initOptionalVarHeaderLength should fail.
	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   []byte{0x00, 0x01, 0x02},
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatNotLongEnoughInfo)
}

func TestChunkHeartbeat_Unmarshal_Failure_TruncatedParamBody(t *testing.T) {
	// build a valid HeartbeatInfo TLV, then truncate it so the advertised
	// length is larger than the available bytes.
	info := []byte{0x11, 0x22, 0x33, 0x44}
	p := &paramHeartbeatInfo{heartbeatInformation: info}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}
	if !assert.GreaterOrEqual(t, len(pp), initOptionalVarHeaderLength+1) {
		return
	}

	truncated := pp[:len(pp)-1] // chop one byte off -> length mismatch

	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   truncated,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrParseParamTypeFailed)
}

func TestChunkHeartbeat_Unmarshal_Failure_ParamTypeNotHeartbeatInfo(t *testing.T) {
	// use a different param type (e.g., StateCookie) to trigger ErrHeartbeatParam.
	p := &paramStateCookie{cookie: []byte{0x01, 0x02, 0x03}}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}

	ch := chunkHeader{
		typ:   ctHeartbeat,
		flags: 0,
		raw:   pp,
	}
	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb := &chunkHeartbeat{}
	err = hb.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatParam)
}

func TestChunkHeartbeat_Marshal_RoundTrip(t *testing.T) {
	info := []byte{0xca, 0xfe, 0xba, 0xbe}
	hb := &chunkHeartbeat{
		params: []param{
			&paramHeartbeatInfo{
				heartbeatInformation: info,
			},
		},
	}

	raw, err := hb.Marshal()
	if !assert.NoError(t, err) {
		return
	}

	hb2 := &chunkHeartbeat{}
	err = hb2.unmarshal(raw)
	if !assert.NoError(t, err) {
		return
	}

	if assert.Len(t, hb2.params, 1) {
		p, ok := hb2.params[0].(*paramHeartbeatInfo)
		if assert.True(t, ok) {
			assert.Equal(t, info, p.heartbeatInformation)
		}
	}
}

func TestChunkHeartbeat_Marshal_Failure_NoParams(t *testing.T) {
	hb := &chunkHeartbeat{
		params: nil,
	}

	_, err := hb.Marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatMarshalNoInfo)
}

func TestChunkHeartbeat_Marshal_Failure_MoreThanOneParam(t *testing.T) {
	hb := &chunkHeartbeat{
		params: []param{
			&paramHeartbeatInfo{heartbeatInformation: []byte{0x01}},
			&paramHeartbeatInfo{heartbeatInformation: []byte{0x02}},
		},
	}

	_, err := hb.Marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatMarshalNoInfo)
}

func TestChunkHeartbeat_Marshal_Failure_WrongParamType(t *testing.T) {
	// Not a *paramHeartbeatInfo -> ErrHeartbeatParam.
	hb := &chunkHeartbeat{
		params: []param{
			&paramStateCookie{cookie: []byte{0x01}},
		},
	}

	_, err := hb.Marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatParam)
}

func TestChunkHeartbeat_Check(t *testing.T) {
	hb := &chunkHeartbeat{}
	abort, err := hb.check()
	assert.False(t, abort)
	assert.NoError(t, err)
}
