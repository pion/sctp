// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestChunkHeartbeatAck_UnmarshalMarshal_Success(t *testing.T) {
	tt := []struct {
		name string
		info []byte
	}{
		{"empty-info", []byte{}},
		{"aligned-4", []byte{0x01, 0x02, 0x03, 0x04}},
		{"non-aligned-5", []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee}},
	}

	for _, tc := range tt {
		p := &paramHeartbeatInfo{heartbeatInformation: tc.info}
		pp, err := p.marshal()
		if !assert.NoErrorf(t, err, "marshal paramHeartbeatInfo for %s", tc.name) {
			continue
		}

		ch := chunkHeader{
			typ:   ctHeartbeatAck,
			flags: 0,
			raw:   pp,
		}

		encoded, err := ch.marshal()
		if !assert.NoErrorf(t, err, "marshal chunkHeader for %s", tc.name) {
			continue
		}

		hbAck := &chunkHeartbeatAck{}
		err = hbAck.unmarshal(encoded)
		if !assert.NoErrorf(t, err, "unmarshal HeartbeatAck for %s", tc.name) {
			continue
		}

		assert.Equalf(t, ctHeartbeatAck, hbAck.typ, "chunk type for %s", tc.name)
		if assert.Lenf(t, hbAck.params, 1, "params length for %s", tc.name) {
			got, ok := hbAck.params[0].(*paramHeartbeatInfo)
			if assert.Truef(t, ok, "param type for %s", tc.name) {
				assert.Equalf(t, tc.info, got.heartbeatInformation, "heartbeat info for %s", tc.name)
			}
		}

		roundTrip, err := hbAck.marshal()
		if !assert.NoErrorf(t, err, "marshal HeartbeatAck (round-trip) for %s", tc.name) {
			continue
		}
		assert.Equalf(t, encoded, roundTrip, "round-trip bytes for %s", tc.name)
	}
}

func TestChunkHeartbeatAck_Unmarshal_EmptyBody(t *testing.T) {
	ch := chunkHeader{
		typ:   ctHeartbeatAck,
		flags: 0,
		raw:   nil,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	if !assert.NoError(t, err) {
		return
	}

	assert.Nil(t, hbAck.params)
}

func TestChunkHeartbeatAck_Unmarshal_Failure_WrongChunkType(t *testing.T) {
	p := &paramHeartbeatInfo{heartbeatInformation: []byte{0x01, 0x02, 0x03, 0x04}}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}

	ch := chunkHeader{
		typ:   ctHeartbeat, // wrong type on purpose
		flags: 0,
		raw:   pp,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrChunkTypeNotHeartbeatAck)
}

func TestChunkHeartbeatAck_Unmarshal_Failure_BodyTooShort(t *testing.T) {
	// less than initOptionalVarHeaderLength bytes in the body.
	body := []byte{0xaa, 0xbb, 0xcc}

	ch := chunkHeader{
		typ:   ctHeartbeatAck,
		flags: 0,
		raw:   body,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatAckParams)
}

func TestChunkHeartbeatAck_Unmarshal_Failure_TruncatedParamBody(t *testing.T) {
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

	truncated := pp[:len(pp)-1]

	ch := chunkHeader{
		typ:   ctHeartbeatAck,
		flags: 0,
		raw:   truncated,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatAckParams)
}

func TestChunkHeartbeatAck_Unmarshal_Failure_WrongParamType(t *testing.T) {
	// construct a TLV with a param type that is *not* heartbeatInfo but is otherwise valid.
	plen := uint16(initOptionalVarHeaderLength)
	body := []byte{
		0x00, 0x02, // some param type != heartbeatInfo (which is 1 per RFC)
		byte(plen >> 8),
		byte(plen & 0xff),
	}

	ch := chunkHeader{
		typ:   ctHeartbeatAck,
		flags: 0,
		raw:   body,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatAckNotHeartbeatInfo)
}

func TestChunkHeartbeatAck_Unmarshal_Failure_TrailingNonZero(t *testing.T) {
	info := []byte{0x01, 0x02, 0x03, 0x04}
	p := &paramHeartbeatInfo{heartbeatInformation: info}
	pp, err := p.marshal()
	if !assert.NoError(t, err) {
		return
	}

	// append a non-zero byte after the single parameter.
	body := append(append([]byte{}, pp...), 0x01)

	ch := chunkHeader{
		typ:   ctHeartbeatAck,
		flags: 0,
		raw:   body,
	}

	raw, err := ch.marshal()
	if !assert.NoError(t, err) {
		return
	}

	hbAck := &chunkHeartbeatAck{}
	err = hbAck.unmarshal(raw)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatExtraNonZero)
}

func TestChunkHeartbeatAck_Marshal_Failure_ParamCount(t *testing.T) {
	// no params
	hbAck := &chunkHeartbeatAck{}
	_, err := hbAck.marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatAckParams)

	// too many params
	p := &paramHeartbeatInfo{}
	hbAck = &chunkHeartbeatAck{
		params: []param{p, p},
	}
	_, err = hbAck.marshal()
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrHeartbeatAckParams)
}
