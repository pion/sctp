// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package sctp

type chunk interface {
	unmarshal(raw []byte) error
	marshal() ([]byte, error)
	check() (bool, error)

	valueLength() int
}
