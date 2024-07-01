package sctp

import "fmt"

type queue[T any] struct {
	buf   []T
	head  int
	tail  int
	count int
}

const minCap = 16

func newQueue[T any](capacity int) *queue[T] {
	queueCap := minCap
	for queueCap < capacity {
		queueCap <<= 1
	}

	return &queue[T]{
		buf: make([]T, queueCap),
	}
}

func (q *queue[T]) Len() int {
	return q.count
}

func (q *queue[T]) PushBack(ele T) {
	q.growIfFull()
	q.buf[q.tail] = ele
	q.tail = (q.tail + 1) % len(q.buf)
	q.count++
}

func (q *queue[T]) PopFront() T {
	if q.count <= 0 {
		panic("PopFront() called on empty queue")
	}
	ele := q.buf[q.head]
	var zeroVal T
	q.buf[q.head] = zeroVal
	q.head = (q.head + 1) % len(q.buf)
	q.count--
	return ele
}

func (q *queue[T]) Front() T {
	if q.count <= 0 {
		panic("Front() called on empty queue")
	}
	return q.buf[q.head]
}

func (q *queue[T]) At(i int) T {
	if i < 0 || i >= q.count {
		panic(fmt.Sprintf("index %d out of range %d", i, q.count))
	}
	return q.buf[(q.head+i)%(len(q.buf))]
}

func (q *queue[T]) growIfFull() {
	if q.count < len(q.buf) {
		return
	}

	newBuf := make([]T, q.count<<1)
	if q.tail > q.head {
		copy(newBuf, q.buf[q.head:q.tail])
	} else {
		n := copy(newBuf, q.buf[q.head:])
		copy(newBuf[n:], q.buf[:q.tail])
	}

	q.head = 0
	q.tail = q.count
	q.buf = newBuf
}
