package sctp

type pendingQueue struct {
	queue  []*chunkPayloadData
	nBytes int
}

func newPendingQueue() *pendingQueue {
	return &pendingQueue{queue: []*chunkPayloadData{}}
}

func (q *pendingQueue) push(c *chunkPayloadData) {
	q.queue = append(q.queue, c)
	q.nBytes += len(c.userData)
}

func (q *pendingQueue) pop() *chunkPayloadData {
	if len(q.queue) == 0 {
		return nil
	}
	c := q.queue[0]
	q.queue = q.queue[1:]
	q.nBytes -= len(c.userData)
	return c
}

func (q *pendingQueue) get(i int) *chunkPayloadData {
	if len(q.queue) == 0 || i < 0 || i >= len(q.queue) {
		return nil
	}
	return q.queue[i]
}

func (q *pendingQueue) getNumBytes() int {
	return q.nBytes
}

func (q *pendingQueue) size() int {
	return len(q.queue)
}
