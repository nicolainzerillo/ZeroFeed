package feed

import (
	"sync"

	"github.com/zerofeed/zerofeed/pkg/crypto"
)

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 4096)
		return &b
	},
}

func getBuffer(size int) []byte {
	bp := bufPool.Get().(*[]byte)
	if cap(*bp) < size {
		*bp = make([]byte, size)
	} else {
		*bp = (*bp)[:size]
	}
	return *bp
}

func putBuffer(b []byte) {
	if b == nil {
		return
	}
	crypto.ZeroBytes(b)
	b = b[:0]
	bufPool.Put(&b)
}

// SeqMsg represents a sequence-numbered payload in RAM.
type SeqMsg struct {
	SeqNum  uint64
	Payload []byte
}

// RingBuffer represents an in-memory fixed-capacity circular buffer stored in RAM.
type RingBuffer struct {
	capacity int
	data     []SeqMsg
	head     int
	tail     int
	size     int
	mu       sync.RWMutex
}

// NewRingBuffer initializes a RingBuffer with the given maximum capacity (e.g. 100).
func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 100
	}
	return &RingBuffer{
		capacity: capacity,
		data:     make([]SeqMsg, capacity),
	}
}

// Push adds a new payload with an explicit sequence number to the ring buffer.
func (rb *RingBuffer) Push(seqNum uint64, msg []byte) {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	msgCopy := getBuffer(len(msg))
	copy(msgCopy, msg)

	if rb.size == rb.capacity {
		// Overwrite oldest item: scrub old memory and return to pool
		if rb.data[rb.head].Payload != nil {
			putBuffer(rb.data[rb.head].Payload)
			rb.data[rb.head].Payload = nil
		}
		rb.head = (rb.head + 1) % rb.capacity
		rb.size--
	}

	rb.data[rb.tail] = SeqMsg{
		SeqNum:  seqNum,
		Payload: msgCopy,
	}
	rb.tail = (rb.tail + 1) % rb.capacity
	rb.size++
}

// GetAfter returns all messages stored in RAM with a SeqNum strictly greater than lastSeqNum.
func (rb *RingBuffer) GetAfter(lastSeqNum uint64) []SeqMsg {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	var result []SeqMsg
	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		item := rb.data[idx]
		if item.SeqNum > lastSeqNum {
			payloadCopy := getBuffer(len(item.Payload))
			copy(payloadCopy, item.Payload)
			result = append(result, SeqMsg{
				SeqNum:  item.SeqNum,
				Payload: payloadCopy,
			})
		}
	}
	return result
}

// GetAll returns a slice containing copies of all current messages ordered from oldest to newest.
func (rb *RingBuffer) GetAll() [][]byte {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	result := make([][]byte, rb.size)
	for i := 0; i < rb.size; i++ {
		idx := (rb.head + i) % rb.capacity
		msgCopy := getBuffer(len(rb.data[idx].Payload))
		copy(msgCopy, rb.data[idx].Payload)
		result[i] = msgCopy
	}
	return result
}

// Len returns the current number of messages stored in the ring buffer.
func (rb *RingBuffer) Len() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	return rb.size
}

// OldestSeqNum returns the sequence number of the oldest message currently in RAM.
func (rb *RingBuffer) OldestSeqNum() uint64 {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 {
		return 0
	}
	return rb.data[rb.head].SeqNum
}

// IsOverflow checks if lastSeqNum missed messages that were already overwritten in RAM.
func (rb *RingBuffer) IsOverflow(lastSeqNum uint64) bool {
	rb.mu.RLock()
	defer rb.mu.RUnlock()

	if rb.size == 0 || lastSeqNum == 0 {
		return false
	}
	oldest := rb.data[rb.head].SeqNum
	return oldest > 0 && lastSeqNum < oldest-1
}

// Wipe explicitly overwrites all stored message buffers in RAM with zeros and resets pointers.
func (rb *RingBuffer) Wipe() {
	rb.mu.Lock()
	defer rb.mu.Unlock()

	for i := 0; i < rb.capacity; i++ {
		if rb.data[i].Payload != nil {
			putBuffer(rb.data[i].Payload)
			rb.data[i].Payload = nil
			rb.data[i].SeqNum = 0
		}
	}
	rb.head = 0
	rb.tail = 0
	rb.size = 0
}
