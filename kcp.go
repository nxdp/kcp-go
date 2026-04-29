// The MIT License (MIT)
//
// Copyright (c) 2015 xtaci
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package kcp

import (
	"container/heap"
	"encoding/binary"
	"sync/atomic"
	"time"
)

// KCP Protocol Constants
const (
	// Retransmission Timeout (RTO) bounds, in milliseconds
	IKCP_RTO_NDL = 30    // no-delay mode: minimum RTO (ms)
	IKCP_RTO_MIN = 100   // normal mode: minimum RTO (ms)
	IKCP_RTO_DEF = 200   // default RTO (ms)
	IKCP_RTO_MAX = 60000 // maximum RTO (ms), 60 seconds

	// Command types for the KCP segment header (cmd field)
	IKCP_CMD_PUSH = 81 // cmd: push data
	IKCP_CMD_ACK  = 82 // cmd: acknowledge

	// Default window and MTU sizes
	IKCP_WND_SND = 32   // default send window size (packets)
	IKCP_WND_RCV = 32   // default receive window size (packets)
	IKCP_MTU_DEF = 1400 // default MTU (bytes, not including UDP/IP header)

	// Protocol parameters
	IKCP_ACK_FAST    = 3   // fast retransmit trigger threshold (duplicate ACK count)
	IKCP_INTERVAL    = 100 // default flush interval (ms)
	IKCP_OVERHEAD    = 8   // per-segment header size: conv(2) + cmd(1) + frg(1) + sn(2) + una(2)
	IKCP_DEADLINK    = 20  // max retransmissions before declaring dead link
	IKCP_THRESH_INIT = 2   // initial slow-start threshold (packets)
	IKCP_THRESH_MIN  = 2   // minimum slow-start threshold (packets)
	IKCP_SN_OFFSET   = 4   // byte offset of sequence number (sn) within the segment header
)

type PacketType int8

const (
	IKCP_PACKET_REGULAR PacketType = iota
	IKCP_PACKET_FEC
)

type FlushType int8

const (
	IKCP_FLUSH_ACKONLY FlushType = 1 << iota
	IKCP_FLUSH_FULL
)

type KCPLogType int32

const (
	IKCP_LOG_OUTPUT KCPLogType = 1 << iota
	IKCP_LOG_INPUT
	IKCP_LOG_SEND
	IKCP_LOG_RECV
	IKCP_LOG_OUT_ACK
	IKCP_LOG_OUT_PUSH
	IKCP_LOG_OUT_WASK
	IKCP_LOG_OUT_WINS
	IKCP_LOG_IN_ACK
	IKCP_LOG_IN_PUSH
	IKCP_LOG_IN_WASK
	IKCP_LOG_IN_WINS
)

const (
	IKCP_LOG_OUTPUT_ALL = IKCP_LOG_OUTPUT | IKCP_LOG_OUT_ACK | IKCP_LOG_OUT_PUSH | IKCP_LOG_OUT_WASK | IKCP_LOG_OUT_WINS
	IKCP_LOG_INPUT_ALL  = IKCP_LOG_INPUT | IKCP_LOG_IN_ACK | IKCP_LOG_IN_PUSH | IKCP_LOG_IN_WASK | IKCP_LOG_IN_WINS
	IKCP_LOG_ALL        = IKCP_LOG_OUTPUT_ALL | IKCP_LOG_INPUT_ALL | IKCP_LOG_SEND | IKCP_LOG_RECV
)

// monotonic reference time point
var refTime time.Time = time.Now()

// currentMs returns current elapsed monotonic milliseconds since program startup
func currentMs() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }

// output_callback is a prototype which ought capture conn and call conn.Write
type output_callback func(buf []byte, size int)

// logoutput_callback is a prototype which logging kcp trace output
type logoutput_callback func(msg string, args ...any)

func _itimediff(later, earlier uint32) int32 {
	return (int32)(later - earlier)
}

func _itimediff16(later, earlier uint16) int32 {
	return int32(int16(later - earlier))
}

// segment defines a KCP segment
type segment struct {
	conv     uint16
	cmd      uint8
	frg      uint8
	sn       uint16
	una      uint16
	rto      uint32
	xmit     uint32
	resendts uint32
	fastack  uint32
	acked    uint32 // mark if the seg has acked
	data     []byte
}

// encode a segment header into buffer
func (seg *segment) encode(ptr []byte) []byte {
	_ = ptr[IKCP_OVERHEAD-1] // BCE hint
	binary.LittleEndian.PutUint16(ptr, seg.conv)
	ptr[2] = seg.cmd
	ptr[3] = seg.frg
	binary.LittleEndian.PutUint16(ptr[4:], seg.sn)
	binary.LittleEndian.PutUint16(ptr[6:], seg.una)
	atomic.AddUint64(&DefaultSnmp.OutSegs, 1)
	return ptr[IKCP_OVERHEAD:]
}

// segmentHeap is a min-heap of segments, used for receiving segments in order
type segmentHeap struct {
	segments []segment
	marks    map[uint16]struct{} // to avoid duplicates
}

func newSegmentHeap() *segmentHeap {
	h := &segmentHeap{
		marks: make(map[uint16]struct{}),
	}
	heap.Init(h)
	return h
}

func (h *segmentHeap) Len() int { return len(h.segments) }

func (h *segmentHeap) Less(i, j int) bool {
	return _itimediff16(h.segments[j].sn, h.segments[i].sn) > 0
}

func (h *segmentHeap) Swap(i, j int) { h.segments[i], h.segments[j] = h.segments[j], h.segments[i] }
func (h *segmentHeap) Push(x any) {
	h.segments = append(h.segments, x.(segment))
	h.marks[x.(segment).sn] = struct{}{}
}

func (h *segmentHeap) Pop() any {
	n := len(h.segments)
	x := h.segments[n-1]
	h.segments[n-1] = segment{} // clear reference to avoid memory leak
	h.segments = h.segments[0 : n-1]
	delete(h.marks, x.sn)
	return x
}

func (h *segmentHeap) Has(sn uint16) bool {
	_, exists := h.marks[sn]
	return exists
}

// KCP defines a single KCP connection's protocol state machine.
// It is a pure ARQ (Automatic Repeat reQuest) implementation with no I/O.
type KCP struct {
	// Connection identity and framing
	conv  uint16 // conversation id, must be equal on both sides
	mtu   uint32 // maximum transmission unit (bytes)
	mss   uint32 // maximum segment size = mtu - IKCP_OVERHEAD
	state uint32 // connection state, 0 = active, 0xFFFFFFFF = dead link

	// Sequence numbers and acknowledgment tracking
	snd_una uint16 // oldest unacknowledged sequence number
	snd_nxt uint16 // next sequence number to send
	rcv_nxt uint16 // next expected sequence number to receive

	// Congestion control (RFC 5681 / RFC 6937)
	ssthresh           uint32 // slow-start threshold (packets)
	rx_rttvar, rx_srtt int32  // RTT variance and smoothed RTT (ms), per RFC 6298
	rx_rto, rx_minrto  uint32 // retransmission timeout and its lower bound (ms)
	snd_wnd            uint32 // local send window size (packets)
	rcv_wnd            uint32 // local receive window size (packets)
	rmt_wnd            uint32 // remote receive window size (packets); configured locally when wnd is removed from the wire
	cwnd               uint32 // congestion window (packets)
	incr               uint32 // bytes accumulated for cwnd increment

	// Timers and scheduling
	interval uint32 // flush interval (ms)
	ts_flush uint32 // next flush timestamp (ms)
	nodelay  uint32 // 0: normal, 1: no-delay mode (reduces RTO aggressively)
	updated  uint32 // whether Update() has been called at least once
	// ACK suppression
	lastAckTime uint32 // last time an ACK was sent (standalone or piggybacked)
	ackTimeout  uint32 // standalone ACK timeout in milliseconds

	// Reliability
	dead_link  uint32 // max retransmit count before link is considered dead
	fastresend int32  // fast retransmit trigger count, 0 = disabled
	nocwnd     int32  // 1 = disable congestion control
	stream     int32  // 1 = stream mode (no message boundaries), 0 = message mode

	// Logging
	logmask KCPLogType

	// Data queues and buffers
	snd_queue *RingBuffer[segment] // send queue: segments waiting to enter the send window
	rcv_queue *RingBuffer[segment] // receive queue: ordered segments ready for user read
	snd_buf   *RingBuffer[segment] // send buffer: segments in-flight (sent but unacknowledged)
	rcv_buf   *segmentHeap         // receive buffer: out-of-order segments awaiting reordering

	acklist []ackItem // pending ACKs to be flushed

	buffer []byte          // pre-allocated encoding buffer for flush()
	output output_callback // callback to write data to the underlying transport

	log logoutput_callback // trace log callback
}

type ackItem struct {
	sn uint16
}

// NewKCP create a new kcp state machine
//
// 'conv' must be equal in the connection peers, or else data will be silently rejected.
//
// 'output' function will be called whenever these is data to be sent on wire.
func NewKCP(conv uint16, output output_callback) *KCP {
	kcp := new(KCP)
	kcp.conv = conv
	kcp.snd_wnd = IKCP_WND_SND
	kcp.rcv_wnd = IKCP_WND_RCV
	kcp.rmt_wnd = IKCP_WND_RCV
	kcp.mtu = IKCP_MTU_DEF
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (kcp.mtu+IKCP_OVERHEAD)*3)
	kcp.rx_rto = IKCP_RTO_DEF
	kcp.rx_minrto = IKCP_RTO_MIN
	kcp.interval = IKCP_INTERVAL
	kcp.ts_flush = IKCP_INTERVAL
	kcp.ssthresh = IKCP_THRESH_INIT
	kcp.dead_link = IKCP_DEADLINK
	kcp.ackTimeout = 500
	kcp.output = output
	kcp.snd_buf = NewRingBuffer[segment](IKCP_WND_SND * 2)
	kcp.rcv_queue = NewRingBuffer[segment](IKCP_WND_RCV * 2)
	kcp.snd_queue = NewRingBuffer[segment](IKCP_WND_SND * 2)
	kcp.rcv_buf = newSegmentHeap()
	return kcp
}

// newSegment creates a KCP segment
func (kcp *KCP) newSegment(size int) (seg segment) {
	seg.data = defaultBufferPool.Get()[:size]
	return
}

// recycleSegment recycles a KCP segment
func (kcp *KCP) recycleSegment(seg *segment) {
	if seg.data != nil {
		defaultBufferPool.Put(seg.data)
		seg.data = nil
	}
}

// PeekSize checks the size of next message in the recv queue
func (kcp *KCP) PeekSize() (length int) {
	seg, ok := kcp.rcv_queue.Peek()
	if !ok {
		return -1
	}

	if seg.frg == 0 {
		return len(seg.data)
	}

	if kcp.rcv_queue.Len() < int(seg.frg+1) {
		return -1
	}

	for seg := range kcp.rcv_queue.ForEach {
		length += len(seg.data)
		if seg.frg == 0 {
			break
		}
	}
	return
}

// Receive data from kcp state machine
//
// Return number of bytes read.
//
// Return -1 when there is no readable data.
//
// Return -2 if len(buffer) is smaller than kcp.PeekSize().
func (kcp *KCP) Recv(buffer []byte) (n int) {
	peeksize := kcp.PeekSize()
	if peeksize < 0 {
		return -1
	}

	if peeksize > len(buffer) {
		return -2
	}

	// merge fragment
	for {
		seg, ok := kcp.rcv_queue.Pop()
		if !ok {
			break
		}

		copy(buffer, seg.data)
		buffer = buffer[len(seg.data):]
		n += len(seg.data)
		kcp.recycleSegment(&seg)
		if seg.frg == 0 {
			kcp.debugLog(IKCP_LOG_RECV, "stream", kcp.stream, "conv", kcp.conv, "sn", seg.sn, "datalen", n)
			break
		}
	}

	// move available data from rcv_buf -> rcv_queue
	for kcp.rcv_buf.Len() > 0 {
		seg := heap.Pop(kcp.rcv_buf).(segment)
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
			kcp.rcv_queue.Push(seg)
			kcp.rcv_nxt++
		} else {
			// push back segment
			heap.Push(kcp.rcv_buf, seg)
			break
		}
	}
	return
}

// Send is user/upper level send, returns below zero for error
func (kcp *KCP) Send(buffer []byte) int {
	var count int
	if len(buffer) == 0 {
		return -1
	}

	kcp.debugLog(IKCP_LOG_SEND, "stream", kcp.stream, "conv", kcp.conv, "datalen", len(buffer))

	// append to previous segment in streaming mode (if possible)
	if kcp.stream != 0 {
		if n := kcp.snd_queue.Len(); n > 0 {
			for seg := range kcp.snd_queue.ForEachReverse {
				if len(seg.data) < int(kcp.mss) {
					capacity := int(kcp.mss) - len(seg.data)
					extend := min(len(buffer), capacity)

					// grow slice, the underlying cap is guaranteed to
					// be larger than kcp.mss
					oldlen := len(seg.data)
					seg.data = seg.data[:oldlen+extend]
					copy(seg.data[oldlen:], buffer)
					buffer = buffer[extend:]
				}
				break
			}
		}

		if len(buffer) == 0 {
			return 0
		}
	}

	if len(buffer) <= int(kcp.mss) {
		count = 1
	} else {
		count = (len(buffer) + int(kcp.mss) - 1) / int(kcp.mss)
	}

	if count > 255 {
		return -2
	}

	if count == 0 {
		count = 1
	}

	for i := 0; i < count; i++ {
		var size int
		size = min(len(buffer), int(kcp.mss))
		seg := kcp.newSegment(size)
		copy(seg.data, buffer[:size])
		if kcp.stream == 0 { // message mode
			seg.frg = uint8(count - i - 1)
		} else { // stream mode
			seg.frg = 0
		}

		kcp.snd_queue.Push(seg)
		buffer = buffer[size:]
	}
	return 0
}

// update_ack updates the smoothed RTT and RTO based on a new RTT sample.
// Algorithm follows RFC 6298: Computing TCP's Retransmission Timer.
func (kcp *KCP) update_ack(rtt int32) {
	var rto uint32
	if kcp.rx_srtt == 0 {
		kcp.rx_srtt = rtt
		kcp.rx_rttvar = rtt >> 1
	} else {
		delta := rtt - kcp.rx_srtt
		kcp.rx_srtt += delta >> 3
		if delta < 0 {
			delta = -delta
		}
		if rtt < kcp.rx_srtt-kcp.rx_rttvar {
			// if the new RTT sample is below the bottom of the range of
			// what an RTT measurement is expected to be.
			// give an 8x reduced weight versus its normal weighting
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 5
		} else {
			kcp.rx_rttvar += (delta - kcp.rx_rttvar) >> 2
		}
	}
	rto = uint32(kcp.rx_srtt) + max(kcp.interval, uint32(kcp.rx_rttvar)<<2)
	kcp.rx_rto = min(max(kcp.rx_minrto, rto), IKCP_RTO_MAX)
}

// shrink_buf advances snd_una to the oldest unacknowledged segment in snd_buf.
func (kcp *KCP) shrink_buf() {
	if seg, ok := kcp.snd_buf.Peek(); ok {
		kcp.snd_una = seg.sn
	} else {
		kcp.snd_una = kcp.snd_nxt
	}
}

// parse_ack marks a segment as acknowledged in snd_buf by sequence number.
// The segment is not removed immediately; it stays until snd_una advances past it,
// avoiding expensive shifts in the ring buffer.
func (kcp *KCP) parse_ack(sn uint16) {
	if _itimediff16(sn, kcp.snd_una) < 0 || _itimediff16(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for seg := range kcp.snd_buf.ForEach {
		if sn == seg.sn {
			// mark and free space, but leave the segment here,
			// and wait until `una` to delete this, then we don't
			// have to shift the segments behind forward,
			// which is an expensive operation for large window
			seg.acked = 1
			kcp.recycleSegment(seg)
			break
		}
		if _itimediff16(sn, seg.sn) < 0 {
			break
		}
	}
}

// parse_fastack increments the fast-ack counter for segments with sn < the given sn.
// Returns 1 if any segment's fastack counter has reached the fast retransmit threshold.
func (kcp *KCP) parse_fastack(sn uint16) int {
	shouldFastAck := 0
	if _itimediff16(sn, kcp.snd_una) < 0 || _itimediff16(sn, kcp.snd_nxt) >= 0 {
		return 0
	}

	for seg := range kcp.snd_buf.ForEach {
		if _itimediff16(sn, seg.sn) < 0 {
			break
		} else if sn != seg.sn {
			if seg.fastack != 0xFFFFFFFF {
				seg.fastack++
				if seg.fastack >= uint32(kcp.fastresend) {
					shouldFastAck = 1
				}
			}
		}
	}

	return shouldFastAck
}

// parse_una removes all segments from snd_buf that have been cumulatively acknowledged
// (i.e., segments with sn < una). Returns the number of segments removed.
func (kcp *KCP) parse_una(una uint16) int {
	count := 0
	for seg := range kcp.snd_buf.ForEach {
		if _itimediff16(una, seg.sn) > 0 {
			kcp.recycleSegment(seg)
			count++
		} else {
			break
		}
	}
	kcp.snd_buf.Discard(count)
	return count
}

// ack append
func (kcp *KCP) ack_push(sn uint16) {
	kcp.acklist = append(kcp.acklist, ackItem{sn})
}

// returns true if data has repeated
func (kcp *KCP) parse_data(newseg segment) bool {
	sn := newseg.sn
	if _itimediff16(sn, kcp.rcv_nxt+uint16(kcp.rcv_wnd)) >= 0 ||
		_itimediff16(sn, kcp.rcv_nxt) < 0 {
		return true
	}

	repeat := false
	if !kcp.rcv_buf.Has(sn) {
		// replicate the content if it's new
		dataCopy := defaultBufferPool.Get()[:len(newseg.data)]
		copy(dataCopy, newseg.data)
		newseg.data = dataCopy

		// insert the new segment into rcv_buf
		heap.Push(kcp.rcv_buf, newseg)
	} else {
		repeat = true
	}

	// move available data from rcv_buf -> rcv_queue
	for kcp.rcv_buf.Len() > 0 {
		seg := heap.Pop(kcp.rcv_buf).(segment)
		if seg.sn == kcp.rcv_nxt && kcp.rcv_queue.Len() < int(kcp.rcv_wnd) {
			kcp.rcv_queue.Push(seg)
			kcp.rcv_nxt++
		} else {
			// push back segment
			heap.Push(kcp.rcv_buf, seg)
			break
		}
	}

	return repeat
}

// Input a packet into kcp state machine.
//
// 'regular' indicates it's a real data packet from remote, and it means it's not generated from ReedSolomon
// codecs.
//
// 'ackNoDelay' will trigger immediate ACK, but surely it will not be efficient in bandwidth
func (kcp *KCP) Input(data []byte, pktType PacketType, ackNoDelay bool) int {
	snd_una := kcp.snd_una
	if len(data) < IKCP_OVERHEAD {
		return -1
	}

	var inSegs uint64
	var flushSegments int // signal to flush segments

	for {
		if len(data) < int(IKCP_OVERHEAD) {
			break
		}

		_ = data[IKCP_OVERHEAD-1] // BCE hint
		conv := binary.LittleEndian.Uint16(data)
		cmd := data[2]
		frg := data[3]
		sn := binary.LittleEndian.Uint16(data[4:])
		una := binary.LittleEndian.Uint16(data[6:])
		data = data[IKCP_OVERHEAD:]
		// One KCP segment per DNS packet. The DNS wire layer must strip all framing
		// and pass exact payload bytes with no trailing padding before calling Input().
		// length = all remaining bytes after the header.
		length := uint32(len(data))

		if conv != kcp.conv {
			return -1
		}

		kcp.debugLog(IKCP_LOG_INPUT, "conv", conv, "cmd", cmd, "frg", frg, "sn", sn, "una", una, "datalen", len(data))

		if len(data) < int(length) {
			return -2
		}

		if cmd != IKCP_CMD_PUSH && cmd != IKCP_CMD_ACK {
			return -3
		}

		if kcp.parse_una(una) > 0 {
			flushSegments |= 1
		}
		kcp.shrink_buf()

		switch cmd {
		case IKCP_CMD_ACK:
			kcp.debugLog(IKCP_LOG_IN_ACK, "conv", conv, "sn", sn, "una", una, "rto", kcp.rx_rto)
			kcp.parse_ack(sn)
			flushSegments |= kcp.parse_fastack(sn)
		case IKCP_CMD_PUSH:
			repeat := true
			if _itimediff16(sn, kcp.rcv_nxt+uint16(kcp.rcv_wnd)) < 0 {
				kcp.ack_push(sn)
				if _itimediff16(sn, kcp.rcv_nxt) >= 0 {
					repeat = kcp.parse_data(segment{
						conv: conv, cmd: cmd, frg: frg, sn: sn, una: una,
						data: data[:length], // delayed data copying
					})
				}
			}
			if pktType == IKCP_PACKET_REGULAR && repeat {
				atomic.AddUint64(&DefaultSnmp.RepeatSegs, 1)
			}
			kcp.debugLog(IKCP_LOG_IN_PUSH, "conv", conv, "sn", sn, "una", una, "packettype", pktType, "repeat", repeat)
		default:
			return -3
		}

		inSegs++
		data = data[length:]
	}
	atomic.AddUint64(&DefaultSnmp.InSegs, inSegs)

	// Congestion window (cwnd) update on ACK arrival.
	// Uses Reno-style algorithm: slow-start below ssthresh, then AIMD.
	if kcp.nocwnd == 0 {
		if _itimediff16(kcp.snd_una, snd_una) > 0 {
			if kcp.cwnd < kcp.rmt_wnd {
				mss := kcp.mss
				if kcp.cwnd < kcp.ssthresh {
					kcp.cwnd++
					kcp.incr += mss
				} else {
					if kcp.incr < mss {
						kcp.incr = mss
					}
					kcp.incr += (mss*mss)/kcp.incr + (mss / 16)
					if (kcp.cwnd+1)*mss <= kcp.incr {
						if mss > 0 {
							kcp.cwnd = (kcp.incr + mss - 1) / mss
						} else {
							kcp.cwnd = kcp.incr + mss - 1
						}
					}
				}
				if kcp.cwnd > kcp.rmt_wnd {
					kcp.cwnd = kcp.rmt_wnd
					kcp.incr = kcp.rmt_wnd * mss
				}
			}
		}
	}

	// Determine if we need to flush data segments or acks
	if flushSegments != 0 {
		// If window has slided or, a fastack should be triggered,
		// Flush immediately. In previous implementations, we only
		// send out fastacks when interval timeouts, so the resending packets
		// have to wait until then. Now, we try to flush as soon as we can.
		kcp.flush(IKCP_FLUSH_FULL)
	} else if len(kcp.acklist) >= int(kcp.mtu/IKCP_OVERHEAD) { // clocking
		// This serves as the clock for low-latency network.(i.e. the latency is less than the interval.)
		// If the other end is waiting for confirmations, it has to want until the interval timeouts then
		// the flush() is triggered to send out the una & acks. In low-latency network, the interval time is too long to wait,
		// so acks have to be sent out immediately when there are too many.
		kcp.flush(IKCP_FLUSH_ACKONLY)
	} else if ackNoDelay && len(kcp.acklist) > 0 { // testing(xtaci): ack immediately if acNoDelay is set
		kcp.flush(IKCP_FLUSH_ACKONLY)
	}
	return 0
}

// flush sends pending data through the KCP output callback.
// This is the core scheduling function, organized in 4 phases:
//
//	Phase 1: Flush pending ACKs
//	Phase 2: Move segments from snd_queue to snd_buf (sliding window)
//	Phase 3: Retransmit segments (initial, fast, early, RTO)
//	Phase 4: Update SNMP counters and congestion window
//
// Returns the suggested interval (ms) until the next flush call.
func (kcp *KCP) flush(flushType FlushType) (nextUpdate uint32) {
	var seg segment
	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.una = kcp.rcv_nxt

	buffer := kcp.buffer
	ptr := buffer

	// makeSpace makes room for writing
	makeSpace := func(space int) {
		size := len(buffer) - len(ptr)
		if size+space > int(kcp.mtu) {
			kcp.output(buffer, size)
			ptr = buffer
		}
	}

	// flush bytes in buffer if there is any
	flushBuffer := func() {
		size := len(buffer) - len(ptr)
		if size > 0 {
			kcp.output(buffer, size)
		}
	}

	defer func() {
		flushBuffer()
		atomic.StoreUint64(&DefaultSnmp.RingBufferSndQueue, uint64(kcp.snd_queue.Len()))
		atomic.StoreUint64(&DefaultSnmp.RingBufferRcvQueue, uint64(kcp.rcv_queue.Len()))
		atomic.StoreUint64(&DefaultSnmp.RingBufferSndBuffer, uint64(kcp.snd_buf.Len()))
	}()

	// --- Phase 1: Flush pending ACKs ---
	if flushType == IKCP_FLUSH_ACKONLY || flushType == IKCP_FLUSH_FULL {
		for i, ack := range kcp.acklist {
			makeSpace(IKCP_OVERHEAD)
			// filter jitters caused by bufferbloat
			if _itimediff16(ack.sn, kcp.rcv_nxt) >= 0 || len(kcp.acklist)-1 == i {
				seg.sn = ack.sn
				ptr = seg.encode(ptr)
				kcp.debugLog(IKCP_LOG_OUT_ACK, "conv", seg.conv, "sn", seg.sn, "una", seg.una)
			}
		}
		kcp.acklist = kcp.acklist[0:0]
		kcp.lastAckTime = currentMs()
	}

	// --- Phase 2: Move segments from snd_queue to snd_buf (sliding window) ---
	// Effective window = min(snd_wnd, rmt_wnd, cwnd)
	cwnd := min(kcp.snd_wnd, kcp.rmt_wnd)
	if kcp.nocwnd == 0 {
		cwnd = min(kcp.cwnd, cwnd)
	}

	newSegsCount := 0
	for {
		if _itimediff16(kcp.snd_nxt, kcp.snd_una+uint16(cwnd)) >= 0 {
			break
		}

		newseg, ok := kcp.snd_queue.Pop()
		if !ok {
			break
		}

		newseg.conv = kcp.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.sn = kcp.snd_nxt
		kcp.snd_buf.Push(newseg)
		kcp.snd_nxt++
		newSegsCount++
	}

	// calculate resent
	resent := uint32(kcp.fastresend)
	if kcp.fastresend <= 0 {
		resent = 0xffffffff
	}

	// --- Phase 3: Retransmit segments from snd_buf ---
	// Determines which segments need (re)transmission:
	// - Initial transmit (xmit == 0)
	// - Fast retransmit (fastack >= fastresend threshold)
	// - Early retransmit (fastack > 0, no new segments queued)
	// - RTO-based retransmit (current >= resendts)
	current := currentMs()
	var change, lostSegs, fastRetransSegs, earlyRetransSegs uint64
	nextUpdate = kcp.interval

	if flushType == IKCP_FLUSH_FULL {
		for segment := range kcp.snd_buf.ForEach {
			needsend := false
			if segment.acked == 1 {
				continue
			}
			if segment.xmit == 0 { // initial transmit
				needsend = true
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
			} else if segment.fastack >= resent && segment.fastack != 0xFFFFFFFF { // fast retransmit
				needsend = true
				segment.fastack = 0xFFFFFFFF // must wait until RTO to reset
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
				change++
				fastRetransSegs++
			} else if segment.fastack > 0 && segment.fastack != 0xFFFFFFFF && newSegsCount == 0 { // early retransmit
				needsend = true
				segment.fastack = 0xFFFFFFFF
				segment.rto = kcp.rx_rto
				segment.resendts = current + segment.rto
				change++
				earlyRetransSegs++
			} else if _itimediff(current, segment.resendts) >= 0 { // RTO
				needsend = true
				if kcp.nodelay == 0 {
					segment.rto += kcp.rx_rto
				} else {
					segment.rto += kcp.rx_rto / 2
				}
				segment.fastack = 0
				segment.resendts = current + segment.rto
				lostSegs++
			}

			if needsend {
				current = currentMs()
				segment.xmit++
				segment.una = seg.una

				need := IKCP_OVERHEAD + len(segment.data)
				makeSpace(need)
				kcp.lastAckTime = current
				ptr = segment.encode(ptr)
				copy(ptr, segment.data)
				ptr = ptr[len(segment.data):]

				kcp.debugLog(IKCP_LOG_OUT_PUSH, "conv", segment.conv, "sn", segment.sn, "frg", segment.frg, "una", segment.una, "xmit", segment.xmit, "datalen", len(segment.data))

				if segment.xmit >= kcp.dead_link {
					kcp.state = 0xFFFFFFFF // mark connection as dead
				}
			}

			// get the nearest rto
			if rto := _itimediff(segment.resendts, current); rto > 0 && uint32(rto) < nextUpdate {
				nextUpdate = uint32(rto)
			}
		}
	}

	// --- Phase 4: Update SNMP counters and congestion window ---
	sum := lostSegs
	if lostSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.LostSegs, lostSegs)
	}
	if fastRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.FastRetransSegs, fastRetransSegs)
		sum += fastRetransSegs
	}
	if earlyRetransSegs > 0 {
		atomic.AddUint64(&DefaultSnmp.EarlyRetransSegs, earlyRetransSegs)
		sum += earlyRetransSegs
	}
	if sum > 0 {
		atomic.AddUint64(&DefaultSnmp.RetransSegs, sum)
	}

	// cwnd update
	if kcp.nocwnd == 0 {
		// Update ssthresh after fast retransmit.
		// Rate halving per RFC 6937: ssthresh = inflight / 2
		if change > 0 {
			inflight := uint32(uint16(kcp.snd_nxt - kcp.snd_una))
			kcp.ssthresh = max(inflight/2, IKCP_THRESH_MIN)
			kcp.cwnd = kcp.ssthresh + resent
			kcp.incr = kcp.cwnd * kcp.mss
		}

		// Congestion control after RTO: reset cwnd per RFC 5681
		if lostSegs > 0 {
			kcp.ssthresh = max(cwnd/2, IKCP_THRESH_MIN)
			kcp.cwnd = 1
			kcp.incr = kcp.mss
		}

		if kcp.cwnd < 1 {
			kcp.cwnd = 1
			kcp.incr = kcp.mss
		}
	}

	return nextUpdate
}

// (deprecated)
//
// Update updates state (call it repeatedly, every 10ms-100ms), or you can ask
// ikcp_check when to call it again (without ikcp_input/_send calling).
// 'current' - current timestamp in millisec.
func (kcp *KCP) Update() {
	var slap int32

	current := currentMs()
	if kcp.updated == 0 {
		kcp.updated = 1
		kcp.ts_flush = current
	}

	slap = _itimediff(current, kcp.ts_flush)

	if slap >= 10000 || slap < -10000 {
		kcp.ts_flush = current
		slap = 0
	}

	if slap >= 0 {
		kcp.ts_flush += kcp.interval
		if _itimediff(current, kcp.ts_flush) >= 0 {
			kcp.ts_flush = current + kcp.interval
		}
		kcp.flush(IKCP_FLUSH_FULL)
	}
}

// (deprecated)
//
// Check determines when should you invoke ikcp_update:
// returns when you should invoke ikcp_update in millisec, if there
// is no ikcp_input/_send calling. you can call ikcp_update in that
// time, instead of call update repeatly.
// Important to reduce unnacessary ikcp_update invoking. use it to
// schedule ikcp_update (eg. implementing an epoll-like mechanism,
// or optimize ikcp_update when handling massive kcp connections)
func (kcp *KCP) Check() uint32 {
	current := currentMs()
	ts_flush := kcp.ts_flush
	tm_flush := int32(0x7fffffff)
	tm_packet := int32(0x7fffffff)
	minimal := uint32(0)
	if kcp.updated == 0 {
		return current
	}

	if _itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000 {
		ts_flush = current
	}

	if _itimediff(current, ts_flush) >= 0 {
		return current
	}

	tm_flush = _itimediff(ts_flush, current)

	for seg := range kcp.snd_buf.ForEach {
		diff := _itimediff(seg.resendts, current)
		if diff <= 0 {
			return current
		}
		if diff < tm_packet {
			tm_packet = diff
		}
	}

	minimal = uint32(tm_packet)
	if tm_packet >= tm_flush {
		minimal = uint32(tm_flush)
	}
	if minimal >= kcp.interval {
		minimal = kcp.interval
	}

	return current + minimal
}

// SetMtu changes MTU size, default is 1400
func (kcp *KCP) SetMtu(mtu int) int {
	if mtu <= IKCP_OVERHEAD {
		return -1
	}

	kcp.mtu = uint32(mtu)
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = make([]byte, (mtu+IKCP_OVERHEAD)*3)
	return 0
}

// NoDelay options
// fastest: ikcp_nodelay(kcp, 1, 20, 2, 1)
// nodelay: 0:disable(default), 1:enable
// interval: internal update timer interval in millisec, default is 100ms
// resend: 0:disable fast resend(default), 1:enable fast resend
// nc: 0:normal congestion control(default), 1:disable congestion control
func (kcp *KCP) NoDelay(nodelay, interval, resend, nc int) int {
	if nodelay >= 0 {
		kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			kcp.rx_minrto = IKCP_RTO_MIN
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		kcp.fastresend = int32(resend)
	}
	if nc >= 0 {
		kcp.nocwnd = int32(nc)
	}
	return 0
}

func (kcp *KCP) SetAckTimeout(ms uint32) {
	kcp.ackTimeout = ms
}

// WndSize sets maximum window size: sndwnd=32, rcvwnd=32 by default
func (kcp *KCP) WndSize(sndwnd, rcvwnd int) int {
	if sndwnd > 0 {
		if sndwnd > 0xFFFF {
			sndwnd = 0xFFFF
		}
		kcp.snd_wnd = uint32(sndwnd)
	}
	if rcvwnd > 0 {
		if rcvwnd > 0xFFFF {
			rcvwnd = 0xFFFF
		}
		kcp.rcv_wnd = uint32(rcvwnd)
		kcp.rmt_wnd = uint32(rcvwnd)
	}
	return 0
}

// WaitSnd gets how many packet is waiting to be sent
func (kcp *KCP) WaitSnd() int {
	return kcp.snd_buf.Len() + kcp.snd_queue.Len()
}

// SetLogger configures the trace logger
func (kcp *KCP) SetLogger(mask KCPLogType, logger logoutput_callback) {
	if logger == nil {
		kcp.logmask = 0
		return
	}
	kcp.logmask = mask
	kcp.log = logger
}
