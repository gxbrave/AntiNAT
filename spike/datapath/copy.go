package datapath

import (
	"io"
	"net"
)

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func CopyTCP(destination, source *net.TCPConn, spliceEligible bool) (int64, error) {
	if spliceEligible {
		return io.Copy(destination, source)
	}
	buffer := make([]byte, fallbackBufferBytesPerDirection)
	return io.CopyBuffer(writerOnly{destination}, readerOnly{source}, buffer)
}
