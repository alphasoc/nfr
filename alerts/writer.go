package alerts

// Writer interface for log api alerts response.
type Writer interface {
	Write(*Alert) error
}
