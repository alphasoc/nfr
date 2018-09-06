package alerts

// Writer interface for log api alerts response.
type Writer interface {
	Write(*Event) error
}

type Formatter interface {
	Format(*Event) []byte
}
