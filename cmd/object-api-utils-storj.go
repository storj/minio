package cmd

// AppendCleanupFunc adds fn which will be called in Close after
// all internal cleanup functions have been called.
func (reader *GetObjectReader) AppendCleanupFunc(fn func()) {
	// cleanUpFns are called in reverse order.
	reader.cleanUpFns = append([]func(){fn}, reader.cleanUpFns...)
}
