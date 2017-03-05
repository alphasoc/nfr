package utils

import "testing"

func TestLock(t *testing.T) {
	_, err := LockSocket()
	if err != nil {
		t.Errorf("Locking failed %q", err)
	}

	_, err = LockSocket()
	if err == nil {
		t.Errorf("Expected error here.")
	}
}
