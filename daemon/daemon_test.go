package daemon

import "testing"

func TestLock(t *testing.T) {
	err := LockSocket()
	if err != nil {
		t.Errorf("Locking failed %q", err)
	}

	err = LockSocket()
	if err == nil {
		t.Errorf("Expected error here.")
	}
}
