package config

import "testing"
import "os"

func TestSaveConfig(t *testing.T) {
	var (
		testFilePath = "/tmp/namescore_test/test/namescore_test.toml"
		apiKey       = "abcd"
		iface        = "eth0"
	)

	defer os.Remove(testFilePath)

	c := Config{configFilePath: testFilePath, APIKey: apiKey, NetworkInterface: iface}

	if c.ConfigFileExists() == true {
		t.Errorf("ConfigFileExists() returned unexpected true before storing file.")
	}

	if err := c.SaveToFile(); err != nil {
		t.Errorf("SaveToFile() unexpected err=%v", err)
	}

	if c.ConfigFileExists() == false {
		t.Errorf("ConfigFileExists() expected to have file after calling SaveToFile()")
	}
	c.APIKey = "key_should_be_overwritten"
	c.NetworkInterface = "iface_should_be_overwritten"

	if err := c.ReadFromFile(); err != nil {
		t.Errorf("ReadFromFile() expected error=%v", err)
	}

	if c.APIKey != apiKey {
		t.Errorf("c.APIKey expected %q, got %q", apiKey, c.APIKey)
	}

	if c.NetworkInterface != iface {
		t.Errorf("c.NetworkInterface expected %q, got %q", iface, c.NetworkInterface)
	}

}
