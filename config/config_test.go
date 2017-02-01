package config

import "testing"
import "os"

func TestSaveConfig(t *testing.T) {
	testFilePath := "/tmp/namescore_test.toml"
	defer os.Remove(testFilePath)

	c := Config{configFilePath: testFilePath, APIKey: "abcd", NetworkInterface: "eth0"}

	if c.ConfigFileExists() == true {
		t.Errorf("ConfigFileExists() returned unexpected true before storing file.")
	}

	if err := c.SaveToFile(); err != nil {
		t.Errorf("SaveToFile() unexpected err=%v", err)
	}

	if c.ConfigFileExists() == false {
		t.Errorf("ConfigFileExists() expected to have file after calling SaveToFile()")
	}

	if err := c.ReadFromFile(); err != nil {
		t.Errorf("ReadFromFile() expected error=%v", err)
	}

}
