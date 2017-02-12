package config

import "testing"
import "os"
import "io/ioutil"
import "bytes"

func TestSaveConfig(t *testing.T) {
	var (
		testFilePath = "/tmp/namescore_test/test/namescore_test.toml"
		apiKey       = "abcd"
		iface        = "eth0"
	)
	defer os.Remove(testFilePath)

	c := Config{configFilePath: testFilePath, APIKey: apiKey, NetworkInterface: iface}

	if exist, err := c.ConfigFileExists(); err != nil {
		t.Errorf("ConfigFileExists() unexpected error=%v", err)
	} else if exist == true {
		t.Errorf("ConfigFileExists() returned unexpected true before storing file.")
	}

	if err := c.SaveToFile(); err != nil {
		t.Errorf("SaveToFile() unexpected err=%v", err)
	}

	if exist, err := c.ConfigFileExists(); err != nil {
		t.Errorf("ConfigFileExists() unexpected error=%v after saving file", err)
	} else if exist == false {
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

func TestDoubleSaveConfig(t *testing.T) {
	var (
		testFilePath = "/tmp/namescore_config_save/test/namescore_test.toml"
		apiKey       = "defgh"
		iface        = "eth1"
	)
	defer os.Remove(testFilePath)

	c := Config{configFilePath: testFilePath, APIKey: apiKey, NetworkInterface: iface}
	if err := c.SaveToFile(); err != nil {
		t.Errorf("SaveToFile() unexpected err=%v", err)
	}

	content1, err := ioutil.ReadFile(testFilePath)
	if err != nil {
		t.Errorf("ReadFile() unexpected err=%v", err)
	}

	if len(content1) == 0 {
		t.Errorf("%q is empty file after saving", testFilePath)
	}

	if err := c.SaveToFile(); err != nil {
		t.Errorf("SaveToFile() unexpected err=%v after saving for second time", err)
	}

	if content2, err := ioutil.ReadFile(testFilePath); err != nil {
		t.Errorf("ReadFile() unexpected err=%v", err)
	} else if bytes.Compare(content1, content2) != 0 {
		t.Errorf("Config file content mismatch \n%s!=\n%s\n", content1, content2)
	}

}
