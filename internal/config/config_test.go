package config

import "testing"
import "os"
import "io/ioutil"
import "bytes"
import "github.com/alphasoc/namescore/internal/utils"

func TestSaveConfig(t *testing.T) {
	var (
		testFilePath = "/tmp/namescore_test.toml"
		apiKey       = "abcd"
		iface        = "eth0"
	)
	defer os.Remove(testFilePath)

	c := Config{ConfigFilePath: testFilePath, APIKey: apiKey, NetworkInterface: iface}

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
		testFilePath = "/tmp/namescore_config_test.toml"
		apiKey       = "defgh"
		iface        = "eth1"
	)
	defer os.Remove(testFilePath)

	c := Config{ConfigFilePath: testFilePath, APIKey: apiKey, NetworkInterface: iface}
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

func TestDefaults(t *testing.T) {
	c := Get()

	if c.FollowFilePath == "" {
		t.Errorf("FollowFilePath is empty")
	}

	if c.AlertFilePath == "" {
		t.Errorf("AlertFilePath is empty")
	}

	if c.ConfigFilePath == "" {
		t.Errorf("ConfigFilePath is empty")
	}

	if c.AlphaSOCAddress == "" {
		t.Errorf("AlphaSOCAddress is empty")
	}

	if c.WhitelistFilePath == "" {
		t.Errorf("whitelistFile is empty")
	}

	if c.FailedQueriesDir == "" {
		t.Errorf("failedQueriesDir is empty")
	}

	if c.AlertRequestInterval == 0 {
		t.Errorf("alertRequestInterval is 0")
	}

	if c.SendIntervalTime == 0 {
		t.Errorf("sendIntervalTime is 0")
	}
}

func TestInitialDirsCreate(t *testing.T) {
	var (
		testDir = "/tmp/namescore_test/"
		file1   = "/tmp/namescore_test/dir1/file1.txt"
		dir1    = "/tmp/namescore_test/dir1/"
		file2   = "/tmp/namescore_test/dir2/file2.txt"
		dir2    = "/tmp/namescore_test/dir2/"
		file3   = "/tmp/namescore_test/dir3/file3.txt"
		dir3    = "/tmp/namescore_test/dir3/"
		file4   = "/tmp/namescore_test/dir4/file4.txt"
		dir4    = "/tmp/namescore_test/dir4/"
		dir5    = "/tmp/namescore_test/dir5/"
	)

	cfg := Config{
		AlertFilePath:     file1,
		ConfigFilePath:    file2,
		FollowFilePath:    file3,
		WhitelistFilePath: file4,
		FailedQueriesDir:  dir5,
	}
	defer os.RemoveAll(testDir)

	if err := cfg.InitialDirsCreate(); err != nil {
		t.Fatalf("InitialDirsCreate(), unexpected error %v", err)
	}

	if exist, _ := utils.FileExists(dir1); exist == false {
		t.Fatalf("%q, was not created!", dir1)
	}

	if exist, _ := utils.FileExists(dir2); exist == false {
		t.Fatalf("%q, was not created!", dir2)
	}

	if exist, _ := utils.FileExists(dir3); exist == false {
		t.Fatalf("%q, was not created!", dir3)
	}

	if exist, _ := utils.FileExists(dir4); exist == false {
		t.Fatalf("%q, was not created!", dir4)
	}

	if exist, _ := utils.FileExists(dir5); exist == false {
		t.Fatalf("%q, was not created!", dir5)
	}
}
