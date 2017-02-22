package cmd

import (
	"bufio"
	"bytes"
	"fmt"
	"testing"
)

func testUserInput(w, r *bytes.Buffer) *userInput {
	u := &userInput{reader: r, writer: w}
	u.scanner = bufio.NewScanner(u.reader)
	return u
}

func TestUserInput(t *testing.T) {

	var (
		userValue   = "some value"
		textForUser = "text for user1\n"
	)

	reader := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}

	uin := testUserInput(writer, reader)

	v, err := uin.get(textForUser, false)
	if err != nil {
		t.Errorf("get(), unexpected error=%v", err)
	}

	if v != userValue {
		t.Errorf("get(), got %q, expected %q", v, userValue)
	}

	if textForUser != writer.String() {
		t.Errorf("get(), should print %q, but got %q", textForUser, writer.String())
	}
}

func TestUserInputNoInput(t *testing.T) {

	var (
		userValue   string
		textForUser = "text for user2\n"
	)

	reader := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}
	uin := testUserInput(writer, reader)

	v, err := uin.get(textForUser, false)
	if err != nil {
		t.Errorf("get(), unexpected error=%v", err)
	}

	if v != userValue {
		t.Errorf("get(), got %q, expected %q", v, userValue)
	}

	if textForUser != writer.String() {
		t.Errorf("get(), should print %q, but got %q", textForUser, writer.String())
	}
}

func TestUserInputMandatory(t *testing.T) {
	var (
		userValue   string
		textForUser = "text for user3\n"
	)

	reader := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}
	uin := testUserInput(writer, reader)

	v, err := uin.get(textForUser, true)

	if err == nil || err.Error() != errNoInput.Error() {
		t.Errorf("get(), expected error=%q, got %v", errNoInput.Error(), err)
	}

	if v != "" {
		t.Errorf("get(), %q expected empty string", v)
	}

	if textForUser != writer.String() {
		t.Errorf("get(), should print %q, but got %q", textForUser, writer.String())
	}
}

func TestUserInputMulti(t *testing.T) {
	var (
		userValue    = "some value1\nsome value2"
		expectedVal1 = "some value1"
		expectedVal2 = "some value2"
		textForUser1 = "text for user4\n"
		textForUser2 = "text for user5\n"
	)

	reader1 := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}
	uin := testUserInput(writer, reader1)

	v1, err1 := uin.get(textForUser1, false)
	if err1 != nil {
		t.Errorf("get(), unexpected error=%v", err1)
	}

	if v1 != expectedVal1 {
		t.Errorf("get(), got %q, expected %q", v1, expectedVal1)
	}

	if textForUser1 != writer.String() {
		t.Errorf("get(), should print %q, but got %q", textForUser1, writer.String())
	}

	writer.Reset()

	v2, err2 := uin.get(textForUser2, false)
	if err2 != nil {
		t.Errorf("get(), unexpected error=%v", err2)
	}

	if v2 != expectedVal2 {
		t.Errorf("get(), got %q, expected %q", v2, expectedVal2)
	}

	if textForUser2 != writer.String() {
		t.Errorf("get(), should print %q, but got %q", textForUser2, writer.String())
	}

}

func TestUserReadRegisterData(t *testing.T) {

	var (
		name  = "Tomas The Hacker"
		org   = "AlphaSOC"
		email = "test@alphasoc.com"
		phone = "123-456-789"
		addr1 = "Country"
		addr2 = "City"
		addr3 = "Street"
	)

	userValue := fmt.Sprintf(
		"%s\n%s\n%s\n%s\n%s\n%s\n%s\n",
		name, org, email, phone, addr1, addr2, addr3,
	)

	reader := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}
	uin := testUserInput(writer, reader)

	data, err := readRegisterData(uin)
	if err != nil {
		t.Errorf("readRegisterData(), unexpected error=%v", err)
	}

	if data.Details.Name != name {
		t.Errorf("readRegisterData(), got name %q, expected %q", data.Details.Name, name)
	}

	if data.Details.Organization != org {
		t.Errorf("readRegisterData(), got org %q, expected %q", data.Details.Organization, org)
	}

	if data.Details.Email != email {
		t.Errorf("readRegisterData(), got email %q, expected %q", data.Details.Email, email)
	}

	if data.Details.Phone != phone {
		t.Errorf("readRegisterData(), got phone %q, expected %q", data.Details.Phone, phone)
	}

	if data.Details.Address[0] != addr1 {
		t.Errorf("readRegisterData(), got addr1 %q, expected %q", data.Details.Address[0], addr1)
	}

	if data.Details.Address[1] != addr2 {
		t.Errorf("readRegisterData(), got addr2 %q, expected %q", data.Details.Address[1], addr2)
	}

	if data.Details.Address[2] != addr3 {
		t.Errorf("readRegisterData(), got addr3 %q, expected %q", data.Details.Address[2], addr3)
	}
}

func TestUserReadRegisterDataMissingFields(t *testing.T) {

	var (
		name  = "Tomas The Hacker"
		org   = "AlphaSOC"
		email = "test@alphasoc.com"
		phone = "123-456-789"
	)

	userValue := fmt.Sprintf("%s\n%s\n%s\n%s\n", name, org, email, phone)

	reader := bytes.NewBufferString(userValue)
	writer := &bytes.Buffer{}
	uin := testUserInput(writer, reader)

	data, err := readRegisterData(uin)
	if err == nil {
		t.Errorf("readRegisterData(), expected error")
	}

	if data != nil {
		t.Errorf("readRegisterData(), expected data to be nil")
	}

}
