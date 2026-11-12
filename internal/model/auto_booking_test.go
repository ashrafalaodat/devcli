package model

import (
	"fmt"
	"strings"
	"testing"
)

func TestAutoBookingPolicyLabelValidation(t *testing.T) {
	for _, selector := range []map[string]string{
		nil, {}, {"environment": "testing"}, {"example.com/team": "platform"}, {"empty": ""},
		{strings.Repeat("a", 63): strings.Repeat("v", 63)},
	} {
		if err := ValidateAutoBookingPolicy(AutoBookingPolicy{Enabled: true, Selector: selector}); err != nil {
			t.Fatal("valid equality selector rejected", err)
		}
	}
	tooMany := map[string]string{}
	for i := range 33 {
		tooMany[fmt.Sprintf("label-%d", i)] = "test"
	}
	for _, selector := range []map[string]string{
		{"": "x"}, {"bad/key/again": "test"}, {"bad key": "test"}, {"UPPER.example/team": "test"},
		{strings.Repeat("x", 64): "test"}, {"key": strings.Repeat("x", 64)}, {"key": "a,b"},
		{strings.Repeat("x", 318): "test"}, tooMany,
	} {
		if err := ValidateAutoBookingPolicy(AutoBookingPolicy{Selector: selector}); err == nil {
			t.Fatal("invalid selector accepted")
		}
	}
}

func TestEmptySelectorValueRequiresLabelPresence(t *testing.T) {
	request := Booking{Selector: map[string]string{"marker": ""}}
	if Match(Cluster{Labels: map[string]string{}}, request) {
		t.Fatal("missing label matched an empty-value equality requirement")
	}
	if !Match(Cluster{Labels: map[string]string{"marker": ""}}, request) {
		t.Fatal("present empty label did not match")
	}
}
