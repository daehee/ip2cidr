package ip2cidr

import (
	"strings"
	"testing"
)

func TestConvert(t *testing.T) {
	tests := []struct {
		startIP string
		endIP   string
		want    []string
	}{
		{startIP: "1.0.64.0", endIP: "1.0.127.255", want: []string{"1.0.64.0/18"}},
		{startIP: "1.0.140.0", endIP: "1.0.175.255", want: []string{"1.0.140.0/22", "1.0.144.0/20", "1.0.160.0/20"}},
	}
	for _, tt := range tests {
		got, err := IPRangeToCIDR(tt.startIP, tt.endIP)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Compare(got[0], tt.want[0]) != 0 {
			t.Errorf("%v-%v = %v; want %v", tt.startIP, tt.endIP, got, tt.want)
		}
	}
}

func TestConvertFailure(t *testing.T) {
	tests := []struct {
		startIP string
		endIP   string
	}{
		{startIP: "1.0.64.0", endIP: "1.0.127.256"},
		{startIP: "1.0.260.0", endIP: "1.0.175.255"},
	}
	for _, tt := range tests {
		_, err := IPRangeToCIDR(tt.startIP, tt.endIP)
		if err == nil {
			t.Fatal(err)
		}
	}
}
