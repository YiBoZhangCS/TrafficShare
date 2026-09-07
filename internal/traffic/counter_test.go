package traffic

import "testing"

func TestAdvanceHandlesReset(t *testing.T) {
	b := Baseline{Last: Counter{RX: 100, TX: 200}}
	b = b.Advance(Counter{RX: 150, TX: 260})
	if b.Used != (Counter{RX: 50, TX: 60}) {
		t.Fatalf("unexpected normal delta: %#v", b)
	}
	b = b.Advance(Counter{RX: 7, TX: 9})
	if b.Used != (Counter{RX: 57, TX: 69}) {
		t.Fatalf("unexpected reset delta: %#v", b)
	}
}

func TestParseWGDump(t *testing.T) {
	dump := "priv\tpub\t51820\toff\npeer-key\t(none)\t192.0.2.1:123\t0.0.0.0/0\t1\t123\t456\t25\n"
	c, err := ParseDump(dump, "peer-key")
	if err != nil {
		t.Fatal(err)
	}
	if c.RX != 123 || c.TX != 456 || c.Total() != 579 {
		t.Fatalf("unexpected counter: %#v", c)
	}
}
