package quota

import "testing"

func TestQuotaUsesIntegerBytes(t *testing.T) {
	got, err := ParseGB("20.25 GB")
	if err != nil {
		t.Fatal(err)
	}
	if got != 20_250_000_000 {
		t.Fatalf("got %d", got)
	}
	if Remaining(got, 1_250_000_000) != 19_000_000_000 {
		t.Fatal("remaining mismatch")
	}
	if !Exhausted(got, got) {
		t.Fatal("expected exhausted")
	}
}

func TestQuotaRejectsFloatPrecisionLoss(t *testing.T) {
	if _, err := ParseGB("1.1234567891"); err == nil {
		t.Fatal("expected precision rejection")
	}
}
