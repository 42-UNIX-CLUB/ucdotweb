package store

import "testing"

// Finding D2: Flag ignores the query's error, so a panic switch that cannot be read counts
// as off. Here the read fails because the database is closed; any read error does the same.
func TestOptFlagReadErrorMeansOff(t *testing.T) {
	d := open(t)
	if err := d.SetFlag("admin", "all_off", true); err != nil {
		t.Fatal(err)
	}
	if !d.Flag("all_off") {
		t.Fatal("all_off should read as on")
	}
	d.Close()
	if !d.Flag("all_off") {
		t.Error("after a read error all_off reads as OFF: the switch fails open")
	}
}
