package keycheck

import (
	"errors"
	"strconv"
	"testing"
)

func TestSetGetDelValidator(t *testing.T) {
	kc, err := NewKeyChain[int](OR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	expectedStatus := Status{ID: "A", Details: "alpha"}
	expectedFn := func(v int) (bool, error) { return v == 10, nil }

	if err := kc.SetValidator(expectedStatus, expectedFn); err != nil {
		t.Fatalf("set validator: %v", err)
	}

	status, fn, err := kc.GetValidator("A")
	if err != nil {
		t.Fatalf("get validator: %v", err)
	}
	if status != expectedStatus {
		t.Fatalf("unexpected status: got %+v want %+v", status, expectedStatus)
	}
	if fn == nil {
		t.Fatal("expected validator function, got nil")
	}

	ok, fnErr := fn(10)
	if fnErr != nil {
		t.Fatalf("validator returned error: %v", fnErr)
	}
	if !ok {
		t.Fatal("validator should have returned true")
	}

	if err := kc.DelValidator("A"); err != nil {
		t.Fatalf("delete validator: %v", err)
	}

	_, fn, err = kc.GetValidator("A")
	if err != nil {
		t.Fatalf("get validator after delete: %v", err)
	}
	if fn != nil {
		t.Fatal("expected nil validator function after delete")
	}
}

func TestValidateOR(t *testing.T) {
	kc, err := NewKeyChain[int](OR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	wantStatus := Status{ID: "SECOND", Details: "second"}
	expectedErr := errors.New("first failed")

	if err := kc.SetValidator(Status{ID: "FIRST"}, func(v int) (bool, error) {
		return false, expectedErr
	}); err != nil {
		t.Fatalf("set validator: %v", err)
	}
	if err := kc.SetValidator(wantStatus, func(v int) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("set validator: %v", err)
	}

	status, ok, errs := kc.Validate(1, NONE)
	if !ok {
		t.Fatal("expected OR validation to succeed")
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors on OR success, got %d", len(errs))
	}
	if status.GetID() != wantStatus.ID {
		t.Fatalf("unexpected status ID: got %q want %q", status.GetID(), wantStatus.ID)
	}
}

func TestValidateORCollectsAllErrors(t *testing.T) {
	kc, err := NewKeyChain[int](OR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	const total = 40
	for i := range total {
		if err := kc.SetValidator(Status{ID: "S" + strconv.Itoa(i)}, func(v int) (bool, error) {
			return false, errors.New("err")
		}); err != nil {
			t.Fatalf("set validator %d: %v", i, err)
		}
	}

	_, ok, errs := kc.Validate(1, NONE)
	if ok {
		t.Fatal("expected OR validation to fail")
	}
	if len(errs) != total {
		t.Fatalf("expected %d errors, got %d", total, len(errs))
	}
}

func TestValidateAND(t *testing.T) {
	kc, err := NewKeyChain[int](AND)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	expectedErr := errors.New("and failed")

	if err := kc.SetValidator(Status{ID: "FIRST"}, func(v int) (bool, error) {
		return true, nil
	}); err != nil {
		t.Fatalf("set validator: %v", err)
	}
	if err := kc.SetValidator(Status{ID: "SECOND"}, func(v int) (bool, error) {
		return false, expectedErr
	}); err != nil {
		t.Fatalf("set validator: %v", err)
	}

	status, ok, errs := kc.Validate(1, NONE)
	if ok {
		t.Fatal("expected AND validation to fail")
	}
	if status.GetID() != NONE.GetID() {
		t.Fatalf("unexpected default status ID: got %q want %q", status.GetID(), NONE.GetID())
	}
	if len(errs) != 1 || !errors.Is(errs[0], expectedErr) {
		t.Fatalf("unexpected errors: %#v", errs)
	}
}

func TestValidateXOR(t *testing.T) {
	kc, err := NewKeyChain[int](XOR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	wantStatus := Status{ID: "ONLY_TRUE"}
	if err := kc.SetValidator(wantStatus, func(v int) (bool, error) { return true, nil }); err != nil {
		t.Fatalf("set validator: %v", err)
	}
	if err := kc.SetValidator(Status{ID: "FALSE"}, func(v int) (bool, error) { return false, errors.New("nope") }); err != nil {
		t.Fatalf("set validator: %v", err)
	}

	status, ok, errs := kc.Validate(1, NONE)
	if !ok {
		t.Fatal("expected XOR validation to succeed")
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors on XOR success, got %d", len(errs))
	}
	if status.GetID() != wantStatus.ID {
		t.Fatalf("unexpected status ID: got %q want %q", status.GetID(), wantStatus.ID)
	}
}

func TestValidateXORCollectsAllErrorsOnFailure(t *testing.T) {
	kc, err := NewKeyChain[int](XOR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	const total = 40
	for i := range total {
		if err := kc.SetValidator(Status{ID: "X" + strconv.Itoa(i)}, func(v int) (bool, error) {
			return false, errors.New("err")
		}); err != nil {
			t.Fatalf("set validator %d: %v", i, err)
		}
	}

	_, ok, errs := kc.Validate(1, NONE)
	if ok {
		t.Fatal("expected XOR validation to fail")
	}
	if len(errs) != total {
		t.Fatalf("expected %d errors, got %d", total, len(errs))
	}
}

func TestValidateNOT(t *testing.T) {
	kc, err := NewKeyChain[int](NOT)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	if err := kc.SetValidator(Status{ID: "FIRST_FALSE"}, func(v int) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("set validator: %v", err)
	}
	if err := kc.SetValidator(Status{ID: "SECOND_FALSE"}, func(v int) (bool, error) { return false, nil }); err != nil {
		t.Fatalf("set validator: %v", err)
	}

	status, ok, errs := kc.Validate(1, NONE)
	if !ok {
		t.Fatal("expected NOT validation to succeed when all validators are false")
	}
	if len(errs) != 0 {
		t.Fatalf("expected no errors, got %d", len(errs))
	}
	if status.GetID() != "SECOND_FALSE" {
		t.Fatalf("unexpected status ID: got %q want %q", status.GetID(), "SECOND_FALSE")
	}
}

func TestResetAndNilReceiverBehavior(t *testing.T) {
	kc, err := NewKeyChain[int](OR)
	if err != nil {
		t.Fatalf("new keychain: %v", err)
	}

	if err := kc.SetValidator(Status{ID: "A"}, func(v int) (bool, error) { return true, nil }); err != nil {
		t.Fatalf("set validator: %v", err)
	}
	kc.Reset()

	if err := kc.DelValidator("A"); err == nil {
		t.Fatal("expected error deleting validator after reset")
	}
	if _, _, err := kc.GetValidator("A"); err == nil {
		t.Fatal("expected error getting validator after reset")
	}

	var nilKC *keyChain[int]
	if err := nilKC.SetValidator(Status{ID: "A"}, nil); err == nil {
		t.Fatal("expected nil receiver error on set")
	}
	if _, _, err := nilKC.GetValidator("A"); err == nil {
		t.Fatal("expected nil receiver error on get")
	}
	if err := nilKC.DelValidator("A"); err == nil {
		t.Fatal("expected nil receiver error on delete")
	}
}
