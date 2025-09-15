package keycheck_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/colduction/keycheck-go"
)

func alwaysTrue(s string) (bool, error) {
	return true, nil
}

func alwaysFalse(s string) (bool, error) {
	return false, errors.New("always false")
}

func sometimesTrue(target string) func(string) (bool, error) {
	return func(s string) (bool, error) {
		if s == target {
			return true, nil
		}
		return false, errors.New("input did not match target")
	}
}

func TestNewKeyChain(t *testing.T) {
	t.Run("Valid Conditions", func(t *testing.T) {
		validConditions := []keycheck.BitwiseID{keycheck.NOT, keycheck.AND, keycheck.OR, keycheck.XOR}
		for _, cond := range validConditions {
			kc, err := keycheck.NewKeyChain[string](cond)
			if err != nil {
				t.Errorf("NewKeyChain with valid condition %d returned an error: %v", cond, err)
			}
			if kc == nil {
				t.Errorf("NewKeyChain with valid condition %d returned a nil keyChain", cond)
			}
		}
	})
}

func TestKeyChain_PublicAPI(t *testing.T) {
	t.Run("Set, Get, and Order", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.OR)
		fn1 := alwaysTrue
		label1 := keycheck.ID("first")
		_ = kc.SetValidator(label1, fn1)

		fn2 := alwaysTrue
		label2 := keycheck.ID("second")
		_ = kc.SetValidator(label2, fn2)

		retrievedFn, err := kc.GetValidator(label1)
		if err != nil {
			t.Fatalf("GetValidator failed: %v", err)
		}
		if reflect.ValueOf(retrievedFn).Pointer() != reflect.ValueOf(fn1).Pointer() {
			t.Error("Retrieved validator is not the one that was set")
		}

		label, ok, _ := kc.Validate("any", keycheck.FAIL)
		if !ok || label != label1 {
			t.Errorf("Expected validation to pass with label '%s' to confirm order, but got '%s'", label1, label)
		}
	})

	t.Run("Overwrite", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.AND)
		_ = kc.SetValidator("validatorA", alwaysTrue)
		_ = kc.SetValidator("validatorB", alwaysFalse)

		_, ok, _ := kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Fatal("Validation should have failed before overwrite")
		}

		_ = kc.SetValidator("validatorB", alwaysTrue)

		_, ok, _ = kc.Validate("any", keycheck.FAIL)
		if !ok {
			t.Error("Validation should have passed after overwrite")
		}
	})

	t.Run("Delete", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.OR)
		_ = kc.SetValidator("validatorA", alwaysFalse)
		_ = kc.SetValidator("validatorB", alwaysTrue)

		label, ok, _ := kc.Validate("any", keycheck.FAIL)
		if !ok || label != "validatorB" {
			t.Fatalf("Validation did not pass with validatorB as expected before deletion")
		}

		_ = kc.DelValidator("validatorB")
		_, ok, _ = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("Validation should have failed after deleting the only passing validator")
		}

		retrievedFn, _ := kc.GetValidator("validatorB")
		if retrievedFn != nil {
			t.Error("GetValidator should return a nil function for a deleted validator")
		}
	})
}

func TestKeyChain_Reset(t *testing.T) {
	kc, _ := keycheck.NewKeyChain[string](keycheck.AND)
	_ = kc.SetValidator("test", alwaysTrue)

	_, ok, _ := kc.Validate("any", keycheck.FAIL)
	if !ok {
		t.Fatal("Validation failed unexpectedly before Reset")
	}

	kc.Reset()

	_, ok, _ = kc.Validate("any", keycheck.RETRY)
	if ok {
		t.Error("Validation should fail on a reset keychain")
	}

	_, err := kc.GetValidator("test")
	if err == nil {
		t.Error("GetValidator should return an error on a reset keychain")
	}
}

func TestKeyChain_Validate(t *testing.T) {
	t.Run("AND Condition", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.AND)
		_ = kc.SetValidator("true1", alwaysTrue)
		_ = kc.SetValidator("true2", alwaysTrue)

		label, ok, errs := kc.Validate("any", keycheck.FAIL)
		if !ok {
			t.Error("AND validation failed: expected true, got false when all validators pass")
		}
		if label != "true2" {
			t.Errorf("AND validation failed: expected label 'true2', got '%s'", label)
		}
		if len(errs) != 0 {
			t.Errorf("AND validation failed: expected no errors, got %d", len(errs))
		}

		_ = kc.SetValidator("false1", alwaysFalse)
		label, ok, errs = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("AND validation succeeded: expected false, got true when one validator fails")
		}
		if label != keycheck.FAIL {
			t.Errorf("AND validation succeeded: expected default label 'FAIL', got '%s'", label)
		}
		if len(errs) != 1 {
			t.Errorf("AND validation succeeded: expected 1 error, got %d", len(errs))
		}
	})

	t.Run("OR Condition", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.OR)
		_ = kc.SetValidator("false1", alwaysFalse)
		_ = kc.SetValidator("true1", alwaysTrue)
		_ = kc.SetValidator("false2", alwaysFalse)

		label, ok, errs := kc.Validate("any", keycheck.FAIL)
		if !ok {
			t.Error("OR validation failed: expected true, got false when one validator passes")
		}
		if label != "true1" {
			t.Errorf("OR validation failed: expected label 'true1', got '%s'", label)
		}
		if errs != nil {
			t.Errorf("OR validation failed: expected nil errors, got %v", errs)
		}

		kc, _ = keycheck.NewKeyChain[string](keycheck.OR)
		_ = kc.SetValidator("false1", alwaysFalse)
		_ = kc.SetValidator("false2", alwaysFalse)
		label, ok, errs = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("OR validation succeeded: expected false, got true when all validators fail")
		}
		if label != "false2" {
			t.Errorf("OR validation succeeded: expected last label 'false2', got '%s'", label)
		}
		if len(errs) != 2 {
			t.Errorf("OR validation succeeded: expected 2 errors, got %d", len(errs))
		}
	})

	t.Run("NOT Condition", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.NOT)
		_ = kc.SetValidator("false1", alwaysFalse)
		_ = kc.SetValidator("false2", alwaysFalse)

		label, ok, errs := kc.Validate("any", keycheck.FAIL)
		if !ok {
			t.Error("NOT validation failed: expected true, got false when all validators fail")
		}
		if label != "false2" {
			t.Errorf("NOT validation failed: expected label 'false2', got '%s'", label)
		}
		if errs != nil {
			t.Errorf("NOT validation failed: expected nil errors, got %v", errs)
		}

		_ = kc.SetValidator("true1", alwaysTrue)
		label, ok, errs = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("NOT validation succeeded: expected false, got true when one validator passes")
		}
		if label != keycheck.FAIL {
			t.Errorf("NOT validation succeeded: expected default label 'FAIL', got '%s'", label)
		}
		if len(errs) != 1 {
			t.Errorf("NOT validation succeeded: expected 1 error, got %d", len(errs))
		}
	})

	t.Run("XOR Condition", func(t *testing.T) {
		kc, _ := keycheck.NewKeyChain[string](keycheck.XOR)
		_ = kc.SetValidator("false1", alwaysFalse)
		_ = kc.SetValidator("is_target", sometimesTrue("target"))
		_ = kc.SetValidator("false2", alwaysFalse)

		label, ok, errs := kc.Validate("target", keycheck.FAIL)
		if !ok {
			t.Error("XOR validation failed: expected true, got false for exactly one success")
		}
		if label != "false2" {
			t.Errorf("XOR validation failed: expected last label 'false2', got '%s'", label)
		}
		if errs != nil {
			t.Errorf("XOR validation failed: expected nil errors, got %v", errs)
		}

		kc, _ = keycheck.NewKeyChain[string](keycheck.XOR)
		_ = kc.SetValidator("true1", alwaysTrue)
		_ = kc.SetValidator("true2", alwaysTrue)
		label, ok, errs = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("XOR validation succeeded: expected false, got true for multiple successes")
		}
		if label != keycheck.FAIL {
			t.Errorf("XOR validation succeeded: expected default label 'FAIL', got '%s'", label)
		}
		if errs != nil {
			t.Errorf("XOR validation succeeded: expected nil errors, got %v", errs)
		}

		kc, _ = keycheck.NewKeyChain[string](keycheck.XOR)
		_ = kc.SetValidator("false1", alwaysFalse)
		_ = kc.SetValidator("false2", alwaysFalse)
		label, ok, errs = kc.Validate("any", keycheck.FAIL)
		if ok {
			t.Error("XOR validation succeeded: expected false, got true for zero successes")
		}
		if label != keycheck.FAIL {
			t.Errorf("XOR validation succeeded: expected default label 'FAIL', got '%s'", label)
		}
		if len(errs) != 2 {
			t.Errorf("XOR validation succeeded: expected 2 errors, got %d", len(errs))
		}
	})
}
