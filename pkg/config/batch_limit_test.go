package config

import "testing"

func TestValidate_MaxBatchEvaluations(t *testing.T) {
	for limit, wantErr := range map[int]bool{-1: true, 0: false, 1: false, 500: false} {
		cfg := DefaultConfig()
		cfg.Server.MaxBatchEvaluations = limit
		if err := cfg.Validate(); (err != nil) != wantErr {
			t.Errorf("max_batch_evaluations=%d: Validate() = %v, wantErr %v", limit, err, wantErr)
		}
	}
}
