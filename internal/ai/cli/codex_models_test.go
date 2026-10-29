package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func TestCodexModelHelper(t *testing.T) {
	mode := os.Getenv("MOTTY_MODEL_TEST")
	if mode == "" {
		return
	}
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Cursor string `json:"cursor"`
			} `json:"params"`
		}
		if json.Unmarshal(scanner.Bytes(), &req) != nil {
			os.Exit(1)
		}
		switch req.Method {
		case "initialize":
			fmt.Println(`{"method":"notification","params":{}}`)
			fmt.Printf(`{"id":%d,"result":{}}`+"\n", req.ID)
		case "model/list":
			switch mode {
			case "wait":
				time.Sleep(time.Minute)
			case "error":
				fmt.Printf(`{"id":%d,"error":{"message":"PRIVATE_TOKEN"}}`+"\n", req.ID)
			case "cycle":
				fmt.Printf(`{"id":%d,"result":{"data":[],"nextCursor":"same"}}`+"\n", req.ID)
			default:
				if req.Params.Cursor == "" {
					fmt.Printf(`{"id":%d,"result":{"data":[{"id":"display","model":"alpha"},{"model":"default"}],"nextCursor":"next"}}`+"\n", req.ID)
				} else {
					fmt.Printf(`{"id":%d,"result":{"data":[{"model":"beta"},{"model":"alpha"}],"nextCursor":null}}`+"\n", req.ID)
				}
			}
		}
	}
	os.Exit(0)
}

func modelHelper(t *testing.T, mode string) command {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return command{program: exe, args: []string{"-test.run=^TestCodexModelHelper$"}, env: []string{"MOTTY_MODEL_TEST=" + mode}}
}

func TestCodexModelExchangePaginationAndErrors(t *testing.T) {
	names, err := codexModelExchange(t.Context(), modelHelper(t, "success"))
	if err != nil || !reflect.DeepEqual(names, []string{"default", "alpha", "beta"}) {
		t.Fatalf("models: %v, error: %v", names, err)
	}
	for _, mode := range []string{"error", "cycle"} {
		if _, err := codexModelExchange(t.Context(), modelHelper(t, mode)); err == nil || err.Error() == "PRIVATE_TOKEN" {
			t.Fatalf("%s: %v", mode, err)
		}
	}
}

func TestCodexModelExchangeCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := codexModelExchange(ctx, modelHelper(t, "wait")); err != context.DeadlineExceeded || time.Since(start) > 4*time.Second {
		t.Fatalf("cancellation: %v after %v", err, time.Since(start))
	}
}
