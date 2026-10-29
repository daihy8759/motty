package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"
)

// codexModels uses the installed CLI's catalog and credentials without starting
// a model session. The default entry continues to follow the CLI configuration.
func codexModels(ctx context.Context, spec command) ([]string, error) {
	dir, err := os.MkdirTemp("", "motty-codex-models-")
	if err != nil {
		return nil, errors.New("cli: runtime_directory_failed")
	}
	defer os.RemoveAll(dir)
	spec.args = withOverrides(append(spec.args, "app-server"), append(append([]string{}, codexControls...), "mcp_servers={}"))
	spec.dir = dir
	return codexModelExchange(ctx, spec)
}

func codexModelExchange(ctx context.Context, spec command) ([]string, error) {
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(child, spec.program, spec.args...)
	cmd.Dir, cmd.Env = spec.dir, processEnv(spec.env)
	cmd.WaitDelay = 2 * time.Second
	configureProcess(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, errors.New("cli: execution_failed")
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, errors.New("cli: execution_failed")
	}
	cmd.Stderr = &boundedWriter{limit: maxStderr}
	if err = cmd.Start(); err != nil {
		return nil, errors.New("cli: execution_failed")
	}
	defer func() {
		cancel()
		_ = stdin.Close()
		_ = cmd.Wait()
	}()
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4096), maxLine)
	total := 0
	request := func(id int, method string, params any, result any) error {
		if err := json.NewEncoder(stdin).Encode(map[string]any{"id": id, "method": method, "params": params}); err != nil {
			return errors.New("cli: model_list_failed")
		}
		for scanner.Scan() {
			total += len(scanner.Bytes())
			if total > maxOutput {
				return errors.New("cli: output_limit")
			}
			var response struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  json.RawMessage `json:"error"`
			}
			if json.Unmarshal(scanner.Bytes(), &response) != nil {
				return errors.New("cli: invalid_model_list")
			}
			if string(response.ID) != fmt.Sprint(id) {
				continue
			}
			if len(response.Error) != 0 && string(response.Error) != "null" {
				return errors.New("cli: model_list_failed")
			}
			if len(response.Result) == 0 || string(response.Result) == "null" || json.Unmarshal(response.Result, result) != nil {
				return errors.New("cli: invalid_model_list")
			}
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("cli: model_list_failed")
	}
	var initialized map[string]any
	if err := request(1, "initialize", map[string]any{"clientInfo": map[string]string{"name": "motty", "version": "1"}}, &initialized); err != nil {
		return nil, err
	}
	if err := json.NewEncoder(stdin).Encode(map[string]any{"method": "initialized"}); err != nil {
		return nil, errors.New("cli: model_list_failed")
	}
	names := []string{"default"}
	seen := map[string]bool{"default": true}
	cursors := map[string]bool{}
	cursor := ""
	for page := 0; page < 100; page++ {
		params := map[string]any{"limit": 100}
		if cursor != "" {
			params["cursor"] = cursor
		}
		var result struct {
			Data []struct {
				Model string `json:"model"`
			} `json:"data"`
			NextCursor string `json:"nextCursor"`
		}
		if err := request(page+2, "model/list", params, &result); err != nil {
			return nil, err
		}
		if result.Data == nil {
			return nil, errors.New("cli: invalid_model_list")
		}
		for _, model := range result.Data {
			if model.Model != "" && !seen[model.Model] {
				seen[model.Model] = true
				names = append(names, model.Model)
			}
		}
		if result.NextCursor == "" {
			return names, nil
		}
		if cursors[result.NextCursor] {
			return nil, errors.New("cli: invalid_model_list")
		}
		cursor = result.NextCursor
		cursors[cursor] = true
	}
	return nil, errors.New("cli: output_limit")
}
