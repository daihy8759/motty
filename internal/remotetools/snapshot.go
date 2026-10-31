package remotetools

import (
	"context"
	"sort"
	"strconv"
	"strings"
)

const (
	maxSnapshotProcesses = 5000
	maxSnapshotCommand   = 1024
	maxSnapshotOutput    = 8 << 20
	snapshotReadRows     = maxSnapshotProcesses + 9
)

// ProcessSnapshot is a bounded host reading, not merely the busiest processes.
// The flags keep search scope honest at the limits.
type ProcessSnapshot struct {
	Processes         []Process
	Truncated         bool
	CommandsTruncated bool
}

func snapshotCommand(legacy bool) string {
	command := "LC_ALL=C " + collectorMarker + " -o pmem= -o etime= -o args= 2>&1"
	if legacy {
		command = legacyProcessCommand
	}
	return command + " | head -n " + strconv.Itoa(snapshotReadRows) + " | cut -c1-" + strconv.Itoa(maxSnapshotCommand+60)
}

// ReadProcessSnapshot never receives a search query: filtering the bounded
// result is local, so user input cannot become a remote shell command.
func ReadProcessSnapshot(ctx context.Context, runner Runner, key SortKey) (ProcessSnapshot, error) {
	if runnerSystem(runner) == "windows" {
		return readWindowsProcesses(ctx, runner, key)
	}
	command := snapshotCommand(false)
	if runnerSystem(runner) == "darwin" {
		command = strings.Replace(command, "ps -e ", "/bin/ps -A ", 1)
	}
	output, err := runner.RunCommand(ctx, command, maxSnapshotOutput)
	legacy := false
	if unsupportedPSOptions(output) {
		legacy = true
		output, err = runner.RunCommand(ctx, snapshotCommand(true), maxSnapshotOutput)
	}
	if err != nil {
		if diagnostic := snapshotDiagnostic(output); diagnostic != "" {
			return ProcessSnapshot{}, &Failure{Message: diagnostic, Err: err}
		}
		return ProcessSnapshot{}, err
	}
	result := ProcessSnapshot{Truncated: strings.Count(strings.TrimSpace(string(output)), "\n")+1 >= snapshotReadRows}
	for _, line := range strings.Split(string(output), "\n") {
		if len(line) >= maxSnapshotCommand+60 {
			result.CommandsTruncated = true
		}
	}
	if legacy {
		rows, parseErr := parseLegacyProcessRows(output, key, maxSnapshotProcesses+1, maxSnapshotCommand)
		if parseErr != nil {
			return ProcessSnapshot{}, parseErr
		}
		result.Processes = rows
	} else {
		firstBad := ""
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(strings.TrimRight(line, "\r"))
			if line == "" {
				continue
			}
			process, ok := parseProcessWithLimit(line, maxSnapshotCommand)
			if !ok {
				if firstBad == "" {
					firstBad = line
				}
				continue
			}
			if !ownPipeline(process.Command) {
				result.Processes = append(result.Processes, process)
			}
		}
		if len(result.Processes) == 0 {
			if firstBad != "" {
				return ProcessSnapshot{}, &Failure{Message: firstBad, Err: ErrUnsupported}
			}
			return ProcessSnapshot{}, ErrMalformed
		}
		sort.SliceStable(result.Processes, func(i, j int) bool {
			if key == SortMemory {
				return result.Processes[i].Memory > result.Processes[j].Memory
			}
			return result.Processes[i].CPU > result.Processes[j].CPU
		})
	}
	for _, process := range result.Processes {
		if len(process.Command) >= maxSnapshotCommand || strings.HasSuffix(process.Command, "…") {
			result.CommandsTruncated = true
		}
	}
	if len(result.Processes) > maxSnapshotProcesses {
		result.Truncated = true
		result.Processes = result.Processes[:maxSnapshotProcesses]
	}
	return result, nil
}

// snapshotDiagnostic is the server's own complaint from a failed snapshot.
// Output that holds process rows is data from a read that was cut short, not a
// diagnostic: reporting its first row as the failure would hide the real error,
// so such output falls through to err.
func snapshotDiagnostic(output []byte) string {
	first := ""
	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" {
			continue
		}
		if first == "" {
			first = line
		}
		if looksLikeProcessRow(line) {
			return ""
		}
	}
	return first
}

// looksLikeProcessRow recognizes both snapshot row formats, so a partial read is
// never mistaken for the server's explanation of why it failed.
func looksLikeProcessRow(line string) bool {
	if strings.HasPrefix(line, "USER ") {
		return true
	}
	if _, ok := parseProcessWithLimit(line, maxSnapshotCommand); ok {
		return true
	}
	fields := strings.Fields(line)
	if len(fields) < 11 {
		return false
	}
	if pid, err := strconv.Atoi(fields[1]); err != nil || pid <= 0 {
		return false
	}
	if _, err := strconv.ParseFloat(fields[2], 64); err != nil {
		return false
	}
	_, err := strconv.ParseFloat(fields[3], 64)
	return err == nil
}
