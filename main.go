package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

// GetUnpushedCommits retrieves all unpushed commits from the upstream branch to HEAD
func GetUnpushedCommits() ([]string, error) {
	// Check if the branch has an upstream set
	checkUpstream := exec.Command("git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
	if err := checkUpstream.Run(); err != nil {
		return nil, fmt.Errorf("no upstream branch set for the current branch. Please set upstream before pushing.")
	}

	// If upstream exists, get unpushed commits
	cmd := exec.Command("git", "rev-list", "--oneline", "@{u}..HEAD")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to get unpushed commits: %v", err)
	}
	commitLines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var commits []string
	for _, line := range commitLines {
		if len(line) > 0 {
			commits = append(commits, strings.Fields(line)[0])
		}
	}
	return commits, nil
}

// GetChangedFilesInCommit retrieves files changed in a specific commit
func GetChangedFilesInCommit(commit string) ([]string, error) {
	cmd := exec.Command("git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get files for commit %s: %v", commit, err)
	}
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	return files, nil
}

// DLPScan scans a given text for sensitive data using Google Cloud DLP
func DLPScan(projectID, text string) (bool, error) {
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to create DLP client: %v", err)
	}
	defer client.Close()

	customRegexPattern := "XY[0-9]{4}.*"
	customInfoType := &dlppb.CustomInfoType{
		InfoType: &dlppb.InfoType{Name: "RampID"},
		Type: &dlppb.CustomInfoType_Regex_{Regex: &dlppb.CustomInfoType_Regex{
			Pattern: customRegexPattern,
		}},
		Likelihood: dlppb.Likelihood_POSSIBLE,
	}

	inspectConfig := &dlppb.InspectConfig{
		InfoTypes: []*dlppb.InfoType{
			{Name: "EMAIL_ADDRESS"},
			{Name: "PHONE_NUMBER"},
			{Name: "US_SOCIAL_SECURITY_NUMBER"},
		},
		CustomInfoTypes: []*dlppb.CustomInfoType{customInfoType},
		IncludeQuote:    true,
	}

	contentItem := &dlppb.ContentItem{
		DataItem: &dlppb.ContentItem_Value{Value: text},
	}

	req := &dlppb.InspectContentRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/global", projectID),
		Item:          contentItem,
		InspectConfig: inspectConfig,
	}

	resp, err := client.InspectContent(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to inspect content: %v", err)
	}

	return len(resp.Result.Findings) > 0, nil
}

// ScanCommit checks each file in a specific commit for sensitive data
func ScanCommit(commit, projectID string, flaggedFiles map[string]bool) error {
	files, err := GetChangedFilesInCommit(commit)
	if err != nil {
		return err
	}

	for _, file := range files {
		cmd := exec.Command("git", "show", fmt.Sprintf("%s:%s", commit, file))
		output, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("failed to get content of file %s in commit %s: %v", file, commit, err)
		}
		foundSensitiveData, err := DLPScan(projectID, string(output))
		if err != nil {
			return err
		}
		if foundSensitiveData {
			flaggedFiles[file] = true
			fmt.Printf("Sensitive data found in file %s in commit %s.\n", file, commit)
		}
	}

	return nil
}

// ScanFinalState scans the latest version of flagged files at HEAD for sensitive data
func ScanFinalState(projectID string, flaggedFiles map[string]bool) (bool, error) {
	for file := range flaggedFiles {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return false, fmt.Errorf("could not read file %s: %v", file, err)
		}
		foundSensitiveData, err := DLPScan(projectID, string(data))
		if err != nil {
			return false, err
		}
		if foundSensitiveData {
			fmt.Printf("Sensitive data found in final state of file %s. Aborting push.\n", file)
			return true, nil
		}
	}

	return false, nil
}

func main() {
	projectID := "datalake-sea-eng-us-cert"

	// Set the GIT_HTTP_EXTRAHEADER environment variable
	os.Setenv("GIT_HTTP_EXTRAHEADER", "DLP-Scanned: true")
	defer os.Unsetenv("GIT_HTTP_EXTRAHEADER") // Ensure it is unset after execution

	commits, err := GetUnpushedCommits()
	if err != nil {
		fmt.Printf("Error retrieving unpushed commits: %v\n", err)
		os.Exit(1)
	}

	// Step 1: Scan each commit in the range to track files with sensitive data
	flaggedFiles := make(map[string]bool)
	for _, commit := range commits {
		fmt.Printf("Scanning commit: %s\n", commit)
		err := ScanCommit(commit, projectID, flaggedFiles)
		if err != nil {
			fmt.Printf("Scan error in commit %s: %v\n", commit, err)
			os.Exit(1)
		}
	}

	// Step 2: Perform a final scan on the latest file states at HEAD for flagged files only
	fmt.Println("Performing final DLP scan on latest flagged file states...")
	foundSensitiveData, err := ScanFinalState(projectID, flaggedFiles)
	if err != nil {
		fmt.Printf("Final state scan error: %v\n", err)
		os.Exit(1)
	}
	if foundSensitiveData {
		os.Exit(1) // Exit if sensitive data is found in the final state
	}

	fmt.Println("DLP scan complete, no sensitive data found.")
}
