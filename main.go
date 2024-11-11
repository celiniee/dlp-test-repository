package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	dlp "cloud.google.com/go/dlp/apiv2"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

// GetChangedFiles retrieves the list of files changed in the latest commit
func GetChangedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--name-only", "HEAD~1", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get changed files: %v", err)
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

// SetGitExtraHeader sets the GIT_HTTP_EXTRAHEADER environment variable
func SetGitExtraHeader() {
	os.Setenv("GIT_HTTP_EXTRAHEADER", "DLP-Scanned: true")
	fmt.Println("Set GIT_HTTP_EXTRAHEADER environment variable.")
}

// RunGitPush performs the git push command, setting upstream if needed
func RunGitPush() error {
	cmd := exec.Command("git", "rev-parse", "--abbrev-ref", "HEAD")
	branchBytes, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get current branch name: %v", err)
	}
	branchName := strings.TrimSpace(string(branchBytes))

	cmd = exec.Command("git", "push", "--set-upstream", "origin", branchName)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git push failed: %v", err)
	}
	return nil
}

// ScanFile reads file content, performs a DLP scan, and sets HTTP header if no sensitive data is found
func ScanFile(filename, projectID string) (bool, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return false, fmt.Errorf("could not read file: %v", err)
	}

	foundSensitiveData, err := DLPScan(projectID, string(data))
	if err != nil {
		return false, err
	}

	return !foundSensitiveData, nil
}

func main() {
	projectID := "datalake-sea-eng-us-cert"
	files, err := GetChangedFiles()
	if err != nil {
		fmt.Printf("Error retrieving changed files: %v\n", err)
		os.Exit(1)
	}

	// Track if all files are clean
	allFilesClean := true
	for _, file := range files {
		if file == "" {
			continue
		}
		fmt.Printf("Scanning file: %s\n", file)
		fileClean, err := ScanFile(file, projectID)
		if err != nil {
			fmt.Printf("Scan error: %v\n", err)
			os.Exit(1)
		}
		if !fileClean {
			fmt.Printf("Sensitive data found in file %s. Skipping git push.\n", file)
			allFilesClean = false
			break
		}
	}

	if allFilesClean {
		// Set the custom HTTP header and perform the push
		SetGitExtraHeader()
		defer os.Unsetenv("GIT_HTTP_EXTRAHEADER")
		if err := RunGitPush(); err != nil {
			fmt.Printf("Push failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Sensitive data detected, aborting push.")
		os.Exit(1)
	}

	fmt.Println("DLP scan complete, push successful.")
}
