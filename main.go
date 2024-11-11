package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
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

	// If any findings are present, return true for sensitive data found
	return len(resp.Result.Findings) > 0, nil
}

// SetGitExtraHeader sets the GIT_HTTP_EXTRAHEADER environment variable
func SetGitExtraHeader() {
	os.Setenv("GIT_HTTP_EXTRAHEADER", "DLP-Scanned: true")
	fmt.Println("Set GIT_HTTP_EXTRAHEADER environment variable.")
}

// ClearGitExtraHeader clears the GIT_HTTP_EXTRAHEADER environment variable
func ClearGitExtraHeader() {
	os.Unsetenv("GIT_HTTP_EXTRAHEADER")
	fmt.Println("Cleared GIT_HTTP_EXTRAHEADER environment variable.")
}

// RunGitPush performs the git push command
func RunGitPush() error {
	cmd := exec.Command("git", "push")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Run the command with the environment variable set
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git push failed: %v", err)
	}
	return nil
}

// ScanFile reads file content, performs a DLP scan, and runs Git push with an extra header if no sensitive data is found
func ScanFile(filename, projectID string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("could not read file: %v", err)
	}

	// Perform DLP scan
	foundSensitiveData, err := DLPScan(projectID, string(data))
	if err != nil {
		return err
	}

	if !foundSensitiveData {
		fmt.Printf("No sensitive data found in file %s. Proceeding with git push.\n", filename)
		SetGitExtraHeader()
		defer ClearGitExtraHeader() // Ensure the environment variable is cleared after use
		if err := RunGitPush(); err != nil {
			return err
		}
	} else {
		fmt.Printf("Sensitive data found in file %s. Skipping git push.\n", filename)
	}

	return nil
}

func main() {
	projectID := "datalake-sea-eng-us-cert"

	files, err := GetChangedFiles()
	if err != nil {
		fmt.Printf("Error retrieving changed files: %v\n", err)
		os.Exit(1)
	}

	for _, file := range files {
		if file == "" {
			continue
		}
		fmt.Printf("Scanning file: %s\n", file)
		if err := ScanFile(file, projectID); err != nil {
			fmt.Printf("Scan error: %v\n", err)
			os.Exit(1) // Exit with non-zero status to block push
		}
	}
	fmt.Println("DLP scan complete.")
}
