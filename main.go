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

// GetStagedFiles retrieves the list of staged files in the Git index
func GetStagedFiles() ([]string, error) {
	cmd := exec.Command("git", "diff", "--cached", "--name-only")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get staged files: %v", err)
	}
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	return files, nil
}

// DLPScan scans a given text for sensitive data using Google Cloud DLP
func DLPScan(projectID, text string) error {
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		return fmt.Errorf("failed to create DLP client: %v", err)
	}
	defer client.Close()

	// Custom regex pattern for additional sensitive data detection
	customRegexPattern := "XY[0-9]{4}.*"
	customInfoType := &dlppb.CustomInfoType{
		InfoType: &dlppb.InfoType{Name: "RampID"},
		Type: &dlppb.CustomInfoType_Regex_{Regex: &dlppb.CustomInfoType_Regex{
			Pattern: customRegexPattern,
		}},
		Likelihood: dlppb.Likelihood_POSSIBLE,
	}

	// Configuration for DLP scan including standard and custom info types
	inspectConfig := &dlppb.InspectConfig{
		InfoTypes: []*dlppb.InfoType{
			{Name: "EMAIL_ADDRESS"},
			{Name: "PHONE_NUMBER"},
			{Name: "US_SOCIAL_SECURITY_NUMBER"},
		},
		CustomInfoTypes: []*dlppb.CustomInfoType{customInfoType},
		IncludeQuote:    true,
	}

	// Define the content item to be inspected
	contentItem := &dlppb.ContentItem{
		DataItem: &dlppb.ContentItem_Value{Value: text},
	}

	// Create the inspection request
	req := &dlppb.InspectContentRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/global", projectID),
		Item:          contentItem,
		InspectConfig: inspectConfig,
	}

	// Execute the DLP scan
	resp, err := client.InspectContent(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to inspect content: %v", err)
	}

	// Check for findings
	if len(resp.Result.Findings) > 0 {
		fmt.Println("Sensitive data detected:")
		for _, finding := range resp.Result.Findings {
			fmt.Printf(" - %s\n", finding.InfoType.Name)
		}
		return fmt.Errorf("sensitive data found")
	}

	return nil
}

// ScanFile reads file content and performs a DLP scan
func ScanFile(filename, projectID string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("could not read file: %v", err)
	}
	return DLPScan(projectID, string(data))
}

func main() {
	projectID := "datalake-sea-eng-us-cert"

	files, err := GetStagedFiles()
	if err != nil {
		fmt.Printf("Error retrieving staged files: %v\n", err)
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
	fmt.Println("No sensitive data found.")
}
