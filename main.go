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

	req := &dlppb.InspectContentRequest{
		Parent: fmt.Sprintf("projects/%s", projectID),
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_Value{Value: text},
		},
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes: []*dlppb.InfoType{
				{Name: "EMAIL_ADDRESS"},
				{Name: "PHONE_NUMBER"},
				{Name: "US_SOCIAL_SECURITY_NUMBER"},
				{Name: "CREDIT_CARD_NUMBER"},
			},
			MinLikelihood: dlppb.Likelihood_POSSIBLE,
		},
	}

	resp, err := client.InspectContent(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to inspect content: %v", err)
	}

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
