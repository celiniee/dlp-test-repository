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

	if len(resp.Result.Findings) > 0 {
		fmt.Println("Sensitive data detected:")
		for _, finding := range resp.Result.Findings {
			fmt.Printf(" - %s\n", finding.InfoType.Name)
		}
		return true, nil
	}
	return false, nil
}

// ProxyCheck makes a POST request to a specified HTTP proxy with a custom "DLP-scanned" header and prints the status code
func ProxyCheck(proxyURL string) error {
	req, err := http.NewRequest("POST", proxyURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %v", err)
	}

	// Add custom header
	req.Header.Set("DLP-scanned", "true")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Print status code to see if the proxy allows the request
	fmt.Printf("Proxy response status code: %d\n", resp.StatusCode)
	return nil
}

// ScanFile reads file content, performs a DLP scan, and checks proxy if sensitive data is found
func ScanFile(filename, projectID, proxyURL string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("could not read file: %v", err)
	}

	foundSensitiveData, err := DLPScan(projectID, string(data))
	if err != nil {
		return err
	}
	if foundSensitiveData {
		// Call ProxyCheck if sensitive data is found
		if err := ProxyCheck(proxyURL); err != nil {
			return fmt.Errorf("proxy check failed for file %s: %v", filename, err)
		}
		return fmt.Errorf("sensitive data found in file %s", filename)
	}
	return nil
}

func main() {
	projectID := "datalake-sea-eng-us-cert"
	proxyURL := "https://10.13.48.89:80" // Replace with your proxy URL

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
		if err := ScanFile(file, projectID, proxyURL); err != nil {
			fmt.Printf("Scan error: %v\n", err)
			os.Exit(1) // Exit with non-zero status to block push
		}
	}
	fmt.Println("No sensitive data found.")
}
