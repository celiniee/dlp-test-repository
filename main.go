package main

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"cloud.google.com/go/dlp/apiv2"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
)

func GetUnpushedCommits() ([]string, error) {
	checkUpstream := exec.Command("git", "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
	if err := checkUpstream.Run(); err != nil {
		return nil, fmt.Errorf("no upstream branch set for the current branch. Please set upstream before pushing.")
	}

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

func GetChangedFilesInCommit(commit string) ([]string, error) {
	cmd := exec.Command("git", "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get files for commit %s: %v", commit, err)
	}
	files := strings.Split(strings.TrimSpace(string(output)), "\n")
	return files, nil
}

func DLPScan(ctx context.Context, client *dlp.Client, projectID, text string) (bool, error) {
	req := &dlppb.InspectContentRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectID),
		Item: &dlppb.ContentItem{
			DataItem: &dlppb.ContentItem_Value{
				Value: text,
			},
		},
		InspectConfig: &dlppb.InspectConfig{
			InfoTypes: []*dlppb.InfoType{
				{Name: "CREDIT_CARD_NUMBER"},
				{Name: "EMAIL_ADDRESS"},
				{Name: "PHONE_NUMBER"},
			},
		},
	}

	resp, err := client.InspectContent(ctx, req)
	if err != nil {
		return false, fmt.Errorf("failed to inspect content: %v", err)
	}

	for _, finding := range resp.Result.Findings {
		log.Printf("Found sensitive data: %v", finding.InfoType.Name)
	}

	return len(resp.Result.Findings) == 0, nil
}

func ScanCommit(ctx context.Context, client *dlp.Client, commit, projectID string, flaggedFiles map[string]bool) error {
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
		foundSensitiveData, err := DLPScan(ctx, client, projectID, string(output))
		if err != nil {
			return err
		}
		if !foundSensitiveData {
			flaggedFiles[file] = true
			fmt.Printf("Sensitive data found in file %s in commit %s.\n", file, commit)
		}
	}

	return nil
}

func ScanFinalState(ctx context.Context, client *dlp.Client, projectID string, flaggedFiles map[string]bool) (bool, error) {
	for file := range flaggedFiles {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return false, fmt.Errorf("could not read file %s: %v", file, err)
		}
		foundSensitiveData, err := DLPScan(ctx, client, projectID, string(data))
		if err != nil {
			return false, err
		}
		if !foundSensitiveData {
			fmt.Printf("Sensitive data found in final state of file %s. Aborting push.\n", file)
			return true, nil
		}
	}

	return false, nil
}

func ScanPullClone(ctx context.Context, client *dlp.Client, projectID string) (bool, error) {
	cmd := exec.Command("git", "diff", "--name-only", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("failed to get changed files during pull or clone: %v", err)
	}
	files := strings.Split(strings.TrimSpace(string(output)), "\n")

	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err != nil {
			return false, fmt.Errorf("could not read file %s during pull or clone: %v", file, err)
		}
		foundSensitiveData, err := DLPScan(ctx, client, projectID, string(data))
		if err != nil {
			return false, err
		}
		if !foundSensitiveData {
			fmt.Printf("Sensitive data found in file %s during pull or clone. Aborting operation.\n", file)
			return true, nil
		}
	}
	return false, nil
}

func blockGitOperation(success bool, operation string) {
	if !success {
		log.Fatalf("Sensitive data detected. Blocking git %s operation.", operation)
		os.Exit(1)
	}
}

func detectGitOperation() string {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "push":
			return "push"
		case "pull":
			return "pull"
		case "clone":
			return "clone"
		}
	}
	return ""
}

func main() {
	ctx := context.Background()
	client, err := dlp.NewClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create DLP client: %v", err)
	}
	defer client.Close()

	projectID := "datalake-sea-eng-us-cert"

	os.Setenv("GIT_HTTP_EXTRAHEADER", "DLP-Scanned: true")
	defer os.Unsetenv("GIT_HTTP_EXTRAHEADER")

	operation := detectGitOperation()
	if operation == "push" {
		commits, err := GetUnpushedCommits()
		if err != nil {
			fmt.Printf("Error retrieving unpushed commits: %v\n", err)
			os.Exit(1)
		}

		flaggedFiles := make(map[string]bool)
		for _, commit := range commits {
			fmt.Printf("Scanning commit: %s\n", commit)
			err := ScanCommit(ctx, client, commit, projectID, flaggedFiles)
			if err != nil {
				fmt.Printf("Scan error in commit %s: %v\n", commit, err)
				os.Exit(1)
			}
		}

		fmt.Println("Performing final DLP scan on flagged files...")
		foundSensitiveData, err := ScanFinalState(ctx, client, projectID, flaggedFiles)
		if err != nil {
			fmt.Printf("Final state scan error: %v\n", err)
			os.Exit(1)
		}
		blockGitOperation(!foundSensitiveData, "push")
	} else if operation == "pull" || operation == "clone" {
		fmt.Printf("Scanning for sensitive data during git %s operation...")
	}
}
