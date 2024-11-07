package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"cloud.google.com/go/dlp/apiv2"
	"google.golang.org/api/option"
	dlppb "google.golang.org/genproto/googleapis/privacy/dlp/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// Middleware to check HTTP payload
func payloadCheckMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Received request: %s %s\n", r.Method, r.URL.Path)
		if r.Method == http.MethodPost {
			// Read and check the payload
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Unable to read request body", http.StatusInternalServerError)
				fmt.Printf("Error reading request body: %v\n", err)
				return
			}
			// For demonstration purposes, let's just log the payload
			fmt.Printf("Received payload: %s\n", body)

			// Perform DLP inspection
			projectID := "datalake-sea-eng-us-cert"
			result, err := inspectContent(context.Background(), body, projectID)
			if err != nil {
				http.Error(w, "DLP inspection failed", http.StatusInternalServerError)
				fmt.Printf("DLP inspection failed: %v\n", err)
				return
			}
			fmt.Printf("Inspection results: %v\n", result)
		}
		// Call the next handler
		next.ServeHTTP(w, r)
	})
}

// inspectContent performs DLP inspection on the provided content.
func inspectContent(ctx context.Context, content []byte, projectID string) (*dlppb.InspectContentResponse, error) {
	// Create a gRPC connection using Application Default Credentials
	conn, err := grpc.DialContext(ctx, "dlp.googleapis.com:443",
		grpc.WithTransportCredentials(insecure.NewCredentials())) // Use insecure.NewCredentials() for testing, replace with secure credentials in production
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC connection: %w", err)
	}
	defer conn.Close()

	// Create the DLP client with default credentials
	client, err := dlp.NewClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		return nil, fmt.Errorf("failed to create DLP client: %w", err)
	}
	defer client.Close()

	/**
	// Define the custom info type
	customRegexPattern := "XY[0-9]{4}.*"
	customInfoType := &dlppb.CustomInfoType{
		InfoType: &dlppb.InfoType{
			Name: "RampID",
		},
		Type: &dlppb.CustomInfoType_Regex_{
			Regex: &dlppb.CustomInfoType_Regex{
				Pattern: customRegexPattern,
			},
		},
		Likelihood: dlppb.Likelihood_POSSIBLE,
	}

	// Define the inspect configuration
	inspectConfig := &dlppb.InspectConfig{
		InfoTypes: []*dlppb.InfoType{
			{Name: "PHONE_NUMBER"},
			{Name: "EMAIL_ADDRESS"},
			{Name: "US_SOCIAL_SECURITY_NUMBER"},
		},
		CustomInfoTypes: []*dlppb.CustomInfoType{
			customInfoType,
		},
		IncludeQuote: true,
	}

	// Define the content item to be inspected
	contentItem := &dlppb.ContentItem{
		DataItem: &dlppb.ContentItem_Value{
			Value: string(content),
		},
	}

	// Create the inspection request
	request := &dlppb.InspectContentRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/global", projectID),
		Item:          contentItem,
		InspectConfig: inspectConfig,
	}

	// Perform the inspection
	resp, err := client.InspectContent(ctx, request)
	if err != nil {
		fmt.Printf("DLP inspection failed: %v\n", err)
		if grpcError, ok := status.FromError(err); ok {
			fmt.Printf("GRPC Error Code: %v\n", grpcError.Code())
			fmt.Printf("GRPC Error Message: %v\n", grpcError.Message())
		}
		return nil, err
	}

	// Verbose logging of inspection results
	fmt.Printf("Inspection results:\n")
	fmt.Printf("Findings: %d\n", len(resp.Result.Findings))
	for _, f := range resp.Result.Findings {
		fmt.Printf("\tQuote: %s\n", f.Quote)
		fmt.Printf("\tInfo type: %s\n", f.InfoType.Name)
		fmt.Printf("\tLikelihood: %s\n", f.Likelihood)
		fmt.Println("")
		// Uncomment the next line if you want to print the entire Finding as a string
		fmt.Printf("\tString: %s\n", f.String())
	}
	**/

	simpleRequest := &dlppb.InspectContentRequest{
		Parent:        fmt.Sprintf("projects/%s/locations/global", projectID),
		Item:          &dlppb.ContentItem{DataItem: &dlppb.ContentItem_Value{Value: "Test data"}},
		InspectConfig: &dlppb.InspectConfig{InfoTypes: []*dlppb.InfoType{{Name: "EMAIL_ADDRESS"}}},
	}

	resp, err := client.InspectContent(ctx, simpleRequest)
	if err != nil {
		fmt.Printf("DLP inspection failed: %v\n", err)
		if grpcError, ok := status.FromError(err); ok {
			fmt.Printf("GRPC Error Code: %v\n", grpcError.Code())
			fmt.Printf("GRPC Error Message: %v\n", grpcError.Message())
		}
		return nil, err
	}
	fmt.Printf("Inspection results: %v\n", resp.Result)

	return resp, nil
}

func httpScan() {
	// Set up the proxy URL
	proxyURL := "http://10.13.48.89:80" // Update with your proxy URL
	proxyURLParsed, err := url.Parse(proxyURL)
	if err != nil {
		fmt.Printf("Invalid proxy URL: %v\n", err)
		return
	}

	// Define a custom dialer function for the proxy
	dialer := func(ctx context.Context, address string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
		defer cancel()
		conn, err := net.Dial("tcp", proxyURLParsed.Host)
		if err != nil {
			return nil, err
		}
		_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", address, address)
		if err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}

	// Create a gRPC connection with the custom dialer
	conn, err := grpc.DialContext(context.Background(), "dlp.googleapis.com:443",
		grpc.WithTransportCredentials(insecure.NewCredentials()), // Use secure credentials in production
		grpc.WithContextDialer(dialer),
		grpc.WithTimeout(120*time.Second)) // Increase timeout here
	if err != nil {
		fmt.Printf("Failed to create gRPC connection: %v\n", err)
		return
	}
	defer conn.Close()

	// Create the DLP client with the custom gRPC connection
	client, err := dlp.NewClient(context.Background(), option.WithGRPCConn(conn))
	if err != nil {
		fmt.Printf("Failed to create DLP client: %v\n", err)
		return
	}
	defer client.Close()

	fmt.Println("DLP client created successfully")

	// Set up an HTTP server with the payload check middleware
	http.Handle("/", payloadCheckMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a placeholder handler; implement your logic here
		w.Write([]byte("Hello, world!"))
	})))

	fmt.Println("Starting HTTP server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
