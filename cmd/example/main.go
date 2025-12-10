package main

import (
	"context"
	"fmt"
	"os"

	"github.com/joho/godotenv"
	"github.com/resnickio/unifi-go-sdk/pkg/unifi"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file")
		return
	}

	apiKey := os.Getenv("UNIFI_API_KEY")
	if apiKey == "" {
		fmt.Println("UNIFI_API_KEY not set")
		return
	}

	client := unifi.NewClient(apiKey)

	hosts, err := client.ListAllHosts(context.Background())
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	// Get first host by ID
	host, err := client.GetHost(context.Background(), hosts[0].ID)
	if err != nil {
		fmt.Println("Error getting host:", err)
		return
	}

	fmt.Printf("Got host: %s (%s)\n", host.Host.ReportedState.Name, host.Host.ID)
}
