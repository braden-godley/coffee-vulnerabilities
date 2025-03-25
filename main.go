package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
    "encoding/json"
)

type CVEResponse struct {
    TotalResults int `json:"totalResults"`
    Vulnerabilities []struct {
        Cve struct {
            Id string `json:"id"`
            Published string `json:"published"`
            Descriptions []struct {
                Lang string `json:"lang"`
                Value string `json:"value"`
            } `json:"descriptions"`
            Metrics struct {
                CvssMetricV31 []struct {
                    CvssData struct {
                        BaseScore float32 `json:"baseScore"`
                    } `json:"cvssData"`
                } `json:"cvssMetricV31"`
            } `json:"metrics"`
        } `json:"cve"`
    } `json:"vulnerabilities"`
}

func main() {
    log.SetPrefix("coffee: ")
    log.SetFlags(0)

    vulns, err := getVulnerabilities()
    if err != nil {
        log.Fatal(err)
    }

    log.Printf("Received %d CVEs", len(vulns.Vulnerabilities))

    for _, v := range vulns.Vulnerabilities {
        log.Printf("Id: %s", v.Cve.Id)
        for _, desc := range v.Cve.Descriptions {
            if desc.Lang == "en" {
                log.Printf("Description: %s", desc.Value)
            }
        }
        for _, data := range v.Cve.Metrics.CvssMetricV31 {
            log.Printf("Base score: %f", data.CvssData.BaseScore)
        }
        log.Println("")
    }
}

func getVulnerabilities() (*CVEResponse, error) {
    end := time.Now()
    start := end.Add(-24 * time.Hour)

    url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&pubStartDate=%v&pubEndDate=%v", start.Format(time.RFC3339), end.Format(time.RFC3339))

    log.Printf("Getting %v", url)

    resp, err := http.Get(url)
    if err != nil {
        return nil, err
    }

    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    var response CVEResponse
    err = json.Unmarshal(body, &response)
    if err != nil {
        return nil, err
    }

    // log.Printf("Decoded: %+v\n", response)

    return &response, nil
}
