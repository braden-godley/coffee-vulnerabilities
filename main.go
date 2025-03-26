package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/samber/lo"
)

const ScoreThreshold = 9.0

type CVEResponse struct {
	TotalResults    int             `json:"totalResults"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	Cve struct {
		Id           string        `json:"id"`
		Published    string        `json:"published"`
		Descriptions []Description `json:"descriptions"`
		Metrics      struct {
			CvssMetricV31 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV31"`
			CvssMetricV40 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV40"`
			CvssMetricV2 []struct {
				CvssData CvssData `json:"cvssData"`
			} `json:"cvssMetricV2"`
		} `json:"metrics"`
	} `json:"cve"`
}

type CvssData struct {
	BaseScore float64 `json:"baseScore"`
}

type Description struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func main() {
	log.SetPrefix("coffee: ")
	log.SetFlags(0)

	vulns, err := getVulnerabilities()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Received %d CVEs", len(vulns.Vulnerabilities))

	critical := lo.Filter(vulns.Vulnerabilities, func(v Vulnerability, _ int) bool {
		return v.getBaseScore() > ScoreThreshold
	})

	for _, v := range critical {
		log.Printf("Id: %s", v.Cve.Id)
		if desc, ok := lo.Find(v.Cve.Descriptions, func(desc Description) bool {
			return desc.Lang == "en"
		}); ok {
			log.Printf("Description: %s", desc.Value)
		}
		log.Println("")
	}

	log.Printf("Found %d/%d CVEs with score at least %f", len(critical), len(vulns.Vulnerabilities), ScoreThreshold)
}

func getVulnerabilities() (*CVEResponse, error) {
	end := time.Now()
	start := end.Add(-24 * time.Hour)

	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0/?noRejected&pubStartDate=%v&pubEndDate=%v", start.Format(time.RFC3339), end.Format(time.RFC3339))

	log.Printf("Getting %v", url)

	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	resp, err := client.Get(url)
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

	return &response, nil
}

func (v Vulnerability) getBaseScore() float64 {
	metrics := v.Cve.Metrics
	if len(metrics.CvssMetricV40) > 0 {
		return metrics.CvssMetricV40[0].CvssData.BaseScore
	}

	if len(metrics.CvssMetricV31) > 0 {
		return metrics.CvssMetricV31[0].CvssData.BaseScore
	}

	if len(metrics.CvssMetricV2) > 0 {
		return metrics.CvssMetricV2[0].CvssData.BaseScore
	}

	return 0
}
